// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandbox

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/moby/sys/capability"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// passt mode gives a rootless sandbox outbound IPv4 network access. runsc
// starts passt (https://passt.top) and netgofer. The sentry sends IP packets to
// netgofer, netgofer sends them to passt as Ethernet frames, and passt opens
// host sockets as an unprivileged user. See runsc/gofer/net/passt.go.
//
// The sandbox network configuration is fixed. It uses the same addresses as
// QEMU user networking.
//
// The netgofer egress filter reads host interface addresses once at startup.
// It does not block addresses added to the host later, so the sandbox can
// reach them (including host services bound to the wildcard address).

var (
	// passtGuestAddr is the IPv4 address of the sandbox eth0.
	passtGuestAddr = net.IP{10, 0, 2, 15}

	// passtGateway is the default gateway of the sandbox.
	passtGateway = net.IP{10, 0, 2, 2}

	// passtGuestMAC is the Ethernet address of the sandbox eth0. It matches
	// PasstGuestMAC in runsc/gofer/net/passt.go.
	passtGuestMAC = net.HardwareAddr{0x02, 0x02, 0x02, 0x02, 0x02, 0x02}

	passtEth0Addresses = []sentryapi.IPWithPrefix{
		{Address: passtGuestAddr, PrefixLen: passtPrefixLen},
	}

	passtEth0Routes = []sentryapi.Route{
		{
			Destination: net.IPNet{
				IP:   net.IP{10, 0, 2, 0},
				Mask: net.IPMask{255, 255, 255, 0},
			},
		},
	}

	passtDefaultRoute = sentryapi.DefaultRoute{
		Route: sentryapi.Route{
			Destination: net.IPNet{
				IP:   net.IP{0, 0, 0, 0},
				Mask: net.IPMask{0, 0, 0, 0},
			},
			Gateway: passtGateway,
		},
		Name: defaultPrimaryInterfaceName,
	}

	passtIPv4LoopbackAddresses = []sentryapi.IPWithPrefix{
		{Address: net.IP{127, 0, 0, 1}, PrefixLen: 8},
	}

	passtIPv4LoopbackRoutes = []sentryapi.Route{
		{
			Destination: net.IPNet{
				IP:   net.IP{127, 0, 0, 0},
				Mask: net.IPMask{255, 0, 0, 0},
			},
		},
	}

	// passtStartTimeout bounds how long runsc waits for passt to initialize and
	// daemonize.
	passtStartTimeout = 30 * time.Second

	// passtTestEnv is empty in production and overridden in unit tests that
	// execute the test binary as a fake passt process.
	passtTestEnv []string
)

const (
	// passtPrefixLen is the prefix length of the sandbox eth0 subnet.
	passtPrefixLen    = 24
	passtPrefixLenStr = "24"

	passtGuestAddrStr = "10.0.2.15"
	passtGatewayStr   = "10.0.2.2"

	// passtMTU is the MTU of the sandbox eth0. It matches passt's default MTU
	// (65520) so Netstack does not fragment outbound IPv4 datagrams, which passt
	// drops.
	passtMTU = 65520

	// passtMAC is the MAC address of passt. It matches PasstMAC in
	// runsc/gofer/net/passt.go, which netgofer sets as the destination MAC
	// address on Ethernet frames sent to passt.
	passtMAC = "02:02:02:02:02:03"

	// maxPasstOutputBytes bounds diagnostic output captured from passt.
	maxPasstOutputBytes = 64 << 10
)

// resolveSandboxPasstBinary returns the passt binary path for a sandbox with
// effective user ID euid, or "" if passt mode does not apply. Non-root callers
// without --rootless that hold CAP_SYS_ADMIN keep standard namespace networking.
func resolveSandboxPasstBinary(conf *config.Config, euid int) string {
	return resolveSandboxPasstBinaryWithCaps(conf, euid, func() bool {
		return specutils.HasCapabilities(capability.CAP_SYS_ADMIN)
	})
}

func resolveSandboxPasstBinaryWithCaps(conf *config.Config, euid int, hasSysAdmin func() bool) string {
	if !conf.CanUsePasst(euid) {
		return ""
	}
	if !conf.Rootless && euid != 0 && hasSysAdmin() {
		return ""
	}
	return conf.PasstBinaryPath()
}

// sandboxNetworkNamespace returns the network namespace to configure on the
// sandbox process, or (_, false) when the sandbox uses the host network
// namespace.
func sandboxNetworkNamespace(conf *config.Config, spec *specs.Spec, usePasst bool) (specs.LinuxNamespace, bool) {
	if ns, ok := specutils.GetNS(specs.NetworkNamespace, spec); ok && conf.Network != config.NetworkNone && !usePasst {
		return ns, true
	}
	if conf.Network == config.NetworkHost {
		return specs.LinuxNamespace{}, false
	}
	return specs.LinuxNamespace{Type: specs.NetworkNamespace}, true
}

// passtLinksAndRoutes returns the sandbox network configuration for passt
// mode: a loopback link and an eth0 proxy link backed by udsFile.
func passtLinksAndRoutes(conf *config.Config, disableIPv6 bool, udsFile *os.File) sentryapi.CreateLinksAndRoutesArgs {
	lo := sentryapi.DefaultLoopbackLink
	lo.GVisorGRO = conf.GVisorGRO
	if disableIPv6 {
		lo.Addresses = passtIPv4LoopbackAddresses
		lo.Routes = passtIPv4LoopbackRoutes
	}

	// Disable software GSO and GRO on eth0: at MTU 65520, Netstack already sends
	// full-MSS segments up to passt's advertised MSS without runt splits or
	// sub-MSS Nagle stalls, and the single-packet Readv UDS dispatcher does not
	// coalesce inbound GRO packets.
	eth0 := sentryapi.FDBasedLink{
		Name:                 defaultPrimaryInterfaceName,
		MTU:                  passtMTU,
		LinkAddress:          passtGuestMAC,
		Addresses:            passtEth0Addresses,
		Routes:               passtEth0Routes,
		TXChecksumOffload:    conf.TXChecksumOffload,
		RXChecksumOffload:    conf.RXChecksumOffload,
		NumChannels:          conf.NumNetworkChannels,
		ProcessorsPerChannel: conf.NetworkProcessorsPerChannel,
		QDisc:                conf.QDisc,
		TBFRate:              conf.TBFRate,
		TBFBurst:             uint32(conf.TBFBurst),
	}
	configureProxyLink(&eth0)

	var files []*os.File
	if conf.PCAP != "" {
		files = make([]*os.File, 1, 2)
		files[0] = udsFile
	} else {
		files = []*os.File{udsFile}
	}

	return sentryapi.CreateLinksAndRoutesArgs{
		LoopbackLinks:           []sentryapi.LoopbackLink{lo},
		FDBasedLinks:            []sentryapi.FDBasedLink{eth0},
		Defaultv4Gateway:        passtDefaultRoute,
		PauseExternalNetworking: conf.PauseExternalNetworking,
		AllowConnectedOnSave:    conf.AllowConnectedOnSave,
		FilePayload:             urpc.FilePayload{Files: files},
	}
}

func pcapOpenFlags(path string) int {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC | unix.O_NOCTTY
	if !specutils.IsProcFDPath(path) {
		flags |= unix.O_NOFOLLOW
	}
	return flags
}

// createPasstInterfacesAndRoutes creates the passt mode network links in the
// sandbox. It returns the MTU of the eth0 link.
func createPasstInterfacesAndRoutes(conn *urpc.Client, conf *config.Config, disableIPv6 bool, isRestore bool, udsFile *os.File) (int, error) {
	if udsFile == nil {
		return 0, fmt.Errorf("passt mode enabled but the sandbox UDS is nil")
	}
	args := passtLinksAndRoutes(conf, disableIPv6, udsFile)
	args.LogPackets = conf.LogPackets
	if conf.PCAP != "" {
		args.PCAP = true
		pcap, err := os.OpenFile(conf.PCAP, pcapOpenFlags(conf.PCAP), 0600)
		if err != nil {
			return 0, fmt.Errorf("opening PCAP file %q: %w", conf.PCAP, err)
		}
		defer pcap.Close()
		args.FilePayload.Files = append(args.FilePayload.Files, pcap)
	}
	if conf.ReproduceNAT || conf.ReproduceNftables {
		log.Warningf("Ignoring --reproduce-nat and --reproduce-nftables in passt mode")
	}
	args.IsRestore = isRestore
	log.Debugf("Setting up passt network, config: %+v", args)
	if err := conn.Call(sentryapi.ContMgrSetNetworkArgs, &args, nil); err != nil {
		return 0, fmt.Errorf("creating links and routes: %w", err)
	}
	return passtMTU, nil
}

// passtArgs returns the passt command line arguments. fd is the passt end of
// the connected socket to netgofer.
func passtArgs(fd int) []string {
	return []string{
		"--fd", strconv.Itoa(fd),
		"--one-off",
		"--ipv4-only",
		"--address", passtGuestAddrStr,
		"--netmask", passtPrefixLenStr,
		"--gateway", passtGatewayStr,
		"--mac-addr", passtMAC,
		// Do not map the gateway address to host loopback so the sandbox cannot
		// reach services bound only to host loopback.
		"--no-map-gw",
		"--tcp-ports", "none",
		"--udp-ports", "none",
		"--no-dhcp",
		"--no-dhcp-dns",
		"--no-dhcp-search",
		// Do not read the host /etc/resolv.conf: the sandbox gets no DNS
		// information from passt.
		"--dns", "none",
		"--search", "none",
		"--quiet",
	}
}

func readNonblockingPipe(pipeFD int) []byte {
	defer unix.Close(pipeFD)
	_ = unix.SetNonblock(pipeFD, true)

	var out []byte
	var buf [4096]byte
	for len(out) < maxPasstOutputBytes {
		rem := maxPasstOutputBytes - len(out)
		chunk := buf[:]
		if rem < len(chunk) {
			chunk = chunk[:rem]
		}
		n, err := unix.Read(pipeFD, chunk)
		if n > 0 {
			out = append(out, chunk[:n]...)
		}
		if err == unix.EINTR {
			continue
		}
		if n == 0 || err != nil {
			break
		}
	}
	return out
}

// startPasst starts passt with one end of a new connected SOCK_STREAM socket
// pair and returns the other end for netgofer. If cloneIntoCgroupFD is
// non-nil, startPasst clones passt directly into that cgroup.
//
// Without --foreground, passt initializes, forks a daemon, and exits the
// parent process. startPasst therefore waits until passt is ready and reports
// any setup error. runsc does not track the daemon PID because the daemon
// exits when netgofer closes the shared socket.
func startPasst(passtBinary string, cloneIntoCgroupFD *os.File) (*os.File, error) {
	if passtBinary == "" {
		return nil, fmt.Errorf("passt not found at %q and --passt-binary is not set", config.DefaultPasstBinary)
	}
	if !filepath.IsAbs(passtBinary) {
		return nil, fmt.Errorf("starting passt %q: path must be absolute", passtBinary)
	}
	var st unix.Stat_t
	if err := unix.Stat(passtBinary, &st); err != nil {
		return nil, fmt.Errorf("starting passt %q: %w", passtBinary, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("starting passt %q: not a regular file", passtBinary)
	}
	if err := SetCloExeOnAllFDs(); err != nil {
		return nil, fmt.Errorf("setting CLOEXEC on all FDs: %w", err)
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("creating passt socket pair: %w", err)
	}
	for _, fd := range fds {
		setUDSBufSizes(fd, false /* tryForce */)
	}
	passtEnd := os.NewFile(uintptr(fds[0]), "passt")
	defer passtEnd.Close()
	netgoferEnd := os.NewFile(uintptr(fds[1]), "passt-netgofer")

	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC); err != nil {
		_ = netgoferEnd.Close()
		return nil, fmt.Errorf("creating passt output pipe: %w", err)
	}
	pipeW := os.NewFile(uintptr(pipeFDs[1]), "passt-output-w")

	cmd := exec.Command(passtBinary, passtArgs(3)...)
	// Set argv[0] to "passt" so the binary always runs in passt mode even if
	// passtBinary is a link whose basename contains "pasta". passt locates its
	// .avx2 build via /proc/self/exe, not argv[0].
	cmd.Args[0] = "passt"
	cmd.Dir = "/"
	cmd.Env = append([]string{}, passtTestEnv...)
	cmd.ExtraFiles = []*os.File{passtEnd}
	cmd.Stdout = pipeW
	cmd.Stderr = pipeW
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setsid: true,
	}
	if cloneIntoCgroupFD != nil {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = int(cloneIntoCgroupFD.Fd())
	}

	log.Infof("Starting passt: %s %v", cmd.Path, cmd.Args)
	if err := cmd.Start(); err != nil {
		_ = pipeW.Close()
		_ = unix.Close(pipeFDs[0])
		_ = netgoferEnd.Close()
		return nil, fmt.Errorf("starting passt %q: %w", passtBinary, err)
	}
	_ = pipeW.Close()

	// Wait with WNOWAIT first: the unreaped zombie keeps its PID and process
	// group ID allocated, so the timeout cannot signal a reused process group.
	var waitMu sync.Mutex
	exited := false
	timedOut := false
	timer := time.AfterFunc(passtStartTimeout, func() {
		waitMu.Lock()
		defer waitMu.Unlock()
		if !exited {
			timedOut = true
			_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		}
	})
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			break
		}
	}
	waitMu.Lock()
	exited = true
	killed := timedOut
	waitMu.Unlock()
	timer.Stop()
	waitErr := cmd.Wait()

	out := readNonblockingPipe(pipeFDs[0])
	if killed {
		_ = netgoferEnd.Close()
		return nil, fmt.Errorf("starting passt %q timed out after %v: %w, output: %q", passtBinary, passtStartTimeout, waitErr, out)
	}
	if waitErr != nil {
		_ = netgoferEnd.Close()
		return nil, fmt.Errorf("starting passt %q: %w, output: %q", passtBinary, waitErr, out)
	}
	if len(out) > 0 {
		log.Infof("passt output: %s", out)
	}
	log.Infof("passt started")
	return netgoferEnd, nil
}
