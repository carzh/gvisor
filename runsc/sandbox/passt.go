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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
)

// passt mode gives a rootless sandbox network access. runsc starts passt
// (https://passt.top) and netgofer. The sentry sends IP packets to netgofer,
// netgofer sends them to passt as Ethernet frames, and passt opens host
// sockets as the current user. See runsc/gofer/net/passt.go.
//
// The sandbox network configuration is fixed. It uses the same addresses as
// QEMU user networking.
//
// Netgofer's egress filter reads the host's interface addresses once when
// netgofer starts. An address added to the host after netgofer starts is not
// blocked by the filter and is reachable from the sandbox (including host
// services bound to the wildcard address).

var (
	// passtGuestAddr is the IPv4 address of the sandbox eth0.
	passtGuestAddr = net.IPv4(10, 0, 2, 15).To4()

	// passtGateway is the default gateway of the sandbox. passt answers for
	// it.
	passtGateway = net.IPv4(10, 0, 2, 2).To4()

	// passtStartTimeout bounds how long runsc waits for passt to start.
	passtStartTimeout = 30 * time.Second
)

const (
	// passtPrefixLen is the prefix length of the sandbox eth0 subnet.
	passtPrefixLen = 24

	// passtMTU is the MTU of the sandbox eth0. It matches passt's default
	// MTU (65520) so that Netstack does not fragment outbound IPv4
	// datagrams, which passt cannot reassemble.
	passtMTU = 65520

	// passtMAC is the MAC address of passt. It must match PasstMAC in
	// runsc/gofer/net/passt.go, because netgofer uses it as the destination
	// MAC address of the frames it sends to passt.
	passtMAC = "02:02:02:02:02:03"
)

// passtLinksAndRoutes returns the sandbox network configuration for passt
// mode: a loopback link and an eth0 proxy link backed by udsFile.
func passtLinksAndRoutes(conf *config.Config, disableIPv6 bool, udsFile *os.File) sentryapi.CreateLinksAndRoutesArgs {
	lo := sentryapi.DefaultLoopbackLink
	lo.GVisorGRO = conf.GVisorGRO
	if disableIPv6 {
		var addrs []sentryapi.IPWithPrefix
		for _, a := range lo.Addresses {
			if a.Address.To4() != nil {
				addrs = append(addrs, a)
			}
		}
		lo.Addresses = addrs
		var routes []sentryapi.Route
		for _, r := range lo.Routes {
			if r.Destination.IP.To4() != nil {
				routes = append(routes, r)
			}
		}
		lo.Routes = routes
	}

	mask := net.CIDRMask(passtPrefixLen, net.IPv4len*8)
	eth0 := sentryapi.FDBasedLink{
		Name:                 defaultPrimaryInterfaceName,
		MTU:                  passtMTU,
		Addresses:            []sentryapi.IPWithPrefix{{Address: passtGuestAddr, PrefixLen: passtPrefixLen}},
		Routes:               []sentryapi.Route{{Destination: net.IPNet{IP: passtGuestAddr.Mask(mask), Mask: mask}}},
		TXChecksumOffload:    conf.TXChecksumOffload,
		RXChecksumOffload:    conf.RXChecksumOffload,
		NumChannels:          1,
		ProcessorsPerChannel: conf.NetworkProcessorsPerChannel,
		QDisc:                conf.QDisc,
		TBFRate:              conf.TBFRate,
		TBFBurst:             uint32(conf.TBFBurst),
		GVisorGRO:            conf.GVisorGRO,
	}
	configureProxyLink(&eth0)
	if eth0.GSOMaxSize == 0 && conf.GVisorGSO {
		eth0.GSOMaxSize = tcpip.GVisorGSOMaxSize
		eth0.GVisorGSOEnabled = true
	}

	args := sentryapi.CreateLinksAndRoutesArgs{
		LoopbackLinks: []sentryapi.LoopbackLink{lo},
		FDBasedLinks:  []sentryapi.FDBasedLink{eth0},
		Defaultv4Gateway: sentryapi.DefaultRoute{
			Route: sentryapi.Route{
				Destination: net.IPNet{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
				Gateway:     passtGateway,
			},
			Name: eth0.Name,
		},
		PauseExternalNetworking: conf.PauseExternalNetworking,
		AllowConnectedOnSave:    conf.AllowConnectedOnSave,
	}
	args.FilePayload.Files = append(args.FilePayload.Files, udsFile)
	return args
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
		pcap, err := os.OpenFile(conf.PCAP, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
		if err != nil {
			return 0, fmt.Errorf("failed to open PCAP file %s: %w", conf.PCAP, err)
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
		// passt exits when this socket is closed (--fd implies --one-off).
		"--fd", strconv.Itoa(fd),
		"--ipv4-only",
		"--address", passtGuestAddr.String(),
		"--netmask", strconv.Itoa(passtPrefixLen),
		"--gateway", passtGateway.String(),
		"--mac-addr", passtMAC,
		// Do not map the gateway address to the host loopback address, so
		// that the sandbox cannot connect to services that listen only on
		// host loopback.
		"--no-map-gw",
		"--no-dhcp",
		"--quiet",
	}
}

// startPasst starts passt with one end of a new connected SOCK_STREAM socket
// pair, and returns the other end for netgofer. If cloneIntoCgroupFD is
// non-nil, passt is cloned directly into that cgroup.
//
// Without --foreground, passt forks a daemon after its setup is complete, and
// the first process exits. So this function returns after passt is ready,
// and it returns passt setup errors. runsc does not track the daemon: it
// exits when the socket to netgofer is closed.
func startPasst(passtBinary string, cloneIntoCgroupFD *os.File) (*os.File, error) {
	if passtBinary == "" {
		return nil, fmt.Errorf("passt not found at %q and --passt-binary is not set", config.DefaultPasstBinary)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("creating passt socket pair: %w", err)
	}
	for _, fd := range fds {
		setUDSBufSizes(fd)
	}
	passtEnd := os.NewFile(uintptr(fds[0]), "passt")
	defer passtEnd.Close()
	netgoferEnd := os.NewFile(uintptr(fds[1]), "passt-netgofer")

	ctx, cancel := context.WithTimeout(context.Background(), passtStartTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, passtBinary, passtArgs(3)...)
	// Set argv[0] to "passt" so the binary always runs in passt mode even if
	// passtBinary is a link whose basename contains "pasta". passt locates its
	// .avx2 build via /proc/self/exe, not argv[0].
	cmd.Args[0] = "passt"
	cmd.ExtraFiles = []*os.File{passtEnd}
	if cloneIntoCgroupFD != nil {
		cmd.SysProcAttr = &unix.SysProcAttr{
			UseCgroupFD: true,
			CgroupFD:    int(cloneIntoCgroupFD.Fd()),
		}
	}
	// The passt daemon should not keep the output pipe open. If it does,
	// stop waiting for the pipe after a short delay.
	cmd.WaitDelay = time.Second
	log.Infof("Starting passt: %s %v", cmd.Path, cmd.Args)
	out, err := cmd.CombinedOutput()
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		_ = netgoferEnd.Close()
		return nil, fmt.Errorf("starting passt %q: %w, output: %q", passtBinary, err, out)
	}
	if len(out) > 0 {
		log.Infof("passt output: %s", out)
	}
	log.Infof("passt started")
	return netgoferEnd, nil
}
