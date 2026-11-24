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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	netgofer "gvisor.dev/gvisor/runsc/gofer/net"
)

const (
	// childRoleEnv selects the role of a child process of the tests. See
	// TestMain.
	childRoleEnv = "SANDBOX_TEST_CHILD_ROLE"

	// childPIDFileEnv is the path of the file where the fake passt writes the
	// PID of its daemon.
	childPIDFileEnv = "SANDBOX_TEST_CHILD_PID_FILE"

	// childEOFFileEnv is the path of the file that the fake passt daemon
	// creates when it reads EOF on the passt socket.
	childEOFFileEnv = "SANDBOX_TEST_CHILD_EOF_FILE"

	// Child roles. The passt roles act as the passt binary that startPasst
	// runs. roleNetgofer acts as the netgofer binary that startProxy runs.
	rolePasstOK     = "passt-ok"     // Writes a greeting to the socket and exits.
	rolePasstDaemon = "passt-daemon" // Like passt-ok, but leaves a daemon running.
	rolePasstFail   = "passt-fail"   // Prints an error and exits with status 1.
	rolePasstHang   = "passt-hang"   // Does not exit before the start timeout.
	roleDaemon      = "daemon"       // The daemon that passt-daemon starts.
	roleNetgofer    = "netgofer"

	// fakePasstGreeting is written by the fake passt to its socket.
	fakePasstGreeting = "hello from fake passt"

	// fakeNetgoferAck is written by the fake netgofer to the sentry socket.
	fakeNetgoferAck = "netgofer-passt-ok"
)

// TestMain runs a child role when the environment selects one. Otherwise it
// runs the tests.
//
// startPasst and startProxy start the children with their own arguments, so a
// child must not reach the flag parsing of the testing package.
func TestMain(m *testing.M) {
	if role := os.Getenv(childRoleEnv); role != "" {
		runChild(role)
	}

	// Make the sidecar lookup return the test binary as netgofer. The lookup
	// result is cached, so the directory must exist for the whole test run.
	sidecarDir, err := os.MkdirTemp("", "sandbox-test-sidecars-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp failed: %v\n", err)
		os.Exit(1)
	}
	exe, err := os.Executable()
	if err == nil {
		err = os.Symlink(exe, filepath.Join(sidecarDir, "runsc-netgofer"))
	}
	if err == nil {
		err = os.Setenv("GVISOR_SIDECAR_BINARIES_DIR", sidecarDir)
	}
	if err != nil {
		_ = os.RemoveAll(sidecarDir)
		fmt.Fprintf(os.Stderr, "setting up the fake netgofer failed: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(sidecarDir)
	os.Exit(code)
}

// childFatalf prints a message and exits a child process with status 2.
func childFatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "test child: "+format+"\n", args...)
	os.Exit(2)
}

// runChild runs a child role. It does not return.
func runChild(role string) {
	switch role {
	case roleNetgofer:
		runFakeNetgofer()
	case roleDaemon:
		runFakePasstDaemon()
	}

	// The other roles act as passt. Check how startPasst started the process.
	if os.Args[0] != "passt" {
		childFatalf("argv[0] = %q, want \"passt\"", os.Args[0])
	}
	if !slices.Equal(os.Args[1:], passtArgs(3)) {
		childFatalf("args = %q, want %q", os.Args[1:], passtArgs(3))
	}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SANDBOX_TEST_CHILD_") {
			childFatalf("environment has %q, want only the test variables", kv)
		}
	}
	switch role {
	case rolePasstOK, rolePasstDaemon:
		sock := os.NewFile(3, "passt")
		if _, err := sock.Write([]byte(fakePasstGreeting)); err != nil {
			childFatalf("writing the greeting: %v", err)
		}
		if role == rolePasstDaemon {
			startFakePasstDaemon(sock)
		}
		fmt.Fprintln(os.Stderr, "fake passt: initialized")
		os.Exit(0)
	case rolePasstFail:
		fmt.Fprintln(os.Stderr, "fake passt: setup failed")
		os.Exit(1)
	case rolePasstHang:
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	childFatalf("unknown role %q", role)
}

// startFakePasstDaemon starts the daemon of the fake passt with sock as FD 3.
// The daemon also inherits stderr, so the passt output pipe stays open after
// the fake passt exits. startPasst must not wait for that pipe to close.
func startFakePasstDaemon(sock *os.File) {
	exe, err := os.Executable()
	if err != nil {
		childFatalf("os.Executable: %v", err)
	}
	daemon := exec.Command(exe)
	daemon.Env = []string{
		childRoleEnv + "=" + roleDaemon,
		childEOFFileEnv + "=" + os.Getenv(childEOFFileEnv),
	}
	daemon.Stderr = os.Stderr
	daemon.ExtraFiles = []*os.File{sock}
	if err := daemon.Start(); err != nil {
		childFatalf("starting the daemon: %v", err)
	}
	pid := strconv.Itoa(daemon.Process.Pid)
	if err := os.WriteFile(os.Getenv(childPIDFileEnv), []byte(pid), 0600); err != nil {
		childFatalf("writing the daemon PID: %v", err)
	}
}

// runFakePasstDaemon reads the passt socket (FD 3) until the socket closes,
// then creates the file named by childEOFFileEnv. The socket closes only
// after every copy of the netgofer end of the socket pair is closed.
func runFakePasstDaemon() {
	// Do not outlive a failed test.
	time.AfterFunc(30*time.Second, func() { os.Exit(3) })
	_, _ = io.Copy(io.Discard, os.NewFile(3, "passt"))
	if err := os.WriteFile(os.Getenv(childEOFFileEnv), nil, 0600); err != nil {
		childFatalf("writing the EOF file: %v", err)
	}
	os.Exit(0)
}

// runFakeNetgofer acts as netgofer in passt mode. It checks its arguments,
// reads the greeting of the fake passt, and reports its parent-death signal
// on the sentry socket.
func runFakeNetgofer() {
	i := slices.Index(os.Args, "netgofer")
	if i < 0 {
		childFatalf("no netgofer subcommand in %q", os.Args)
	}
	fdArg := func(arg, prefix string) int {
		fd, err := strconv.Atoi(strings.TrimPrefix(arg, prefix))
		if err != nil {
			childFatalf("bad argument %q", arg)
		}
		return fd
	}
	udsFD, passtFD, sawMTU := -1, -1, false
	for _, arg := range os.Args[i+1:] {
		switch {
		case arg == "--allow-loopback":
			childFatalf("unexpected --allow-loopback in passt mode")
		case arg == fmt.Sprintf("--mtu=%d", passtMTU):
			sawMTU = true
		case strings.HasPrefix(arg, "--uds-fd="):
			udsFD = fdArg(arg, "--uds-fd=")
		case strings.HasPrefix(arg, "--passt-fd="):
			passtFD = fdArg(arg, "--passt-fd=")
		}
	}
	if !sawMTU || udsFD < 0 || passtFD < 0 {
		childFatalf("missing expected arguments in %q", os.Args)
	}

	passtSock := os.NewFile(uintptr(passtFD), "passt-fd")
	buf := make([]byte, len(fakePasstGreeting))
	if _, err := io.ReadFull(passtSock, buf); err != nil || string(buf) != fakePasstGreeting {
		childFatalf("reading the greeting: err=%v got=%q", err, buf)
	}
	// Close the only netgofer copy of the socket. The fake passt daemon then
	// sees the socket close only if runsc closed its own copy.
	_ = passtSock.Close()

	pdeathsig, err := getPdeathsig()
	if err != nil {
		childFatalf("PR_GET_PDEATHSIG: %v", err)
	}
	udsSock := os.NewFile(uintptr(udsFD), "uds-fd")
	if _, err := fmt.Fprintf(udsSock, "%s pdeathsig=%d", fakeNetgoferAck, pdeathsig); err != nil {
		childFatalf("writing the ack: %v", err)
	}
	// Stay alive until the sentry socket closes or stopNetgofer stops the
	// process.
	var b [1]byte
	_, _ = udsSock.Read(b[:])
	os.Exit(0)
}

// useFakePasst makes startPasst run the test binary in a passt role with the
// given extra environment. It returns the path to use as the passt binary.
func useFakePasst(t *testing.T, role string, env ...string) string {
	t.Helper()
	old := passtTestEnv
	passtTestEnv = append([]string{childRoleEnv + "=" + role}, env...)
	t.Cleanup(func() { passtTestEnv = old })
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() failed: %v", err)
	}
	return exe
}

func TestPasstMACMatchesNetgofer(t *testing.T) {
	mac, err := net.ParseMAC(passtMAC)
	if err != nil {
		t.Fatalf("net.ParseMAC(%q) failed: %v", passtMAC, err)
	}
	if got, want := string(mac), string(netgofer.PasstMAC); got != want {
		t.Errorf("passtMAC = %v, want netgofer.PasstMAC %v", mac, netgofer.PasstMAC)
	}
	if got, want := string(passtGuestMAC), string(netgofer.PasstGuestMAC); got != want {
		t.Errorf("passtGuestMAC = %v, want netgofer.PasstGuestMAC %v", passtGuestMAC, netgofer.PasstGuestMAC)
	}
}

func TestPasstLinksAndRoutes(t *testing.T) {
	udsFile, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("os.Open(%q) failed: %v", os.DevNull, err)
	}
	defer udsFile.Close()

	// The software GSO and GRO flags must not apply to eth0.
	conf := &config.Config{GVisorGSO: true, GVisorGRO: true, NumNetworkChannels: 1}
	args := passtLinksAndRoutes(conf, false /* disableIPv6 */, udsFile)

	if len(args.LoopbackLinks) != 1 || len(args.LoopbackLinks[0].Addresses) != 2 {
		t.Errorf("LoopbackLinks = %+v, want one link with an IPv4 and an IPv6 address", args.LoopbackLinks)
	}
	if len(args.FDBasedLinks) != 1 {
		t.Fatalf("FDBasedLinks = %+v, want one link", args.FDBasedLinks)
	}
	eth0 := args.FDBasedLinks[0]
	if eth0.Name != "eth0" || !eth0.IsProxy || eth0.MTU != 65520 {
		t.Errorf("eth0 = {Name %q, IsProxy %t, MTU %d}, want {eth0, true, 65520}", eth0.Name, eth0.IsProxy, eth0.MTU)
	}
	if !slices.Equal(eth0.LinkAddress, net.HardwareAddr{0x02, 0x02, 0x02, 0x02, 0x02, 0x02}) {
		t.Errorf("eth0.LinkAddress = %v, want 02:02:02:02:02:02", eth0.LinkAddress)
	}
	if eth0.GVisorGSOEnabled || eth0.GSOMaxSize != 0 || eth0.GVisorGRO {
		t.Errorf("eth0 GSO/GRO = {GSO %t, MaxSize %d, GRO %t}, want {false, 0, false}",
			eth0.GVisorGSOEnabled, eth0.GSOMaxSize, eth0.GVisorGRO)
	}
	if len(eth0.Addresses) != 1 || !eth0.Addresses[0].Address.Equal(net.IP{10, 0, 2, 15}) || eth0.Addresses[0].PrefixLen != 24 {
		t.Errorf("eth0.Addresses = %+v, want 10.0.2.15/24", eth0.Addresses)
	}
	if len(eth0.Routes) != 1 || eth0.Routes[0].Destination.String() != "10.0.2.0/24" {
		t.Errorf("eth0.Routes = %+v, want 10.0.2.0/24", eth0.Routes)
	}
	gw := args.Defaultv4Gateway
	if gw.Name != "eth0" || !gw.Route.Gateway.Equal(net.IP{10, 0, 2, 2}) || gw.Route.Destination.String() != "0.0.0.0/0" {
		t.Errorf("Defaultv4Gateway = %+v, want 0.0.0.0/0 via 10.0.2.2 on eth0", gw)
	}
	if len(args.FilePayload.Files) != 1 || args.FilePayload.Files[0] != udsFile {
		t.Errorf("FilePayload.Files = %v, want [udsFile]", args.FilePayload.Files)
	}

	lo := passtLinksAndRoutes(conf, true /* disableIPv6 */, udsFile).LoopbackLinks[0]
	if len(lo.Addresses) != 1 || lo.Addresses[0].Address.To4() == nil || len(lo.Routes) != 1 || lo.Routes[0].Destination.IP.To4() == nil {
		t.Errorf("disableIPv6: lo = %+v, want one IPv4 address and one IPv4 route", lo)
	}
}

func (cm *containerManager) SetNetworkArgs(args *sentryapi.CreateLinksAndRoutesArgs, _ *struct{}) error {
	if cm.setNetwork != nil {
		return cm.setNetwork(args)
	}
	return nil
}

// netArgsRecorder records the network arguments that the sentry receives.
type netArgsRecorder struct {
	gotArgs sentryapi.CreateLinksAndRoutesArgs
	gotFDs  int
}

func (r *netArgsRecorder) handle(args *sentryapi.CreateLinksAndRoutesArgs) error {
	r.gotFDs = len(args.FilePayload.Files)
	args.FilePayload.Files = nil
	r.gotArgs = *args
	return nil
}

// startFakeURPCServer starts a control server that acts as the sentry. It
// calls onSet, if not nil, for each SetNetworkArgs call.
func startFakeURPCServer(t *testing.T, onSet func(*sentryapi.CreateLinksAndRoutesArgs) error) *urpc.Client {
	t.Helper()
	srvSock, cliSock, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("unet.SocketPair() failed: %v", err)
	}
	srv := urpc.NewServer()
	srv.Register(&containerManager{setNetwork: onSet})
	srv.StartHandling(srvSock)
	t.Cleanup(func() {
		srv.Stop(time.Second)
	})
	cli := urpc.NewClient(cliSock)
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

func TestCreatePasstInterfacesAndRoutes(t *testing.T) {
	udsFile, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("os.Open(%q) failed: %v", os.DevNull, err)
	}
	defer udsFile.Close()

	t.Run("flags", func(t *testing.T) {
		rec := &netArgsRecorder{}
		cli := startFakeURPCServer(t, rec.handle)
		conf := &config.Config{
			NumNetworkChannels: 1,
			LogPackets:         true,
			ReproduceNAT:       true,
			ReproduceNftables:  true,
		}
		mtu, err := createPasstInterfacesAndRoutes(cli, conf, true /* disableIPv6 */, true /* isRestore */, udsFile)
		if err != nil {
			t.Fatalf("createPasstInterfacesAndRoutes() failed: %v", err)
		}
		if mtu != 65520 {
			t.Errorf("mtu = %d, want 65520", mtu)
		}
		if rec.gotFDs != 1 || !rec.gotArgs.LogPackets || !rec.gotArgs.IsRestore || rec.gotArgs.NATBlob || rec.gotArgs.PCAP {
			t.Errorf("gotFDs=%d gotArgs=%+v, want 1 FD, LogPackets, IsRestore, no NATBlob, no PCAP", rec.gotFDs, rec.gotArgs)
		}
	})

	t.Run("pcap", func(t *testing.T) {
		tmpDir := t.TempDir()
		pcapPath := filepath.Join(tmpDir, "net.pcap")
		rec := &netArgsRecorder{}
		cli := startFakeURPCServer(t, rec.handle)
		conf := &config.Config{NumNetworkChannels: 1, PCAP: pcapPath}
		if _, err := createPasstInterfacesAndRoutes(cli, conf, false, false, udsFile); err != nil {
			t.Fatalf("createPasstInterfacesAndRoutes(PCAP) failed: %v", err)
		}
		if rec.gotFDs != 2 || !rec.gotArgs.PCAP {
			t.Errorf("gotFDs=%d PCAP=%t, want 2 and true", rec.gotFDs, rec.gotArgs.PCAP)
		}
		fi, err := os.Stat(pcapPath)
		if err != nil {
			t.Fatalf("os.Stat(%q) failed: %v", pcapPath, err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Errorf("PCAP mode = %o, want 0600", fi.Mode().Perm())
		}

		symPath := filepath.Join(tmpDir, "sym.pcap")
		if err := os.Symlink(pcapPath, symPath); err != nil {
			t.Fatalf("os.Symlink() failed: %v", err)
		}
		confSym := &config.Config{NumNetworkChannels: 1, PCAP: symPath}
		if _, err := createPasstInterfacesAndRoutes(cli, confSym, false, false, udsFile); err == nil {
			t.Error("createPasstInterfacesAndRoutes(symlink PCAP) succeeded, want O_NOFOLLOW error")
		}
	})
}

// readUntilEOF reads sock until EOF and returns the data. It fails the test
// if EOF does not arrive.
func readUntilEOF(t *testing.T, sock *os.File) string {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(sock)
		ch <- result{data, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("reading the passt socket: %v", res.err)
		}
		return string(res.data)
	case <-time.After(5 * time.Second):
		t.Fatal("no EOF on the passt socket: a copy of the passt end is still open")
		return ""
	}
}

func TestStartPasst(t *testing.T) {
	sock, err := startPasst(useFakePasst(t, rolePasstOK), nil)
	if err != nil {
		t.Fatalf("startPasst() failed: %v", err)
	}
	defer sock.Close()

	soType, err := unix.GetsockoptInt(int(sock.Fd()), unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || soType != unix.SOCK_STREAM {
		t.Errorf("SO_TYPE = %d (err=%v), want SOCK_STREAM (%d)", soType, err, unix.SOCK_STREAM)
	}
	fdFlags, err := unix.FcntlInt(sock.Fd(), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		t.Errorf("FD flags = %#x (err=%v), want FD_CLOEXEC set", fdFlags, err)
	}
	// The fake passt exited, and runsc must hold no copy of the passt end.
	if got := readUntilEOF(t, sock); got != fakePasstGreeting {
		t.Errorf("read %q from the passt socket, want %q", got, fakePasstGreeting)
	}
}

func TestStartPasstTimeout(t *testing.T) {
	old := passtStartTimeout
	passtStartTimeout = 100 * time.Millisecond
	t.Cleanup(func() { passtStartTimeout = old })

	sock, err := startPasst(useFakePasst(t, rolePasstHang), nil)
	if err == nil {
		_ = sock.Close()
		t.Fatal("startPasst() succeeded when passt did not exit, want timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("startPasst() error = %v, want timeout message", err)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("startPasst() error = %v, want *exec.ExitError", err)
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Errorf("wait status = %v, want SIGKILL", exitErr.ProcessState)
	}
}

func TestStartPasstFails(t *testing.T) {
	sock, err := startPasst(useFakePasst(t, rolePasstFail), nil)
	if err == nil {
		_ = sock.Close()
		t.Fatal("startPasst() succeeded, want error")
	}
	if !strings.Contains(err.Error(), "setup failed") {
		t.Errorf("startPasst() error = %v, want the passt output", err)
	}
	if _, err := startPasst(filepath.Join(t.TempDir(), "missing-passt"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("startPasst(missing) err = %v, want os.ErrNotExist", err)
	}

	// The clone fails if the cgroup FD is not a cgroup directory.
	dirFD, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("os.Open() failed: %v", err)
	}
	defer dirFD.Close()
	if _, err := startPasst(useFakePasst(t, rolePasstOK), dirFD); err == nil {
		t.Error("startPasst(non-cgroup FD) succeeded, want error")
	}
}

// peerUDSCapture records a duplicate of the sentry end of the netgofer UDS
// that setupNetwork sends over SetNetworkArgs.
type peerUDSCapture struct {
	peer *os.File
}

func (c *peerUDSCapture) handle(args *sentryapi.CreateLinksAndRoutesArgs) error {
	if len(args.FilePayload.Files) != 1 {
		return fmt.Errorf("got %d FDs, want 1", len(args.FilePayload.Files))
	}
	dupFD, err := unix.FcntlInt(args.FilePayload.Files[0].Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("F_DUPFD_CLOEXEC failed: %w", err)
	}
	c.peer = os.NewFile(uintptr(dupFD), "peer-uds")
	return nil
}

func (c *peerUDSCapture) close() {
	if c.peer != nil {
		_ = c.peer.Close()
		c.peer = nil
	}
}

// readNetgoferAck reads the fake netgofer ack and returns the parent-death
// signal that netgofer reports.
func (c *peerUDSCapture) readNetgoferAck(t *testing.T) string {
	t.Helper()
	if c.peer == nil {
		t.Fatal("peer UDS was not sent to SetNetworkArgs")
	}
	buf := make([]byte, 128)
	n, err := c.peer.Read(buf)
	if err != nil {
		t.Fatalf("reading ack from fake netgofer: %v", err)
	}
	ack, sig, ok := strings.Cut(string(buf[:n]), " pdeathsig=")
	if !ok || ack != fakeNetgoferAck {
		t.Fatalf("ack = %q, want %q followed by pdeathsig", buf[:n], fakeNetgoferAck)
	}
	return sig
}

func TestSetupNetworkPasst(t *testing.T) {
	missingDefault := filepath.Join(t.TempDir(), "no-default-passt")
	t.Cleanup(config.OverrideDefaultPasstBinaryForTest(missingDefault))
	// startProxy starts the test binary as netgofer. See TestMain.
	t.Setenv(childRoleEnv, roleNetgofer)

	t.Run("attached", func(t *testing.T) {
		tmp := t.TempDir()
		eofFile := filepath.Join(tmp, "eof")
		pidFile := filepath.Join(tmp, "daemon.pid")
		exe := useFakePasst(t, rolePasstDaemon, childEOFFileEnv+"="+eofFile, childPIDFileEnv+"="+pidFile)
		t.Cleanup(func() {
			if b, err := os.ReadFile(pidFile); err == nil {
				if pid, err := strconv.Atoi(string(b)); err == nil && pid > 1 {
					_ = unix.Kill(pid, unix.SIGKILL)
				}
			}
		})
		capture := &peerUDSCapture{}
		t.Cleanup(capture.close)
		cli := startFakeURPCServer(t, capture.handle)

		conf := &config.Config{
			Rootless:           true,
			Network:            config.NetworkSandbox,
			PasstBinary:        exe,
			NumNetworkChannels: 1,
		}
		spec := &specs.Spec{
			Linux: &specs.Linux{
				Namespaces: []specs.LinuxNamespace{{Type: specs.NetworkNamespace, Path: "/nonexistent/netns"}},
			},
		}
		s := &Sandbox{ID: "test-passt-sbx", attached: true}
		t.Cleanup(func() { s.stopNetgofer() })

		// The sandbox PID does not exist: passt mode must not use
		// /proc/<pid>/ns/net.
		if err := s.setupNetwork(cli, 99999999, spec, conf, false, false); err != nil {
			t.Fatalf("setupNetwork() failed: %v", err)
		}
		if !s.PasstResolved || s.PasstBinary != exe {
			t.Errorf("PasstResolved=%t PasstBinary=%q, want true and %q", s.PasstResolved, s.PasstBinary, exe)
		}
		if s.NetgoferPid.Load() <= 0 {
			t.Fatalf("NetgoferPid = %d, want > 0", s.NetgoferPid.Load())
		}
		if sig := capture.readNetgoferAck(t); sig != strconv.Itoa(int(unix.SIGKILL)) {
			t.Errorf("attached netgofer pdeathsig = %s, want %d (SIGKILL)", sig, unix.SIGKILL)
		}
		// The fake netgofer closed its passt socket. The fake passt daemon
		// sees that only if runsc closed its own copy (DonateAndClose).
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(eofFile); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the fake passt daemon did not see the socket close: runsc may hold a copy of the netgofer passt socket")
			}
			time.Sleep(20 * time.Millisecond)
		}
		capture.close()
		s.stopNetgofer()
		if s.NetgoferPid.Load() != 0 {
			t.Errorf("after stopNetgofer(), NetgoferPid = %d, want 0", s.NetgoferPid.Load())
		}
	})

	t.Run("saved mode, detached", func(t *testing.T) {
		exe := useFakePasst(t, rolePasstOK)
		capture := &peerUDSCapture{}
		t.Cleanup(capture.close)
		cli := startFakeURPCServer(t, capture.handle)
		// No --passt-binary and no default passt: only the mode that was saved
		// when the sandbox was created selects passt.
		conf := &config.Config{
			Rootless:           true,
			Network:            config.NetworkSandbox,
			NumNetworkChannels: 1,
		}
		s := &Sandbox{ID: "test-passt-saved", PasstBinary: exe, PasstResolved: true}
		t.Cleanup(func() { s.stopNetgofer() })
		if err := s.setupNetwork(cli, 99999999, nil, conf, false, false); err != nil {
			t.Fatalf("setupNetwork() failed: %v", err)
		}
		if sig := capture.readNetgoferAck(t); sig != "0" {
			t.Errorf("detached netgofer pdeathsig = %s, want 0", sig)
		}
	})

	t.Run("no passt binary", func(t *testing.T) {
		cli := startFakeURPCServer(t, nil)
		conf := &config.Config{
			Rootless:           true,
			Network:            config.NetworkSandbox,
			NumNetworkChannels: 1,
		}
		s := &Sandbox{ID: "test-no-passt"}
		err := s.setupNetwork(cli, 99999999, nil, conf, false, false)
		if err == nil || !strings.Contains(err.Error(), config.DefaultPasstBinary) {
			t.Errorf("setupNetwork() err = %v, want %q mentioned", err, config.DefaultPasstBinary)
		}
		if s.NetgoferPid.Load() != 0 {
			t.Errorf("NetgoferPid = %d, want 0", s.NetgoferPid.Load())
		}
	})
}
