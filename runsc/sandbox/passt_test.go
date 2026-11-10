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
	// fakePasstEnv selects the fake passt behavior in init.
	fakePasstEnv = "SANDBOX_TEST_FAKE_PASST"

	// fakePasstPidFileEnv passes a file path where hold-pipe and hold-sock
	// record their child PID.
	fakePasstPidFileEnv = "SANDBOX_TEST_FAKE_PASST_PID_FILE"

	// fakePasstEOFFileEnv passes a file path that the hold-sock child creates
	// when it reads EOF on the inherited passt socket.
	fakePasstEOFFileEnv = "SANDBOX_TEST_FAKE_PASST_EOF_FILE"

	// fakePasstGreeting is written by the fake passt to its inherited socket.
	fakePasstGreeting = "hello from fake passt"

	// fakeNetgoferAck is written by the fake netgofer to the sentry UDS socket.
	fakeNetgoferAck = "netgofer-passt-ok"
)

// init runs fake passt or fake netgofer modes when the test binary is invoked
// as a helper subprocess. It runs before testing parses flags so helper flags
// do not fail flag parsing.
func init() {
	if filepath.Base(os.Args[0]) == "runsc-netgofer" {
		runFakeNetgofer()
	}

	mode := os.Getenv(fakePasstEnv)
	if mode == "" {
		return
	}
	if mode == "sleep" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if mode == "hold-sock-child" {
		runHoldSockChild()
	}
	if os.Args[0] != "passt" {
		fmt.Fprintf(os.Stderr, "fake passt: got argv[0] = %q, want \"passt\"\n", os.Args[0])
		os.Exit(2)
	}
	args := os.Args[1:]
	if !slices.Equal(args, passtArgs(3)) {
		fmt.Fprintf(os.Stderr, "fake passt: got args %q, want %q\n", args, passtArgs(3))
		os.Exit(2)
	}
	switch mode {
	case "ok", "hold-pipe", "hold-sock":
		sock := os.NewFile(3, "passt")
		if _, err := sock.Write([]byte(fakePasstGreeting)); err != nil {
			fmt.Fprintf(os.Stderr, "fake passt: write: %v\n", err)
			os.Exit(2)
		}
		if mode == "hold-sock" {
			// Model the passt daemon: a background child keeps the socket open
			// after the parent exits.
			startFakePasstChild("hold-sock-child", sock)
		}
		_ = sock.Close()
		if mode == "ok" || mode == "hold-sock" {
			fmt.Fprintln(os.Stderr, "fake passt: initialized")
			os.Exit(0)
		}
		startFakePasstChild("sleep", nil)
		os.Exit(0)
	case "hang":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "fail":
		fmt.Fprintln(os.Stderr, "fake passt: setup failed")
		os.Exit(1)
	default:
		os.Exit(3)
	}
}

// startFakePasstChild starts a background copy of the test binary in mode.
// If sock is non-nil, the child inherits it as FD 3. The child inherits
// stderr, so it keeps the passt output pipe open.
func startFakePasstChild(mode string, sock *os.File) {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake passt: os.Executable: %v\n", err)
		os.Exit(2)
	}
	bg := exec.Command(exe, "-test.run=^$")
	bg.Env = []string{fakePasstEnv + "=" + mode, fakePasstEOFFileEnv + "=" + os.Getenv(fakePasstEOFFileEnv)}
	bg.Stderr = os.Stderr
	if sock != nil {
		bg.ExtraFiles = []*os.File{sock}
	}
	if err := bg.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "fake passt: start background child: %v\n", err)
		os.Exit(2)
	}
	if pidFile := os.Getenv(fakePasstPidFileEnv); pidFile != "" {
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(bg.Process.Pid)), 0600)
	}
}

// runHoldSockChild reads the inherited passt socket (FD 3) until EOF, then
// creates the file named by fakePasstEOFFileEnv. EOF arrives only after every
// copy of the netgofer end of the socket pair is closed.
func runHoldSockChild() {
	go func() {
		time.Sleep(30 * time.Second)
		os.Exit(3)
	}()
	sock := os.NewFile(3, "passt")
	var buf [64]byte
	for {
		if _, err := sock.Read(buf[:]); err != nil {
			break
		}
	}
	if eofFile := os.Getenv(fakePasstEOFFileEnv); eofFile != "" {
		_ = os.WriteFile(eofFile, nil, 0600)
	}
	os.Exit(0)
}

func runFakeNetgofer() {
	var (
		udsFD   = -1
		passtFD = -1
		sawMTU  = false
		sawSub  = false
	)
	for _, arg := range os.Args[1:] {
		if arg == "netgofer" {
			sawSub = true
		}
		if !sawSub {
			continue
		}
		switch {
		case arg == "--allow-loopback":
			fmt.Fprintln(os.Stderr, "fake netgofer: unexpected --allow-loopback in passt mode")
			os.Exit(2)
		case arg == fmt.Sprintf("--mtu=%d", passtMTU):
			sawMTU = true
		case strings.HasPrefix(arg, "--uds-fd="):
			v, err := strconv.Atoi(strings.TrimPrefix(arg, "--uds-fd="))
			if err != nil {
				os.Exit(2)
			}
			udsFD = v
		case strings.HasPrefix(arg, "--passt-fd="):
			v, err := strconv.Atoi(strings.TrimPrefix(arg, "--passt-fd="))
			if err != nil {
				os.Exit(2)
			}
			passtFD = v
		}
	}
	if !sawSub || !sawMTU || udsFD < 0 || passtFD < 0 {
		fmt.Fprintf(os.Stderr, "fake netgofer: missing expected args in %q\n", os.Args)
		os.Exit(2)
	}

	passtSock := os.NewFile(uintptr(passtFD), "passt-fd")
	buf := make([]byte, len(fakePasstGreeting))
	if _, err := io.ReadFull(passtSock, buf); err != nil || string(buf) != fakePasstGreeting {
		fmt.Fprintf(os.Stderr, "fake netgofer: reading greeting err=%v got=%q\n", err, buf)
		os.Exit(2)
	}
	// Close the only netgofer copy of the socket. A fake passt daemon then
	// reads EOF only if runsc closed its own copy.
	_ = passtSock.Close()

	pdeathsig, err := getPdeathsig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake netgofer: reading PR_GET_PDEATHSIG: %v\n", err)
		os.Exit(2)
	}
	udsSock := os.NewFile(uintptr(udsFD), "uds-fd")
	if _, err := fmt.Fprintf(udsSock, "%s pdeathsig=%d", fakeNetgoferAck, pdeathsig); err != nil {
		fmt.Fprintf(os.Stderr, "fake netgofer: writing ack: %v\n", err)
		os.Exit(2)
	}
	// Block until udsSock closes or stopNetgofer signals us.
	var extra [1]byte
	_, _ = udsSock.Read(extra[:])
	_ = udsSock.Close()
	os.Exit(0)
}

func TestMain(m *testing.M) {
	sidecarDir, err := os.MkdirTemp("", "sandbox-test-sidecars-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp failed: %v\n", err)
		os.Exit(1)
	}
	exe, err := os.Executable()
	if err != nil {
		_ = os.RemoveAll(sidecarDir)
		fmt.Fprintf(os.Stderr, "Executable failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.Symlink(exe, filepath.Join(sidecarDir, "runsc-netgofer")); err != nil {
		_ = os.RemoveAll(sidecarDir)
		fmt.Fprintf(os.Stderr, "Symlink failed: %v\n", err)
		os.Exit(1)
	}
	_ = os.Setenv("GVISOR_SIDECAR_BINARIES_DIR", sidecarDir)

	code := m.Run()
	_ = os.RemoveAll(sidecarDir)
	os.Exit(code)
}

func setFakePasstEnv(t *testing.T, envs ...string) {
	t.Helper()
	old := passtTestEnv
	passtTestEnv = envs
	t.Cleanup(func() { passtTestEnv = old })
}

func testExePath(t *testing.T) string {
	t.Helper()
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

	conf := &config.Config{
		GVisorGSO:                   true,
		GVisorGRO:                   true,
		TXChecksumOffload:           true,
		RXChecksumOffload:           false,
		NumNetworkChannels:          4,
		QDisc:                       config.QDiscFIFO,
		TBFRate:                     1000,
		TBFBurst:                    2000,
		NetworkProcessorsPerChannel: 2,
		PauseExternalNetworking:     true,
		AllowConnectedOnSave:        true,
	}
	args := passtLinksAndRoutes(conf, false /* disableIPv6 */, udsFile)

	if len(args.LoopbackLinks) != 1 || args.LoopbackLinks[0].Name != "lo" || !args.LoopbackLinks[0].GVisorGRO {
		t.Errorf("LoopbackLinks = %+v, want one GRO-enabled \"lo\" link", args.LoopbackLinks)
	}
	if len(args.LoopbackLinks[0].Addresses) != 2 {
		t.Errorf("lo.Addresses = %+v, want 2 addresses (IPv4 and IPv6)", args.LoopbackLinks[0].Addresses)
	}
	if len(args.FDBasedLinks) != 1 {
		t.Fatalf("FDBasedLinks = %+v, want one link", args.FDBasedLinks)
	}
	eth0 := args.FDBasedLinks[0]
	if eth0.Name != "eth0" || !eth0.IsProxy || eth0.NumChannels != 1 || eth0.MTU != 65520 {
		t.Errorf("eth0 = {Name %q, IsProxy %t, NumChannels %d, MTU %d}, want {eth0, true, 1, 65520}",
			eth0.Name, eth0.IsProxy, eth0.NumChannels, eth0.MTU)
	}
	if !slices.Equal(eth0.LinkAddress, net.HardwareAddr{0x02, 0x02, 0x02, 0x02, 0x02, 0x02}) {
		t.Errorf("eth0.LinkAddress = %v, want 02:02:02:02:02:02", eth0.LinkAddress)
	}
	if eth0.GVisorGSOEnabled || eth0.GSOMaxSize != 0 || eth0.GVisorGRO {
		t.Errorf("eth0 GSO/GRO = {GSO %t, MaxSize %d, GRO %t}, want {false, 0, false}",
			eth0.GVisorGSOEnabled, eth0.GSOMaxSize, eth0.GVisorGRO)
	}
	// configureProxyLink promotes RXChecksumOffload when TXChecksumOffload is set.
	if !eth0.TXChecksumOffload || !eth0.RXChecksumOffload {
		t.Errorf("eth0 checksum offloads = {TX %t, RX %t}, want both true", eth0.TXChecksumOffload, eth0.RXChecksumOffload)
	}
	if eth0.QDisc != config.QDiscFIFO || eth0.TBFRate != 1000 || eth0.TBFBurst != 2000 || eth0.ProcessorsPerChannel != 2 {
		t.Errorf("eth0 qdisc/processors = {QDisc %v, TBFRate %d, TBFBurst %d, Processors %d}, want {FIFO, 1000, 2000, 2}",
			eth0.QDisc, eth0.TBFRate, eth0.TBFBurst, eth0.ProcessorsPerChannel)
	}
	wantAddr := []sentryapi.IPWithPrefix{{Address: net.IP{10, 0, 2, 15}, PrefixLen: 24}}
	if len(eth0.Addresses) != 1 || !eth0.Addresses[0].Address.Equal(wantAddr[0].Address) || eth0.Addresses[0].PrefixLen != 24 {
		t.Errorf("eth0.Addresses = %+v, want %+v", eth0.Addresses, wantAddr)
	}
	if len(eth0.Routes) != 1 || eth0.Routes[0].Destination.String() != "10.0.2.0/24" {
		t.Errorf("eth0.Routes = %+v, want 10.0.2.0/24", eth0.Routes)
	}
	gw := args.Defaultv4Gateway
	if gw.Name != "eth0" || !gw.Route.Gateway.Equal(net.IP{10, 0, 2, 2}) || gw.Route.Destination.String() != "0.0.0.0/0" {
		t.Errorf("Defaultv4Gateway = %+v, want 0.0.0.0/0 via 10.0.2.2 on eth0", gw)
	}
	if !args.Defaultv6Gateway.Route.Empty() {
		t.Errorf("Defaultv6Gateway = %+v, want empty", args.Defaultv6Gateway)
	}
	if args.AllowExternalLoopbackTraffic {
		t.Error("AllowExternalLoopbackTraffic = true, want false")
	}
	if !args.PauseExternalNetworking || !args.AllowConnectedOnSave {
		t.Errorf("args flags = {PauseExternalNetworking %t, AllowConnectedOnSave %t}, want both true",
			args.PauseExternalNetworking, args.AllowConnectedOnSave)
	}
	if len(args.FilePayload.Files) != 1 || args.FilePayload.Files[0] != udsFile {
		t.Errorf("FilePayload.Files = %v, want [udsFile]", args.FilePayload.Files)
	}

	argsDefaultOff := passtLinksAndRoutes(&config.Config{NumNetworkChannels: 1}, true /* disableIPv6 */, udsFile)
	eth0Off := argsDefaultOff.FDBasedLinks[0]
	if eth0Off.TXChecksumOffload || eth0Off.RXChecksumOffload || argsDefaultOff.LoopbackLinks[0].GVisorGRO || argsDefaultOff.PauseExternalNetworking || argsDefaultOff.AllowConnectedOnSave {
		t.Errorf("default-false config produced unexpected true flags: %+v", argsDefaultOff)
	}
	if len(argsDefaultOff.LoopbackLinks[0].Addresses) != 1 || argsDefaultOff.LoopbackLinks[0].Addresses[0].Address.To4() == nil {
		t.Errorf("disableIPv6 lo.Addresses = %+v, want 1 IPv4 address", argsDefaultOff.LoopbackLinks[0].Addresses)
	}
	if len(argsDefaultOff.LoopbackLinks[0].Routes) != 1 || argsDefaultOff.LoopbackLinks[0].Routes[0].Destination.IP.To4() == nil {
		t.Errorf("disableIPv6 lo.Routes = %+v, want 1 IPv4 route", argsDefaultOff.LoopbackLinks[0].Routes)
	}
	if len(sentryapi.DefaultLoopbackLink.Addresses) != 2 || len(sentryapi.DefaultLoopbackLink.Routes) != 2 {
		t.Errorf("DefaultLoopbackLink mutated: %+v", sentryapi.DefaultLoopbackLink)
	}
}

func (cm *containerManager) SetNetworkArgs(args *sentryapi.CreateLinksAndRoutesArgs, _ *struct{}) error {
	if cm.setNetwork != nil {
		return cm.setNetwork(args)
	}
	return nil
}

type netArgsRecorder struct {
	gotArgs sentryapi.CreateLinksAndRoutesArgs
	gotFDs  int
	retErr  error
}

func (r *netArgsRecorder) handle(args *sentryapi.CreateLinksAndRoutesArgs) error {
	r.gotFDs = len(args.FilePayload.Files)
	args.FilePayload.Files = nil
	r.gotArgs = *args
	return r.retErr
}

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

	t.Run("nil udsFile fails", func(t *testing.T) {
		rec := &netArgsRecorder{}
		cli := startFakeURPCServer(t, rec.handle)
		if _, err := createPasstInterfacesAndRoutes(cli, &config.Config{NumNetworkChannels: 1}, false, false, nil); err == nil {
			t.Fatal("createPasstInterfacesAndRoutes(nil udsFile) succeeded, want error")
		}
	})

	t.Run("propagates flags and ignores reproduce-nat", func(t *testing.T) {
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
			t.Errorf("gotFDs=%d gotArgs=%+v", rec.gotFDs, rec.gotArgs)
		}
	})

	t.Run("pcap creates 0600 file and rejects symlink", func(t *testing.T) {
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

	t.Run("rpc error propagated", func(t *testing.T) {
		rec := &netArgsRecorder{retErr: errors.New("boom")}
		cli := startFakeURPCServer(t, rec.handle)
		if _, err := createPasstInterfacesAndRoutes(cli, &config.Config{NumNetworkChannels: 1}, false, false, udsFile); err == nil {
			t.Error("createPasstInterfacesAndRoutes() succeeded on RPC error, want error")
		}
	})
}

func TestPasstArgs(t *testing.T) {
	want := []string{
		"--fd", "7",
		"--one-off",
		"--ipv4-only",
		"--address", "10.0.2.15",
		"--netmask", "24",
		"--gateway", "10.0.2.2",
		"--mac-addr", "02:02:02:02:02:03",
		"--no-map-gw",
		"--tcp-ports", "none",
		"--udp-ports", "none",
		"--no-dhcp",
		"--no-dhcp-dns",
		"--no-dhcp-search",
		"--dns", "none",
		"--search", "none",
		"--quiet",
	}
	if got := passtArgs(7); !slices.Equal(got, want) {
		t.Errorf("passtArgs(7) = %q, want %q", got, want)
	}
}

func readPasstGreetingAndEOF(t *testing.T, sock *os.File) {
	t.Helper()
	type readResult struct {
		got string
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		buf := make([]byte, len(fakePasstGreeting))
		if _, err := io.ReadFull(sock, buf); err != nil {
			ch <- readResult{err: fmt.Errorf("reading greeting: %w", err)}
			return
		}
		var extra [1]byte
		if _, err := sock.Read(extra[:]); !errors.Is(err, io.EOF) {
			ch <- readResult{err: fmt.Errorf("read after peer close = %v, want io.EOF", err)}
			return
		}
		ch <- readResult{got: string(buf)}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatal(res.err)
		}
		if res.got != fakePasstGreeting {
			t.Errorf("read %q from the passt socket, want %q", res.got, fakePasstGreeting)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading greeting and EOF from the passt socket")
	}
}

func TestStartPasst(t *testing.T) {
	setFakePasstEnv(t, fakePasstEnv+"=ok")
	// Invoke through a symlink named "pasta" to verify argv[0] is forced to "passt".
	pastaLink := filepath.Join(t.TempDir(), "pasta")
	if err := os.Symlink(testExePath(t), pastaLink); err != nil {
		t.Fatalf("os.Symlink() failed: %v", err)
	}
	sock, err := startPasst(pastaLink, nil)
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
	readPasstGreetingAndEOF(t, sock)
}

func TestStartPasstHoldPipe(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "bg.pid")
	setFakePasstEnv(t, fakePasstEnv+"=hold-pipe", fakePasstPidFileEnv+"="+pidFile)
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
				_ = unix.Kill(pid, unix.SIGKILL)
			}
		}
	})

	start := time.Now()
	sock, err := startPasst(testExePath(t), nil)
	if err != nil {
		t.Fatalf("startPasst() failed when child held stderr open: %v", err)
	}
	defer sock.Close()
	// The grandchild holds the pipe for 30s, so a blocking read takes 30s.
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("startPasst() blocked for %v while grandchild held pipe open, want < 10s", elapsed)
	}
	readPasstGreetingAndEOF(t, sock)
}

func TestStartPasstTimeout(t *testing.T) {
	old := passtStartTimeout
	passtStartTimeout = 100 * time.Millisecond
	t.Cleanup(func() { passtStartTimeout = old })

	setFakePasstEnv(t, fakePasstEnv+"=hang")
	sock, err := startPasst(testExePath(t), nil)
	if err == nil {
		_ = sock.Close()
		t.Fatal("startPasst() succeeded when passt hung, want timeout error")
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
	setFakePasstEnv(t, fakePasstEnv+"=fail")
	sock, err := startPasst(testExePath(t), nil)
	if err == nil {
		_ = sock.Close()
		t.Fatal("startPasst() succeeded, want error")
	}
	if !strings.Contains(err.Error(), "setup failed") {
		t.Errorf("startPasst() error = %v, want passt stderr output", err)
	}
	if _, err := startPasst("", nil); err == nil {
		t.Error("startPasst(\"\") succeeded, want error")
	}
	if _, err := startPasst("relative/passt", nil); err == nil {
		t.Error("startPasst(relative) succeeded, want error")
	}
	if _, err := startPasst(filepath.Join(t.TempDir(), "missing-passt"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("startPasst(missing) err = %v, want os.ErrNotExist", err)
	}
	if _, err := startPasst(t.TempDir(), nil); err == nil {
		t.Error("startPasst(directory) succeeded, want error")
	}

	dirFD, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("os.Open() failed: %v", err)
	}
	defer dirFD.Close()
	setFakePasstEnv(t, fakePasstEnv+"=ok")
	if _, err := startPasst(testExePath(t), dirFD); err == nil {
		t.Error("startPasst(non-cgroup dirFD) succeeded, want clone3 error")
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
	exe := testExePath(t)
	missingDefault := filepath.Join(t.TempDir(), "no-default-passt")
	t.Cleanup(config.OverrideDefaultPasstBinaryForTest(missingDefault))

	t.Run("full setupNetwork spawns passt and netgofer and closes runsc passtSock", func(t *testing.T) {
		tmp := t.TempDir()
		eofFile := filepath.Join(tmp, "eof")
		pidFile := filepath.Join(tmp, "child.pid")
		setFakePasstEnv(t, fakePasstEnv+"=hold-sock", fakePasstEOFFileEnv+"="+eofFile, fakePasstPidFileEnv+"="+pidFile)
		t.Cleanup(func() {
			if b, err := os.ReadFile(pidFile); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
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

		// Pass a nonexistent PID to verify /proc/<pid>/ns/net is never accessed.
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
		// The fake passt daemon reads EOF only after netgofer closes its end
		// and runsc has closed its own copy (DonateAndClose).
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(eofFile); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("fake passt daemon did not read EOF: runsc may hold a copy of the netgofer passt socket")
			}
			time.Sleep(20 * time.Millisecond)
		}
		capture.close()
		s.stopNetgofer()
		if s.NetgoferPid.Load() != 0 {
			t.Errorf("after stopNetgofer(), NetgoferPid = %d, want 0", s.NetgoferPid.Load())
		}
	})

	t.Run("persisted passt binary is used and detached netgofer has no pdeathsig", func(t *testing.T) {
		setFakePasstEnv(t, fakePasstEnv+"=ok")
		capture := &peerUDSCapture{}
		t.Cleanup(capture.close)
		cli := startFakeURPCServer(t, capture.handle)
		// No --passt-binary and no default passt: only the state from sandbox
		// creation selects passt mode.
		conf := &config.Config{
			Rootless:           true,
			Network:            config.NetworkSandbox,
			NumNetworkChannels: 1,
		}
		s := &Sandbox{ID: "test-passt-persisted", PasstBinary: exe, PasstResolved: true}
		t.Cleanup(func() { s.stopNetgofer() })
		if err := s.setupNetwork(cli, 99999999, nil, conf, false, false); err != nil {
			t.Fatalf("setupNetwork() failed: %v", err)
		}
		if sig := capture.readNetgoferAck(t); sig != "0" {
			t.Errorf("detached netgofer pdeathsig = %s, want 0", sig)
		}
	})

	t.Run("persisted non-passt mode ignores a passt binary that appears later", func(t *testing.T) {
		setFakePasstEnv(t, fakePasstEnv+"=ok")
		rec := &netArgsRecorder{}
		cli := startFakeURPCServer(t, rec.handle)
		conf := &config.Config{
			Rootless:           true,
			Network:            config.NetworkSandbox,
			PasstBinary:        exe,
			NumNetworkChannels: 1,
		}
		s := &Sandbox{ID: "test-no-passt-persisted", PasstResolved: true}
		err := s.setupNetwork(cli, 99999999, nil, conf, false, false)
		if err == nil || !strings.Contains(err.Error(), "created without passt") {
			t.Errorf("setupNetwork() err = %v, want saved non-passt mode error", err)
		}
		if s.PasstBinary != "" || s.NetgoferPid.Load() != 0 {
			t.Errorf("PasstBinary=%q NetgoferPid=%d, want empty and 0", s.PasstBinary, s.NetgoferPid.Load())
		}
	})

	t.Run("rootless sandbox with netgofer proxy returns conflict error", func(t *testing.T) {
		rec := &netArgsRecorder{}
		cli := startFakeURPCServer(t, rec.handle)
		conf := &config.Config{
			Rootless:           true,
			Network:            config.NetworkSandbox,
			Netgofer:           config.NetgoferModeProxy,
			NumNetworkChannels: 1,
		}
		s := &Sandbox{ID: "test-passt-conflict"}
		err := s.setupNetwork(cli, 99999999, nil, conf, false, false)
		if err == nil || !strings.Contains(err.Error(), "incompatible with --netgofer") {
			t.Errorf("setupNetwork() err = %v, want conflict error", err)
		}
		if s.NetgoferPid.Load() != 0 {
			t.Errorf("NetgoferPid = %d, want 0", s.NetgoferPid.Load())
		}
	})

	t.Run("startPasst failure returns error and leaves NetgoferPid 0", func(t *testing.T) {
		setFakePasstEnv(t, fakePasstEnv+"=fail")
		rec := &netArgsRecorder{}
		cli := startFakeURPCServer(t, rec.handle)
		conf := &config.Config{
			Rootless:           true,
			Network:            config.NetworkSandbox,
			PasstBinary:        exe,
			NumNetworkChannels: 1,
		}
		s := &Sandbox{ID: "test-passt-fail"}
		err := s.setupNetwork(cli, 99999999, nil, conf, false, false)
		if err == nil || !strings.Contains(err.Error(), "setup failed") {
			t.Errorf("setupNetwork() err = %v, want passt failure", err)
		}
		if s.NetgoferPid.Load() != 0 {
			t.Errorf("NetgoferPid = %d, want 0", s.NetgoferPid.Load())
		}
	})

	t.Run("rootless sandbox without passt returns actionable error", func(t *testing.T) {
		rec := &netArgsRecorder{}
		cli := startFakeURPCServer(t, rec.handle)
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
	})

	t.Run("network host and none ignore passt-binary without starting sidecars", func(t *testing.T) {
		setFakePasstEnv(t, fakePasstEnv+"=fail")
		for _, netType := range []config.NetworkType{config.NetworkHost, config.NetworkNone} {
			rec := &netArgsRecorder{}
			cli := startFakeURPCServer(t, rec.handle)
			conf := &config.Config{
				Rootless:           true,
				Network:            netType,
				PasstBinary:        exe,
				NumNetworkChannels: 1,
			}
			s := &Sandbox{ID: "test-non-sandbox"}
			if err := s.setupNetwork(cli, 99999999, nil, conf, false, false); err != nil {
				t.Errorf("setupNetwork(%v) failed: %v", netType, err)
			}
			if s.NetgoferPid.Load() != 0 {
				t.Errorf("NetgoferPid = %d for %v, want 0", s.NetgoferPid.Load(), netType)
			}
		}
	})
}
