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
	"slices"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	netgofer "gvisor.dev/gvisor/runsc/gofer/net"
)

// fakePasstEnv selects the fake passt behavior when the test binary runs as
// passt (see init).
const fakePasstEnv = "SANDBOX_TEST_FAKE_PASST"

// fakePasstGreeting is what the fake passt writes to its socket.
const fakePasstGreeting = "hello from fake passt"

// init runs the fake passt when the test binary is started as passt by
// startPasst. It runs before the test framework parses flags, because passt
// flags are not test flags.
func init() {
	mode := os.Getenv(fakePasstEnv)
	if mode == "" {
		return
	}
	if mode == "sleep" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
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
	case "ok":
		sock := os.NewFile(3, "passt")
		if _, err := sock.Write([]byte(fakePasstGreeting)); err != nil {
			fmt.Fprintf(os.Stderr, "fake passt: write: %v\n", err)
			os.Exit(2)
		}
		_ = sock.Close()
		os.Exit(0)
	case "hold-pipe":
		sock := os.NewFile(3, "passt")
		if _, err := sock.Write([]byte(fakePasstGreeting)); err != nil {
			fmt.Fprintf(os.Stderr, "fake passt: write: %v\n", err)
			os.Exit(2)
		}
		_ = sock.Close()
		// Spawn a background child that inherits stderr so cmd.WaitDelay is
		// exercised after the first process exits.
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "fake passt: os.Executable: %v\n", err)
			os.Exit(2)
		}
		bg := exec.Command(exe, "-test.run=^$")
		bg.Env = append(os.Environ(), fakePasstEnv+"=sleep")
		bg.Stderr = os.Stderr
		if err := bg.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "fake passt: start background child: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	case "hang":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "fail":
		fmt.Fprintln(os.Stderr, "fake passt: setup failed")
		os.Exit(1)
	default:
		os.Exit(3)
	}
}

func TestPasstMACMatchesNetgofer(t *testing.T) {
	mac, err := net.ParseMAC(passtMAC)
	if err != nil {
		t.Fatalf("net.ParseMAC(%q) failed: %v", passtMAC, err)
	}
	if got, want := string(mac), string(netgofer.PasstMAC); got != want {
		t.Errorf("passtMAC = %v, want netgofer.PasstMAC %v", mac, netgofer.PasstMAC)
	}
}

func TestPasstLinksAndRoutes(t *testing.T) {
	conf := &config.Config{
		GVisorGSO:                   true,
		GVisorGRO:                   true,
		TXChecksumOffload:           true,
		RXChecksumOffload:           true,
		QDisc:                       config.QDiscFIFO,
		TBFRate:                     1000,
		TBFBurst:                    2000,
		NetworkProcessorsPerChannel: 2,
		PauseExternalNetworking:     true,
		AllowConnectedOnSave:        true,
	}
	udsFile, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("os.Open(%q) failed: %v", os.DevNull, err)
	}
	defer udsFile.Close()

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
	if eth0.Name != "eth0" || !eth0.IsProxy || eth0.NumChannels != 1 || eth0.MTU != passtMTU {
		t.Errorf("eth0 = {Name %q, IsProxy %t, NumChannels %d, MTU %d}, want {eth0, true, 1, %d}",
			eth0.Name, eth0.IsProxy, eth0.NumChannels, eth0.MTU, passtMTU)
	}
	if !eth0.GVisorGSOEnabled || eth0.GSOMaxSize != tcpip.GVisorGSOMaxSize {
		t.Errorf("eth0 GSO = {Enabled %t, MaxSize %d}, want {true, %d}", eth0.GVisorGSOEnabled, eth0.GSOMaxSize, tcpip.GVisorGSOMaxSize)
	}
	if !eth0.TXChecksumOffload || !eth0.RXChecksumOffload || !eth0.GVisorGRO {
		t.Errorf("eth0 offloads = {TX %t, RX %t, GRO %t}, want all true", eth0.TXChecksumOffload, eth0.RXChecksumOffload, eth0.GVisorGRO)
	}
	if eth0.QDisc != config.QDiscFIFO || eth0.TBFRate != 1000 || eth0.TBFBurst != 2000 || eth0.ProcessorsPerChannel != 2 {
		t.Errorf("eth0 qdisc/processors = {QDisc %v, TBFRate %d, TBFBurst %d, Processors %d}, want {FIFO, 1000, 2000, 2}",
			eth0.QDisc, eth0.TBFRate, eth0.TBFBurst, eth0.ProcessorsPerChannel)
	}
	wantAddr := []sentryapi.IPWithPrefix{{Address: net.IPv4(10, 0, 2, 15).To4(), PrefixLen: 24}}
	if len(eth0.Addresses) != 1 || !eth0.Addresses[0].Address.Equal(wantAddr[0].Address) || eth0.Addresses[0].PrefixLen != 24 {
		t.Errorf("eth0.Addresses = %+v, want %+v", eth0.Addresses, wantAddr)
	}
	if len(eth0.Routes) != 1 || eth0.Routes[0].Destination.String() != "10.0.2.0/24" {
		t.Errorf("eth0.Routes = %+v, want 10.0.2.0/24", eth0.Routes)
	}
	gw := args.Defaultv4Gateway
	if gw.Name != "eth0" || !gw.Route.Gateway.Equal(net.IPv4(10, 0, 2, 2)) || gw.Route.Destination.String() != "0.0.0.0/0" {
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

	argsNoV6 := passtLinksAndRoutes(conf, true /* disableIPv6 */, udsFile)
	if len(argsNoV6.LoopbackLinks[0].Addresses) != 1 || argsNoV6.LoopbackLinks[0].Addresses[0].Address.To4() == nil {
		t.Errorf("disableIPv6 lo.Addresses = %+v, want 1 IPv4 address", argsNoV6.LoopbackLinks[0].Addresses)
	}
	if len(argsNoV6.LoopbackLinks[0].Routes) != 1 || argsNoV6.LoopbackLinks[0].Routes[0].Destination.IP.To4() == nil {
		t.Errorf("disableIPv6 lo.Routes = %+v, want 1 IPv4 route", argsNoV6.LoopbackLinks[0].Routes)
	}
}

func TestPasstArgs(t *testing.T) {
	args := strings.Join(passtArgs(3), " ")
	for _, want := range []string{
		"--fd 3",
		"--ipv4-only",
		"--address 10.0.2.15",
		"--netmask 24",
		"--gateway 10.0.2.2",
		"--mac-addr " + passtMAC,
		"--no-map-gw",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("passtArgs(3) = %q, want it to contain %q", args, want)
		}
	}
	for _, unwanted := range []string{"--foreground", "-f "} {
		if strings.Contains(args+" ", unwanted) {
			t.Errorf("passtArgs(3) = %q, want no %q (passt must daemonize)", args, unwanted)
		}
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
		// After the fake passt closes its end and startPasst closes runsc's
		// copy, reading again must return io.EOF.
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
	t.Setenv(fakePasstEnv, "ok")
	sock, err := startPasst(os.Args[0], nil)
	if err != nil {
		t.Fatalf("startPasst() failed: %v", err)
	}
	defer sock.Close()
	readPasstGreetingAndEOF(t, sock)
}

func TestStartPasstWaitDelay(t *testing.T) {
	t.Setenv(fakePasstEnv, "hold-pipe")
	sock, err := startPasst(os.Args[0], nil)
	if err != nil {
		t.Fatalf("startPasst() failed when child held stderr open: %v", err)
	}
	defer sock.Close()
	readPasstGreetingAndEOF(t, sock)
}

func TestStartPasstTimeout(t *testing.T) {
	old := passtStartTimeout
	passtStartTimeout = 100 * time.Millisecond
	t.Cleanup(func() { passtStartTimeout = old })

	t.Setenv(fakePasstEnv, "hang")
	sock, err := startPasst(os.Args[0], nil)
	if err == nil {
		_ = sock.Close()
		t.Fatal("startPasst() succeeded when passt hung, want timeout error")
	}
}

func TestStartPasstFails(t *testing.T) {
	t.Setenv(fakePasstEnv, "fail")
	sock, err := startPasst(os.Args[0], nil)
	if err == nil {
		_ = sock.Close()
		t.Fatal("startPasst() succeeded, want error")
	}
	if !strings.Contains(err.Error(), "setup failed") {
		t.Errorf("startPasst() error = %v, want it to contain the passt output", err)
	}
	if _, err := startPasst("", nil); err == nil {
		t.Error("startPasst(\"\") succeeded, want error")
	}
}
