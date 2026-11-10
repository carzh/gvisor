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
	"slices"
	"strings"
	"testing"
	"time"

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
	args := os.Args[1:]
	if !slices.Equal(args, passtArgs(3)) {
		fmt.Fprintf(os.Stderr, "fake passt: got args %q, want %q\n", args, passtArgs(3))
		os.Exit(2)
	}
	switch mode {
	case "ok":
		// Like passt, use the socket, then let the "daemon" keep it.
		sock := os.NewFile(3, "passt")
		if _, err := sock.Write([]byte(fakePasstGreeting)); err != nil {
			fmt.Fprintf(os.Stderr, "fake passt: write: %v\n", err)
			os.Exit(2)
		}
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
		t.Errorf("passtMAC = %s, want netgofer.PasstMAC %s", mac, netgofer.PasstMAC)
	}
}

func TestPasstLinksAndRoutes(t *testing.T) {
	conf := &config.Config{NumNetworkChannels: 4, GVisorGRO: true}
	udsFile, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("os.Open(%q) failed: %v", os.DevNull, err)
	}
	defer udsFile.Close()

	args := passtLinksAndRoutes(conf, udsFile)

	if len(args.LoopbackLinks) != 1 || args.LoopbackLinks[0].Name != "lo" || !args.LoopbackLinks[0].GVisorGRO {
		t.Errorf("LoopbackLinks = %+v, want one GRO-enabled \"lo\" link", args.LoopbackLinks)
	}
	if len(args.FDBasedLinks) != 1 {
		t.Fatalf("FDBasedLinks = %+v, want one link", args.FDBasedLinks)
	}
	eth0 := args.FDBasedLinks[0]
	if eth0.Name != "eth0" || !eth0.IsProxy || eth0.NumChannels != 1 || eth0.MTU != passtMTU {
		t.Errorf("eth0 = {Name %q, IsProxy %t, NumChannels %d, MTU %d}, want {eth0, true, 1, %d}",
			eth0.Name, eth0.IsProxy, eth0.NumChannels, eth0.MTU, passtMTU)
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
	if len(args.FilePayload.Files) != 1 || args.FilePayload.Files[0] != udsFile {
		t.Errorf("FilePayload.Files = %v, want [udsFile]", args.FilePayload.Files)
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

func TestStartPasst(t *testing.T) {
	t.Setenv(fakePasstEnv, "ok")
	sock, err := startPasst(&config.Config{PasstBinary: os.Args[0]})
	if err != nil {
		t.Fatalf("startPasst() failed: %v", err)
	}
	defer sock.Close()

	// The returned socket must be connected to the socket that passt got.
	if err := sock.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Logf("SetReadDeadline() failed: %v", err)
	}
	buf := make([]byte, len(fakePasstGreeting))
	if _, err := sock.Read(buf); err != nil {
		t.Fatalf("reading from the passt socket failed: %v", err)
	}
	if got := string(buf); got != fakePasstGreeting {
		t.Errorf("read %q from the passt socket, want %q", got, fakePasstGreeting)
	}
}

func TestStartPasstFails(t *testing.T) {
	t.Setenv(fakePasstEnv, "fail")
	sock, err := startPasst(&config.Config{PasstBinary: os.Args[0]})
	if err == nil {
		sock.Close()
		t.Fatal("startPasst() succeeded, want error")
	}
	if !strings.Contains(err.Error(), "setup failed") {
		t.Errorf("startPasst() error = %v, want it to contain the passt output", err)
	}
}
