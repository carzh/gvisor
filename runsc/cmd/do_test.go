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

package cmd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/gofer/net/egressfilter"
)

func TestIDMapSlice(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    idMapSlice
		wantErr error
	}{
		{input: "0 1000 1", want: idMapSlice{{ContainerID: 0, HostID: 1000, Size: 1}}},
		{input: "2147483648 4294967294 1", want: idMapSlice{{ContainerID: 2147483648, HostID: 4294967294, Size: 1}}},
		{input: "0 0 4294967295", want: idMapSlice{{ContainerID: 0, HostID: 0, Size: 4294967295}}},
		{input: "0 1000 1,100 2000 10", want: idMapSlice{{ContainerID: 0, HostID: 1000, Size: 1}, {ContainerID: 100, HostID: 2000, Size: 10}}},
		{input: "foo 1000 1", wantErr: strconv.ErrSyntax},
		{input: "0 foo 1", wantErr: strconv.ErrSyntax},
		{input: "0 1000 foo", wantErr: strconv.ErrSyntax},
		{input: "-1 1000 1", wantErr: strconv.ErrSyntax},
		{input: "0 -1 1", wantErr: strconv.ErrSyntax},
		{input: "0 1000 -1", wantErr: strconv.ErrSyntax},
		{input: "4294967296 1000 1", wantErr: strconv.ErrRange},
		{input: "0 4294967296 1", wantErr: strconv.ErrRange},
		{input: "0 1000 4294967297", wantErr: strconv.ErrRange},
	} {
		t.Run(tc.input, func(t *testing.T) {
			var got idMapSlice
			if err := got.Set(tc.input); !errors.Is(err, tc.wantErr) {
				t.Errorf("Set(%q): got error %v, want %v", tc.input, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Set(%q): unexpected mappings (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestPasstResolvConf(t *testing.T) {
	hostAddrs := func() map[[4]byte]struct{} {
		return map[[4]byte]struct{}{{192, 168, 122, 1}: {}}
	}

	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{
			name: "loopback only falls back to 8.8.8.8 and drops internal search suffix",
			in:   "# Dynamic resolv.conf\nnameserver 127.0.0.53\nnameserver 127.0.0.1\nsearch corp.example.com\ndomain corp.example.com\noptions edns0 trust-ad\n",
			want: "nameserver 8.8.8.8\noptions edns0 trust-ad\n",
		},
		{
			name: "non-loopback ipv4 kept and ipv6 link-local host-ip and guest-ip skipped",
			in:   "nameserver ::1\nnameserver 169.254.169.254\nnameserver 192.168.122.1\nnameserver 10.0.2.15\nnameserver 1.1.1.1\nnameserver 8.8.4.4\n",
			want: "nameserver 1.1.1.1\nnameserver 8.8.4.4\n",
		},
		{
			name: "unspecified current-network multicast broadcast malformed and global ipv6 skipped",
			in:   "; comment\nnameserver\nnameserver not-an-ip\nnameserver 0.0.0.0\nnameserver 0.1.2.3\nnameserver 224.0.0.1\nnameserver 255.255.255.255\nnameserver 2001:4860:4860::8888\nnameserver ::ffff:127.0.0.1\n",
			want: "nameserver 8.8.8.8\n",
		},
		{
			name: "ipv4-mapped ipv6 normalized inline comments stripped and domain preserved",
			in:   "  search a.example   b.example # comment\r\ndomain sub.example ; semi\nnameserver ::ffff:1.1.1.1 # quad1\noptions ndots:2 # opt\nbad\x00line\nsortlist 130.155.160.0\n",
			want: "nameserver 1.1.1.1\nsearch a.example b.example\ndomain sub.example\noptions ndots:2\n",
		},
		{
			name: "empty input falls back to 8.8.8.8",
			in:   "",
			want: "nameserver 8.8.8.8\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := passtResolvConf(tc.in, hostAddrs); got != tc.want {
				t.Errorf("passtResolvConf() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("host addresses read once and only for a candidate nameserver", func(t *testing.T) {
		calls := 0
		countingAddrs := func() map[[4]byte]struct{} {
			calls++
			return hostAddrs()
		}
		if got, want := passtResolvConf("nameserver 127.0.0.53\nnameserver 169.254.169.254\n", countingAddrs), "nameserver 8.8.8.8\n"; got != want {
			t.Errorf("passtResolvConf() = %q, want %q", got, want)
		}
		if calls != 0 {
			t.Errorf("readHostAddrs called %d times for non-candidate nameservers, want 0", calls)
		}
		if got, want := passtResolvConf("nameserver 192.168.122.1\nnameserver 1.1.1.1\nnameserver 8.8.4.4\n", countingAddrs), "nameserver 1.1.1.1\nnameserver 8.8.4.4\n"; got != want {
			t.Errorf("passtResolvConf() = %q, want %q", got, want)
		}
		if calls != 1 {
			t.Errorf("readHostAddrs called %d times, want 1", calls)
		}
	})

	t.Run("nil host address reader keeps static checks", func(t *testing.T) {
		if got, want := passtResolvConf("nameserver 127.0.0.1\nnameserver 192.168.122.1\n", nil), "nameserver 192.168.122.1\n"; got != want {
			t.Errorf("passtResolvConf() = %q, want %q", got, want)
		}
	})
}

// TestPasstNameserverMatchesEgressFilter checks that do.go keeps a nameserver
// only if the netgofer egress filter allows DNS traffic to it.
func TestPasstNameserverMatchesEgressFilter(t *testing.T) {
	hostIP := [4]byte{192, 168, 122, 1}
	filter, err := egressfilter.New(egressfilter.Options{LocalAddrs: []net.IP{net.IP(hostIP[:])}})
	if err != nil {
		t.Fatalf("egressfilter.New() failed: %v", err)
	}
	hostAddrs := map[[4]byte]struct{}{hostIP: {}}
	for _, ip4 := range [][4]byte{
		{0, 0, 0, 0}, {0, 1, 2, 3}, {1, 1, 1, 1}, {8, 8, 8, 8}, {10, 0, 2, 2},
		{10, 1, 2, 3}, {127, 0, 0, 1}, {127, 0, 0, 53}, {169, 254, 169, 254},
		{172, 16, 0, 1}, {192, 168, 122, 1}, {224, 0, 0, 1}, {239, 255, 255, 250},
		{255, 255, 255, 255},
	} {
		_, isHost := hostAddrs[ip4]
		got := passtNameserverCandidate(ip4) && !isHost
		want := filter.Allows(tcpip.AddrFrom4(ip4), 53)
		if got != want {
			t.Errorf("nameserver %v: do.go keeps it = %t, egress filter allows it = %t", net.IP(ip4[:]), got, want)
		}
	}
}

func TestHasResolvConfMount(t *testing.T) {
	for _, tc := range []struct {
		dst  string
		want bool
	}{
		{dst: "/etc", want: true},
		{dst: "/etc/", want: true},
		{dst: "/etc/resolv.conf", want: true},
		{dst: "/etc//resolv.conf", want: true},
		{dst: "/etc/resolv.conf/sub", want: true},
		{dst: "/etc/resolv.conf.bak", want: false},
		{dst: "/etc/hosts", want: false},
		{dst: "/etcetera", want: false},
	} {
		spec := &specs.Spec{Mounts: []specs.Mount{{Destination: tc.dst}}}
		if got := hasResolvConfMount(spec); got != tc.want {
			t.Errorf("hasResolvConfMount(%q) = %t, want %t", tc.dst, got, tc.want)
		}
	}
}

func TestSetupRootlessNet(t *testing.T) {
	passtBin := filepath.Join(t.TempDir(), "passt")
	if err := os.WriteFile(passtBin, nil, 0755); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", passtBin, err)
	}
	missingDefault := filepath.Join(t.TempDir(), "no-default-passt")
	t.Cleanup(config.OverrideDefaultPasstBinaryForTest(missingDefault))

	rootWithResolv := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootWithResolv, "etc"), 0755); err != nil {
		t.Fatalf("os.MkdirAll() failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootWithResolv, "etc", "resolv.conf"), []byte("nameserver 127.0.0.1\n"), 0644); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	t.Run("passt enabled post-reexec euid 0 adds netns writes stderr and cleans up 0644 resolv.conf", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		doCmd := &Do{out: &stdout, errOut: &stderr}
		conf := &config.Config{
			Rootless:    true,
			Network:     config.NetworkSandbox,
			PasstBinary: passtBin,
		}
		spec := &specs.Spec{Root: &specs.Root{Path: rootWithResolv}}
		readCalled := false
		clean, err := doCmd.setupRootlessNet(conf, 0, spec, func() string {
			readCalled = true
			return "nameserver 127.0.0.1\n"
		})
		if err != nil {
			t.Fatalf("setupRootlessNet() failed: %v", err)
		}
		t.Cleanup(clean)
		if !readCalled {
			t.Error("readResolvConf was not called in passt mode")
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want empty on normal passt startup", stdout.String())
		}
		if !strings.Contains(stderr.String(), "Using passt") {
			t.Errorf("stderr = %q, want passt notice", stderr.String())
		}
		if conf.Network != config.NetworkSandbox {
			t.Errorf("conf.Network = %v, want %v", conf.Network, config.NetworkSandbox)
		}
		if spec.Linux == nil || len(spec.Linux.Namespaces) != 1 || spec.Linux.Namespaces[0].Type != specs.NetworkNamespace || spec.Linux.Namespaces[0].Path != "" {
			t.Errorf("spec.Linux.Namespaces = %+v, want [{Type: NetworkNamespace, Path: \"\"}]", spec.Linux)
		}
		if len(spec.Mounts) != 1 || spec.Mounts[0].Destination != "/etc/resolv.conf" {
			t.Fatalf("spec.Mounts = %+v, want 1 mount for /etc/resolv.conf", spec.Mounts)
		}
		src := spec.Mounts[0].Source
		if !slices.Contains(spec.Mounts[0].Options, "ro") || !slices.Contains(spec.Mounts[0].Options, "nosuid") {
			t.Errorf("mount options = %v, want ro and nosuid", spec.Mounts[0].Options)
		}
		fi, err := os.Stat(src)
		if err != nil {
			t.Fatalf("os.Stat(%q) failed: %v", src, err)
		}
		if fi.Mode().Perm() != 0644 {
			t.Errorf("resolv.conf mode = %o, want 0644", fi.Mode().Perm())
		}
		parentInfo, err := os.Stat(filepath.Dir(src))
		if err != nil {
			t.Fatalf("os.Stat(parent) failed: %v", err)
		}
		if parentInfo.Mode().Perm() != 0700 {
			t.Errorf("temp dir mode = %o, want 0700", parentInfo.Mode().Perm())
		}
		gotResolv, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("os.ReadFile(%q) failed: %v", src, err)
		}
		if string(gotResolv) != "nameserver 8.8.8.8\n" {
			t.Errorf("resolv.conf = %q, want %q", gotResolv, "nameserver 8.8.8.8\n")
		}

		clean()
		if _, err := os.Stat(filepath.Dir(src)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("after clean(), temp dir stat err = %v, want os.ErrNotExist", err)
		}
	})

	t.Run("existing user resolv.conf mount is not shadowed", func(t *testing.T) {
		doCmd := &Do{quiet: true}
		conf := &config.Config{
			Rootless:    true,
			Network:     config.NetworkSandbox,
			PasstBinary: passtBin,
		}
		spec := &specs.Spec{
			Root:   &specs.Root{Path: rootWithResolv},
			Mounts: []specs.Mount{{Source: "/custom/resolv.conf", Destination: "/etc/resolv.conf", Type: "bind"}},
		}
		readCalled := false
		clean, err := doCmd.setupRootlessNet(conf, 1000, spec, func() string {
			readCalled = true
			return "nameserver 1.1.1.1\n"
		})
		if err != nil {
			t.Fatalf("setupRootlessNet() failed: %v", err)
		}
		defer clean()
		if readCalled {
			t.Error("readResolvConf called despite user /etc/resolv.conf mount")
		}
		if len(spec.Mounts) != 1 || spec.Mounts[0].Source != "/custom/resolv.conf" {
			t.Errorf("spec.Mounts = %+v, want user mount preserved alone", spec.Mounts)
		}
	})

	t.Run("missing resolv.conf in rootfs skips bind mount without mutating rootfs", func(t *testing.T) {
		emptyRoot := t.TempDir()
		doCmd := &Do{quiet: true}
		conf := &config.Config{
			Rootless:    true,
			Network:     config.NetworkSandbox,
			PasstBinary: passtBin,
		}
		spec := &specs.Spec{Root: &specs.Root{Path: emptyRoot}}
		clean, err := doCmd.setupRootlessNet(conf, 1000, spec, func() string { return "nameserver 1.1.1.1\n" })
		if err != nil {
			t.Fatalf("setupRootlessNet() failed: %v", err)
		}
		defer clean()
		if len(spec.Mounts) != 0 {
			t.Errorf("spec.Mounts = %+v, want empty when /etc/resolv.conf is absent in rootfs", spec.Mounts)
		}
		if _, err := os.Stat(filepath.Join(emptyRoot, "etc")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("emptyRoot/etc stat err = %v, want os.ErrNotExist", err)
		}
	})

	t.Run("non-regular or symlinked resolv.conf in rootfs skips bind mount", func(t *testing.T) {
		dirRoot := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dirRoot, "etc", "resolv.conf"), 0755); err != nil {
			t.Fatalf("os.MkdirAll() failed: %v", err)
		}
		danglingRoot := t.TempDir()
		if err := os.MkdirAll(filepath.Join(danglingRoot, "etc"), 0755); err != nil {
			t.Fatalf("os.MkdirAll() failed: %v", err)
		}
		if err := os.Symlink("../run/systemd/resolve/stub-resolv.conf", filepath.Join(danglingRoot, "etc", "resolv.conf")); err != nil {
			t.Fatalf("os.Symlink() failed: %v", err)
		}
		for _, root := range []string{dirRoot, danglingRoot} {
			doCmd := &Do{quiet: true}
			conf := &config.Config{
				Rootless:    true,
				Network:     config.NetworkSandbox,
				PasstBinary: passtBin,
			}
			spec := &specs.Spec{Root: &specs.Root{Path: root}}
			clean, err := doCmd.setupRootlessNet(conf, 1000, spec, func() string { return "nameserver 1.1.1.1\n" })
			if err != nil {
				t.Fatalf("setupRootlessNet(%q) failed: %v", root, err)
			}
			clean()
			if len(spec.Mounts) != 0 {
				t.Errorf("root %q: spec.Mounts = %+v, want empty", root, spec.Mounts)
			}
		}
	})

	t.Run("erofs root keeps its own resolv.conf", func(t *testing.T) {
		doCmd := &Do{quiet: true, erofs: "/images/root.erofs"}
		conf := &config.Config{
			Rootless:    true,
			Network:     config.NetworkSandbox,
			PasstBinary: passtBin,
		}
		spec := &specs.Spec{}
		readCalled := false
		clean, err := doCmd.setupRootlessNet(conf, 1000, spec, func() string {
			readCalled = true
			return "nameserver 1.1.1.1\n"
		})
		if err != nil {
			t.Fatalf("setupRootlessNet() failed: %v", err)
		}
		defer clean()
		if readCalled || len(spec.Mounts) != 0 {
			t.Errorf("readCalled=%t spec.Mounts=%+v, want no host resolv.conf read and no mount", readCalled, spec.Mounts)
		}
		if spec.Linux == nil || len(spec.Linux.Namespaces) != 1 || spec.Linux.Namespaces[0].Type != specs.NetworkNamespace {
			t.Errorf("spec.Linux = %+v, want a new network namespace", spec.Linux)
		}
	})

	t.Run("passt missing switches to host network without reading resolv.conf", func(t *testing.T) {
		var stdout bytes.Buffer
		doCmd := &Do{out: &stdout}
		conf := &config.Config{
			Rootless: true,
			Network:  config.NetworkSandbox,
		}
		spec := &specs.Spec{}
		readCalled := false
		clean, err := doCmd.setupRootlessNet(conf, 1000, spec, func() string {
			readCalled = true
			return "nameserver 1.1.1.1\n"
		})
		if err != nil {
			t.Fatalf("setupRootlessNet() failed: %v", err)
		}
		defer clean()
		if readCalled {
			t.Error("readResolvConf called when passt is missing")
		}
		if conf.Network != config.NetworkHost {
			t.Errorf("conf.Network = %v, want %v", conf.Network, config.NetworkHost)
		}
		if !strings.Contains(stdout.String(), config.DefaultPasstBinary) {
			t.Errorf("warning = %q, want %q mentioned", stdout.String(), config.DefaultPasstBinary)
		}
	})

	t.Run("proxy or xdp conflict switches to host network with conflict warning", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			conf config.Config
		}{
			{name: "netgofer", conf: config.Config{Rootless: true, Network: config.NetworkSandbox, Netgofer: config.NetgoferModeProxy}},
			{name: "proxy-path", conf: config.Config{Rootless: true, Network: config.NetworkSandbox, NetworkProxyPath: "/run/p.sock"}},
			{name: "xdp", conf: config.Config{Rootless: true, Network: config.NetworkSandbox, XDP: config.XDP{Mode: config.XDPModeNS}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var stdout bytes.Buffer
				doCmd := &Do{out: &stdout}
				spec := &specs.Spec{}
				clean, err := doCmd.setupRootlessNet(&tc.conf, 1000, spec, nil)
				if err != nil {
					t.Fatalf("setupRootlessNet() failed: %v", err)
				}
				defer clean()
				if tc.conf.Network != config.NetworkHost {
					t.Errorf("conf.Network = %v, want %v", tc.conf.Network, config.NetworkHost)
				}
				if !strings.Contains(stdout.String(), "incompatible with --netgofer, --network-proxy-path, and XDP") {
					t.Errorf("warning = %q, want conflict message", stdout.String())
				}
			})
		}
	})

	t.Run("network host is a no-op", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		doCmd := &Do{out: &stdout, errOut: &stderr}
		conf := &config.Config{
			Rootless: true,
			Network:  config.NetworkHost,
		}
		spec := &specs.Spec{}
		clean, err := doCmd.setupRootlessNet(conf, 1000, spec, nil)
		if err != nil {
			t.Fatalf("setupRootlessNet() failed: %v", err)
		}
		defer clean()
		if conf.Network != config.NetworkHost || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Errorf("Network=%v stdout=%q stderr=%q, want NetworkHost and no output", conf.Network, stdout.String(), stderr.String())
		}
	})
}

func TestRunValidateRootlessSandboxNet(t *testing.T) {
	passtBin := filepath.Join(t.TempDir(), "passt")
	if err := os.WriteFile(passtBin, nil, 0755); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", passtBin, err)
	}
	missingDefault := filepath.Join(t.TempDir(), "no-default-passt")
	t.Cleanup(config.OverrideDefaultPasstBinaryForTest(missingDefault))

	for _, tc := range []struct {
		name    string
		conf    config.Config
		euid    int
		wantErr string
	}{
		{
			name: "passt enabled euid 1000",
			conf: config.Config{Rootless: true, Network: config.NetworkSandbox, PasstBinary: passtBin},
			euid: 1000,
		},
		{
			name: "passt enabled post-reexec euid 0",
			conf: config.Config{Rootless: true, Network: config.NetworkSandbox, PasstBinary: passtBin},
			euid: 0,
		},
		{
			name: "network none without passt",
			conf: config.Config{Rootless: true, Network: config.NetworkNone},
			euid: 0,
		},
		{
			name: "network host without passt",
			conf: config.Config{Rootless: true, Network: config.NetworkHost},
			euid: 0,
		},
		{
			name:    "missing passt binary",
			conf:    config.Config{Rootless: true, Network: config.NetworkSandbox},
			euid:    0,
			wantErr: config.DefaultPasstBinary,
		},
		{
			name:    "netgofer conflict",
			conf:    config.Config{Rootless: true, Network: config.NetworkSandbox, Netgofer: config.NetgoferModeProxy},
			euid:    0,
			wantErr: "incompatible with --netgofer",
		},
		{
			name:    "proxy-path conflict",
			conf:    config.Config{Rootless: true, Network: config.NetworkSandbox, NetworkProxyPath: "/run/p.sock"},
			euid:    0,
			wantErr: "incompatible with --netgofer, --network-proxy-path, and XDP",
		},
		{
			name:    "xdp conflict",
			conf:    config.Config{Rootless: true, Network: config.NetworkSandbox, XDP: config.XDP{Mode: config.XDPModeNS}},
			euid:    0,
			wantErr: "incompatible with --netgofer, --network-proxy-path, and XDP",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRootlessSandboxNet(&tc.conf, tc.euid)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("validateRootlessSandboxNet() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("validateRootlessSandboxNet() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("Run.Execute fails before MaybeRunAsRoot when passt is missing", func(t *testing.T) {
		var errBuf bytes.Buffer
		oldLogger := util.ErrorLogger
		util.ErrorLogger = &errBuf
		t.Cleanup(func() { util.ErrorLogger = oldLogger })

		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		var r Run
		r.SetFlags(fs)
		if err := fs.Parse([]string{"test-cid"}); err != nil {
			t.Fatalf("fs.Parse() failed: %v", err)
		}
		conf := &config.Config{Rootless: true, Network: config.NetworkSandbox}
		var ws unix.WaitStatus
		if got := r.Execute(context.Background(), fs, conf, &ws); got != subcommands.ExitFailure {
			t.Errorf("Run.Execute() = %v, want %v", got, subcommands.ExitFailure)
		}
		if !strings.Contains(errBuf.String(), config.DefaultPasstBinary) {
			t.Errorf("ErrorLogger = %q, want %q mentioned", errBuf.String(), config.DefaultPasstBinary)
		}
	})
}
