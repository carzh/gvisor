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
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
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
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{
			name: "loopback only falls back to 8.8.8.8",
			in:   "# Dynamic resolv.conf\nnameserver 127.0.0.53\nnameserver 127.0.0.1\nsearch corp.example.com\noptions edns0 trust-ad\n",
			want: "nameserver 8.8.8.8\nsearch corp.example.com\noptions edns0 trust-ad\n",
		},
		{
			name: "non-loopback ipv4 kept and ipv6/link-local skipped",
			in:   "nameserver ::1\nnameserver 169.254.169.254\nnameserver 1.1.1.1\nnameserver 8.8.4.4\n",
			want: "nameserver 1.1.1.1\nnameserver 8.8.4.4\n",
		},
		{
			name: "empty input falls back to 8.8.8.8",
			in:   "",
			want: "nameserver 8.8.8.8\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := passtResolvConf(tc.in); got != tc.want {
				t.Errorf("passtResolvConf() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSetupRootlessNet(t *testing.T) {
	passtBin := filepath.Join(t.TempDir(), "passt")
	if err := os.WriteFile(passtBin, nil, 0755); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", passtBin, err)
	}

	t.Run("passt enabled adds netns and mounts resolv.conf", func(t *testing.T) {
		doCmd := &Do{quiet: true}
		conf := &config.Config{
			Rootless:    true,
			Network:     config.NetworkSandbox,
			PasstBinary: passtBin,
		}
		spec := &specs.Spec{}
		clean, err := doCmd.setupRootlessNet(conf, 1000, spec, "nameserver 127.0.0.1\n")
		if err != nil {
			t.Fatalf("setupRootlessNet() failed: %v", err)
		}
		defer clean()

		if conf.Network != config.NetworkSandbox {
			t.Errorf("conf.Network = %v, want %v", conf.Network, config.NetworkSandbox)
		}
		if spec.Linux == nil || len(spec.Linux.Namespaces) != 1 || spec.Linux.Namespaces[0].Type != specs.NetworkNamespace {
			t.Errorf("spec.Linux.Namespaces = %+v, want [{Type: NetworkNamespace}]", spec.Linux)
		}
		if len(spec.Mounts) != 1 || spec.Mounts[0].Destination != "/etc/resolv.conf" {
			t.Fatalf("spec.Mounts = %+v, want 1 mount for /etc/resolv.conf", spec.Mounts)
		}
		gotResolv, err := os.ReadFile(spec.Mounts[0].Source)
		if err != nil {
			t.Fatalf("os.ReadFile(%q) failed: %v", spec.Mounts[0].Source, err)
		}
		if string(gotResolv) != "nameserver 8.8.8.8\n" {
			t.Errorf("resolv.conf = %q, want %q", gotResolv, "nameserver 8.8.8.8\n")
		}
	})

	t.Run("passt disabled switches to host network", func(t *testing.T) {
		doCmd := &Do{quiet: true}
		conf := &config.Config{
			Rootless: true,
			Network:  config.NetworkSandbox,
			Netgofer: config.NetgoferModeProxy,
		}
		spec := &specs.Spec{}
		clean, err := doCmd.setupRootlessNet(conf, 1000, spec, "nameserver 127.0.0.1\n")
		if err != nil {
			t.Fatalf("setupRootlessNet() failed: %v", err)
		}
		defer clean()

		if conf.Network != config.NetworkHost {
			t.Errorf("conf.Network = %v, want %v", conf.Network, config.NetworkHost)
		}
		if spec.Linux != nil && len(spec.Linux.Namespaces) != 0 {
			t.Errorf("spec.Linux.Namespaces = %+v, want empty", spec.Linux.Namespaces)
		}
	})
}
