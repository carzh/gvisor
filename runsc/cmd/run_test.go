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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

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
		wantErr string
	}{
		{
			name: "passt enabled",
			conf: config.Config{Rootless: true, Network: config.NetworkSandbox, PasstBinary: passtBin},
		},
		{
			name: "network none without passt",
			conf: config.Config{Rootless: true, Network: config.NetworkNone},
		},
		{
			name:    "missing passt binary",
			conf:    config.Config{Rootless: true, Network: config.NetworkSandbox},
			wantErr: config.DefaultPasstBinary,
		},
		{
			name:    "netgofer conflict",
			conf:    config.Config{Rootless: true, Network: config.NetworkSandbox, Netgofer: config.NetgoferModeProxy},
			wantErr: "incompatible with --netgofer",
		},
		{
			name:    "xdp conflict",
			conf:    config.Config{Rootless: true, Network: config.NetworkSandbox, XDP: config.XDP{Mode: config.XDPModeNS}},
			wantErr: "incompatible with --netgofer, --network-proxy-path, and XDP",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// With --rootless, runsc calls the check with effective UID 0.
			err := validateRootlessSandboxNet(&tc.conf, 0)
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

	t.Run("Run.Execute fails when passt is missing", func(t *testing.T) {
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
