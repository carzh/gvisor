// Copyright 2024 The gVisor Authors.
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

package sandboxsetup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShouldExposeNvidiaDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "nvidiactl", path: "/dev/nvidiactl", want: true},
		{name: "nvidia-uvm", path: "/dev/nvidia-uvm", want: true},
		{name: "nvidia0", path: "/dev/nvidia0", want: true},
		{name: "nvidia1", path: "/dev/nvidia1", want: true},
		{name: "nvidia42", path: "/dev/nvidia42", want: true},
		{name: "nvidia-uvm-tools", path: "/dev/nvidia-uvm-tools", want: true},
		{name: "nvidia-modeset", path: "/dev/nvidia-modeset", want: false},
		{name: "not nvidia", path: "/dev/sda", want: false},
		{name: "nvidia prefix but not device", path: "/dev/nvidia-cap1", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeNvidiaDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeNvidiaDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestShouldExposeVFIODevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "vfio dir", path: "/dev/vfio/vfio", want: true},
		{name: "vfio group", path: "/dev/vfio/0", want: true},
		{name: "vfio dir itself", path: "/dev/vfio", want: true},
		{name: "not vfio", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeVFIODevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeVFIODevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestShouldExposeTpuDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// VFIO devices are always detected as TPU devices regardless of sysfs.
		{name: "vfio device", path: "/dev/vfio/0", want: true},
		{name: "vfio vfio", path: "/dev/vfio/vfio", want: true},
		{name: "not tpu", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeTpuDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeTpuDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestSafeSetupAndMoveMountRejectsSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, nil, 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", src, err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, nil, 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", other, err)
	}
	missing := filepath.Join(dir, "missing")
	for _, tc := range []struct {
		name    string
		target  string
		wantErr string
	}{
		{name: "dangling", target: missing, wantErr: "failed to safely move mount: Open"},
		{name: "live", target: other, wantErr: "expected to open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(dir, "dst-"+tc.name)
			if err := os.Symlink(tc.target, dst); err != nil {
				t.Fatalf("os.Symlink() failed: %v", err)
			}
			// The source mount FD is invalid: the destination check must fail
			// before move_mount(2) runs.
			err := safeSetupAndMoveMount(-1, src, dst, "")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("safeSetupAndMoveMount(%q -> %q) err = %v, want %q", dst, tc.target, err, tc.wantErr)
			}
			if _, err := os.Lstat(missing); !os.IsNotExist(err) {
				t.Errorf("os.Lstat(%q) err = %v, want not exist", missing, err)
			}
		})
	}
}
