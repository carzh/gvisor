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

package donation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

func TestDonateLogFileTruncRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", target, err)
	}
	link := filepath.Join(dir, "out.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink(%q, %q) failed: %v", target, link, err)
	}

	var a Agency
	defer a.Close()
	if err := a.DonateLogFile("log-fd", link, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, &log.DefaultFileOpts{}); !errors.Is(err, unix.ELOOP) {
		t.Errorf("DonateLogFile(%q) = %v, want ELOOP", link, err)
	}
}

func TestDonateLogFileFlags(t *testing.T) {
	for _, flags := range []int{
		os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
		os.O_CREATE | os.O_WRONLY | os.O_APPEND,
		os.O_RDONLY,
	} {
		var a Agency
		if err := a.DonateLogFile("log-fd", "", flags, &log.DefaultFileOpts{}); err != nil {
			t.Errorf("DonateLogFile(\"\", %#x) = %v, want nil", flags, err)
		}
	}
	for _, flags := range []int{
		os.O_CREATE | os.O_WRONLY | os.O_APPEND | os.O_TRUNC,
		os.O_CREATE | os.O_WRONLY,
		os.O_RDWR,
		os.O_RDONLY | os.O_CREATE,
		os.O_RDONLY | os.O_APPEND,
	} {
		var a Agency
		if err := a.DonateLogFile("log-fd", "", flags, &log.DefaultFileOpts{}); err == nil {
			t.Errorf("DonateLogFile(\"\", %#x) succeeded, want error", flags)
		}
	}
}
