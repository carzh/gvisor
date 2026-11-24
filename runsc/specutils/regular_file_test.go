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

package specutils

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenAndTruncateRegularFileExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("old-bytes"), 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", path, err)
	}

	f, err := OpenAndTruncateRegularFile(path, 0644)
	if err != nil {
		t.Fatalf("OpenAndTruncateRegularFile(%q) failed: %v", path, err)
	}
	defer f.Close()

	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatalf("unix.FcntlInt(F_GETFL) failed: %v", err)
	}
	if flags&unix.O_NONBLOCK != 0 {
		t.Errorf("file status flags = %#x, want O_NONBLOCK cleared", flags)
	}
	if _, err := f.Write([]byte("new")); err != nil {
		t.Fatalf("f.Write() failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) failed: %v", path, err)
	}
	if string(got) != "new" {
		t.Errorf("file content = %q, want %q", got, "new")
	}
}

func TestOpenAndTruncateRegularFileCreates(t *testing.T) {
	// Clear the umask so that the mode of the new file is exactly perm.
	oldMask := unix.Umask(0)
	t.Cleanup(func() { _ = unix.Umask(oldMask) })
	path := filepath.Join(t.TempDir(), "file")

	f, err := OpenAndTruncateRegularFile(path, 0640)
	if err != nil {
		t.Fatalf("OpenAndTruncateRegularFile(%q) failed: %v", path, err)
	}
	defer f.Close()

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("os.Lstat(%q) failed: %v", path, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0640 || fi.Size() != 0 {
		t.Errorf("created file has mode %v and size %d, want a regular file with mode 0640 and size 0", fi.Mode(), fi.Size())
	}
}

func TestOpenAndTruncateRegularFileRejects(t *testing.T) {
	const otherContent = "do-not-truncate"
	writeOther := func(t *testing.T, dir string) string {
		t.Helper()
		other := filepath.Join(dir, "other")
		if err := os.WriteFile(other, []byte(otherContent), 0600); err != nil {
			t.Fatalf("os.WriteFile(%q) failed: %v", other, err)
		}
		return other
	}

	for _, tc := range []struct {
		name     string
		setup    func(t *testing.T, dir, path string)
		hasOther bool
		wantErr  error
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, dir, path string) {
				other := writeOther(t, dir)
				if err := os.Symlink(other, path); err != nil {
					t.Fatalf("os.Symlink(%q, %q) failed: %v", other, path, err)
				}
			},
			hasOther: true,
			wantErr:  unix.ELOOP,
		},
		{
			name: "hard link",
			setup: func(t *testing.T, dir, path string) {
				other := writeOther(t, dir)
				if err := os.Link(other, path); err != nil {
					t.Fatalf("os.Link(%q, %q) failed: %v", other, path, err)
				}
			},
			hasOther: true,
			wantErr:  errMultipleLinks,
		},
		{
			name: "FIFO without reader",
			setup: func(t *testing.T, dir, path string) {
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatalf("unix.Mkfifo(%q) failed: %v", path, err)
				}
			},
			wantErr: unix.ENXIO,
		},
		{
			name: "FIFO with reader",
			setup: func(t *testing.T, dir, path string) {
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatalf("unix.Mkfifo(%q) failed: %v", path, err)
				}
				rfd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatalf("unix.Open(%q) failed: %v", path, err)
				}
				t.Cleanup(func() {
					// The read returns EOF only if no write end of the FIFO
					// is open.
					var buf [1]byte
					if n, err := unix.Read(rfd, buf[:]); n != 0 || err != nil {
						t.Errorf("unix.Read() from the FIFO = (%d, %v), want (0, nil)", n, err)
					}
					_ = unix.Close(rfd)
				})
			},
			wantErr: errNotRegularFile,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file")
			tc.setup(t, dir, path)

			f, err := OpenAndTruncateRegularFile(path, 0644)
			if err == nil {
				_ = f.Close()
				t.Fatalf("OpenAndTruncateRegularFile(%q) succeeded, want %v", path, tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("OpenAndTruncateRegularFile(%q) = %v, want %v", path, err, tc.wantErr)
			}
			var pathErr *os.PathError
			if !errors.As(err, &pathErr) || pathErr.Path != path {
				t.Errorf("OpenAndTruncateRegularFile(%q) = %#v, want an *os.PathError for this path", path, err)
			}
			if tc.hasOther {
				other := filepath.Join(dir, "other")
				got, err := os.ReadFile(other)
				if err != nil || string(got) != otherContent {
					t.Errorf("os.ReadFile(%q) = (%q, %v), want (%q, nil)", other, got, err, otherContent)
				}
			}
		})
	}
}
