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

package log

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type replaceOpts struct {
	id string
}

func (r replaceOpts) Build(logPattern string) string {
	return strings.ReplaceAll(logPattern, "%ID%", r.id)
}

func TestOpenFile(t *testing.T) {
	if f, err := OpenFile("", os.O_WRONLY|os.O_CREATE|os.O_APPEND, &DefaultFileOpts{}); err != nil || f != nil {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("OpenFile(\"\") = (%v, %v), want (nil, nil)", f, err)
	}

	dir := t.TempDir()
	pattern := filepath.Join(dir, "%ID%", "sub", "out.%ID%.log")
	wantPath := filepath.Join(dir, "sb1", "sub", "out.sb1.log")

	f, err := OpenFile(pattern, os.O_WRONLY|os.O_CREATE|os.O_APPEND, replaceOpts{id: "sb1"})
	if err != nil {
		t.Fatalf("OpenFile(%q) failed: %v", pattern, err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		_ = f.Close()
		t.Fatalf("Write() failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) failed: %v", wantPath, err)
	}
	if string(got) != "hello" {
		t.Errorf("file content = %q, want %q", got, "hello")
	}

	missing := filepath.Join(dir, "missing.log")
	if f, err := OpenFile(missing, os.O_RDONLY, nil); !errors.Is(err, os.ErrNotExist) {
		if f != nil {
			_ = f.Close()
		}
		t.Errorf("OpenFile(%q, O_RDONLY, nil) = (%v, %v), want os.ErrNotExist", missing, f, err)
	}
}

func TestPrepareAndOpenFileValidationFailure(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "uncreated")
	pattern := filepath.Join(parent, "%ID%")
	sentinel := errors.New("bad path")

	f, err := PrepareAndOpenFile(pattern, replaceOpts{id: "bad"}, func(logPath string) error {
		if want := filepath.Join(parent, "bad"); logPath != want {
			t.Errorf("validate got %q, want %q", logPath, want)
		}
		return sentinel
	}, func(logPath string, perm os.FileMode) (*os.File, error) {
		t.Fatal("open called after validate error")
		return nil, nil
	})
	if f != nil {
		_ = f.Close()
		t.Errorf("PrepareAndOpenFile() returned non-nil file %v on error", f)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("PrepareAndOpenFile() error = %v, want %v", err, sentinel)
	}
	if _, statErr := os.Stat(parent); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("Stat(%q) = %v, want os.ErrNotExist", parent, statErr)
	}
}
