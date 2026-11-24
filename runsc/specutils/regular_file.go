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
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
)

var (
	errNotRegularFile = errors.New("not a regular file")
	errMultipleLinks  = errors.New("file has more than one hard link")
)

// OpenAndTruncateRegularFile opens the regular file at path for writing and
// truncates it to zero length. If the file does not exist, it creates the
// file with mode perm (before umask).
//
// It returns an error if the last component of path is a symbolic link. It
// also returns an error if fstat(2) on the open file descriptor reports a
// file type other than regular file, or a link count greater than one. It
// follows symbolic links in the other components of path. It does not block
// if path is a FIFO.
//
// It calls fstat(2) once, and then truncates the file with ftruncate(2). Each
// error that it returns is an *os.PathError.
func OpenAndTruncateRegularFile(path string, perm os.FileMode) (*os.File, error) {
	// O_NONBLOCK makes open(2) return immediately if path is a FIFO.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK, perm)
	if err != nil {
		return nil, err
	}
	cu := cleanup.Make(func() { _ = f.Close() })
	defer cu.Clean()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("%w (mode %v)", errNotRegularFile, fi.Mode())}
	}
	if nlink := fi.Sys().(*syscall.Stat_t).Nlink; nlink > 1 {
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("%w (%d links)", errMultipleLinks, nlink)}
	}
	// O_NONBLOCK was only for open(2). Clear it so that the file description
	// is in the default blocking mode.
	if err := unix.SetNonblock(int(f.Fd()), false); err != nil {
		return nil, &os.PathError{Op: "fcntl", Path: path, Err: err}
	}
	if err := f.Truncate(0); err != nil {
		return nil, err
	}
	cu.Release()
	return f, nil
}
