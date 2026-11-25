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
	"fmt"
	"os"
	"path/filepath"
)

// FileOpts contains options for creating a log file.
type FileOpts interface {
	// Build constructs the log file path based on the given pattern.
	Build(logPattern string) string
}

// DefaultFileOpts is the default implementation of FileOpts which supports no
// variable substitution.
type DefaultFileOpts struct{}

// Build implements FileOpts.Build.
func (f *DefaultFileOpts) Build(logPattern string) string {
	return logPattern
}

// OpenFile opens a log file using the specified flags. It uses `opts` to
// construct the log file path based on the given `logPattern`.
func OpenFile(logPattern string, flags int, opts FileOpts) (*os.File, error) {
	return PrepareAndOpenFile(logPattern, opts, nil, func(logPath string, perm os.FileMode) (*os.File, error) {
		return os.OpenFile(logPath, flags, perm)
	})
}

// PrepareAndOpenFile constructs the log file path from `logPattern` using
// `opts` (defaulting to DefaultFileOpts if nil), runs `validate` (if non-nil)
// before creating missing parent directories with mode 0755, and opens the
// file using `open` with mode 0644. It returns (nil, nil) if `logPattern` is
// empty.
func PrepareAndOpenFile(logPattern string, opts FileOpts, validate func(logPath string) error, open func(logPath string, perm os.FileMode) (*os.File, error)) (*os.File, error) {
	if len(logPattern) == 0 {
		return nil, nil
	}
	if opts == nil {
		opts = &DefaultFileOpts{}
	}
	if open == nil {
		return nil, fmt.Errorf("error opening file %q: nil open function", logPattern)
	}

	// Replace variables in the log pattern.
	logPath := opts.Build(logPattern)
	if validate != nil {
		if err := validate(logPath); err != nil {
			return nil, fmt.Errorf("error opening file %q: %w", logPath, err)
		}
	}

	// Create parent directory if it doesn't exist.
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("error creating dir %q: %w", dir, err)
	}

	// Open file with mode 0644.
	f, err := open(logPath, 0644)
	if err != nil {
		return nil, fmt.Errorf("error opening file %q: %w", logPath, err)
	}
	return f, nil
}
