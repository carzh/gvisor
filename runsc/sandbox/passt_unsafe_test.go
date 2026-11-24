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
	"unsafe"

	"golang.org/x/sys/unix"
)

// getPdeathsig returns the parent-death signal of the calling thread. The
// kernel keeps this signal per thread, and exec.Cmd sets it on the main thread
// of a child. A child calls getPdeathsig from TestMain, which runs on the main
// thread: the init function in network_test.go locks the main goroutine to it.
func getPdeathsig() (int32, error) {
	var sig int32
	if err := unix.Prctl(unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&sig)), 0, 0, 0); err != nil {
		return 0, err
	}
	return sig, nil
}
