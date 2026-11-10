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

// Package passt_test tests rootless sandbox networking with passt and
// netgofer end to end. The tests run the real runsc and passt binaries as a
// non-root user.
//
// The tests skip if they run as root, if passt is not found ($PASST_BINARY,
// or "passt" in $PATH), if unprivileged user namespaces are not available, or
// if the host cannot connect to the external test address ($PASST_E2E_TARGET,
// default 8.8.8.8:53).
package passt_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// workloadEnv makes the test binary run as the in-sandbox workload (see
	// init).
	workloadEnv = "PASST_E2E_WORKLOAD"

	// defaultTarget is the external address that the sandbox must reach.
	defaultTarget = "8.8.8.8:53"

	// dialTimeout bounds each connection attempt in the workload.
	dialTimeout = 5 * time.Second

	// commandTimeout bounds each runsc command.
	commandTimeout = 2 * time.Minute

	// doneLine is the last line that the workload prints.
	doneLine = "workload done"

	// passtMAC is the passt MAC address that runsc passes to passt. The tests
	// use it to find passt processes started by runsc.
	passtMAC = "02:02:02:02:02:03"
)

// init runs the workload when the test binary is started in the sandbox. Each
// argument is "name=host:port". The workload connects to all addresses over
// TCP at the same time, and prints "name: ok" or "name: fail: <error>" for
// each.
func init() {
	if os.Getenv(workloadEnv) == "" {
		return
	}
	args := os.Args[1:]
	results := make([]string, len(args))
	var wg sync.WaitGroup
	for i, arg := range args {
		name, addr, _ := strings.Cut(arg, "=")
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, dialTimeout)
			if err != nil {
				results[i] = fmt.Sprintf("%s: fail: %v", name, err)
				return
			}
			_ = conn.Close()
			results[i] = fmt.Sprintf("%s: ok", name)
		}()
	}
	wg.Wait()
	for _, r := range results {
		fmt.Println(r)
	}
	fmt.Println(doneLine)
	os.Exit(0)
}

// env holds what the tests need.
type env struct {
	runsc string
	passt string
	// target is the external address that the sandbox must reach.
	target string
	// listener accepts connections on all host addresses. The sandbox must not
	// reach it.
	listener *countingListener
	// hostIP is a non-loopback IPv4 address of the host, or nil.
	hostIP net.IP
}

// countingListener counts accepted connections.
type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) serve() {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		l.accepted.Add(1)
		_ = c.Close()
	}
}

// setup checks the requirements and skips the test if one is missing.
func setup(t *testing.T) *env {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("these tests check rootless mode and must run as a non-root user")
	}
	passt := os.Getenv("PASST_BINARY")
	if passt == "" {
		var err error
		if passt, err = exec.LookPath("passt"); err != nil {
			t.Skipf("passt not found ($PASST_BINARY or $PATH): %v", err)
		}
	}
	if !filepath.IsAbs(passt) {
		abs, err := filepath.Abs(passt)
		if err != nil {
			t.Fatalf("filepath.Abs(%q) failed: %v", passt, err)
		}
		passt = abs
	}
	userns := exec.Command("/bin/true")
	userns.SysProcAttr = &unix.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := userns.Run(); err != nil {
		t.Skipf("unprivileged user namespaces are not available: %v", err)
	}
	target := os.Getenv("PASST_E2E_TARGET")
	if target == "" {
		target = defaultTarget
	}
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		t.Skipf("the host cannot connect to %s: %v", target, err)
	}
	_ = conn.Close()

	runsc, err := testutil.FindRunsc()
	if err != nil {
		t.Fatalf("testutil.FindRunsc() failed: %v", err)
	}

	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	l := &countingListener{Listener: ln}
	go l.serve()
	t.Cleanup(func() { _ = ln.Close() })

	return &env{
		runsc:    runsc,
		passt:    passt,
		target:   target,
		listener: l,
		hostIP:   hostIPv4(),
	}
}

// hostIPv4 returns a non-loopback IPv4 address of the host, or nil.
func hostIPv4() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.To4()
		}
	}
	return nil
}

// targets returns the workload arguments: one allowed external address, and
// the addresses that the sandbox must not reach.
func (e *env) targets() []string {
	port := e.listener.Addr().(*net.TCPAddr).Port
	args := []string{
		"external=" + e.target,
		// passt runs with --no-map-gw, so the gateway is not host loopback.
		fmt.Sprintf("hostloopback=10.0.2.2:%d", port),
		// The egress filter blocks link-local addresses.
		"metadata=169.254.169.254:80",
	}
	if e.hostIP != nil {
		// The egress filter blocks the host's own addresses.
		args = append(args, fmt.Sprintf("hostip=%s", net.JoinHostPort(e.hostIP.String(), fmt.Sprint(port))))
	}
	return args
}

// checkOutput checks the workload output.
func (e *env) checkOutput(t *testing.T, out string) {
	t.Helper()
	results := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	done := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == doneLine {
			done = true
			continue
		}
		if name, result, ok := strings.Cut(line, ": "); ok {
			results[name] = result
		}
	}
	if !done {
		t.Fatalf("workload did not finish; output:\n%s", out)
	}
	if got := results["external"]; got != "ok" {
		t.Errorf("connection to %s from the sandbox: %q, want ok", e.target, got)
	}
	for _, name := range []string{"hostloopback", "metadata", "hostip"} {
		got, ok := results[name]
		if !ok {
			continue
		}
		if !strings.HasPrefix(got, "fail") {
			t.Errorf("connection %q from the sandbox: %q, want fail", name, got)
		}
	}
	if n := e.listener.accepted.Load(); n != 0 {
		t.Errorf("host listener accepted %d connections from the sandbox, want 0", n)
	}
}

// runscFlags returns the global runsc flags.
func (e *env) runscFlags(t *testing.T, rootDir string, extra ...string) []string {
	// A trailing "/" makes --debug-log a directory for per-command logs.
	logDir := t.TempDir() + "/"
	if dir, ok := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR"); ok {
		logDir = filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "_")) + "/"
	}
	flags := []string{
		"--root=" + rootDir,
		"--network=sandbox",
		"--passt-binary=" + e.passt,
		"--debug",
		"--debug-log=" + logDir,
	}
	return append(flags, extra...)
}

// runscCmd returns a runsc command.
func (e *env) runscCmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, e.runsc, args...)
	cmd.WaitDelay = 10 * time.Second
	return cmd
}

// workloadPath returns the absolute path of the test binary, which is also
// the workload. os.Args[0] can be relative, and the sandbox starts the
// workload in a different working directory.
func workloadPath(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() failed: %v", err)
	}
	return path
}

// workloadSpec returns a spec that runs the workload. If userns is true, the
// spec has a user namespace that maps root to the current user, for implicit
// rootless mode.
func (e *env) workloadSpec(t *testing.T, userns bool) *specs.Spec {
	t.Helper()
	spec := testutil.NewSpecWithArgs(append([]string{workloadPath(t)}, e.targets()...)...)
	spec.Process.Env = append(spec.Process.Env, workloadEnv+"=1")
	if userns {
		spec.Linux = &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.NetworkNamespace},
				{Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace},
				{Type: specs.MountNamespace},
				{Type: specs.UserNamespace},
			},
			UIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: uint32(os.Getuid()), Size: 1}},
			GIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: uint32(os.Getgid()), Size: 1}},
		}
	}
	return spec
}

// setupBundle writes spec to a new bundle and creates a root dir.
func setupBundle(t *testing.T, spec *specs.Spec) (bundleDir, rootDir string) {
	t.Helper()
	bundleDir, cleanupBundle, err := testutil.SetupBundleDir(spec)
	if err != nil {
		t.Fatalf("SetupBundleDir() failed: %v", err)
	}
	t.Cleanup(cleanupBundle)
	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("SetupRootDir() failed: %v", err)
	}
	t.Cleanup(cleanupRoot)
	return bundleDir, rootDir
}

// countProcesses returns the number of passt processes started by runsc, and
// the number of netgofer processes for the container id.
func countProcesses(id string) (passt, netgofer int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0
	}
	for _, e := range entries {
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || len(cmdline) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		switch {
		case filepath.Base(args[0]) == "passt" && strings.Contains(string(cmdline), passtMAC):
			passt++
		case args[0] == "runsc-netgofer" && args[len(args)-1] == id:
			netgofer++
		}
	}
	return passt, netgofer
}

// checkProcessesExit checks that passt and netgofer processes for id exit.
// passtBefore is the number of passt processes before the test.
func checkProcessesExit(t *testing.T, id string, passtBefore int) {
	t.Helper()
	var passt, netgofer int
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		passt, netgofer = countProcesses(id)
		if passt <= passtBefore && netgofer == 0 {
			return
		}
	}
	t.Errorf("after the container stopped: %d passt processes (%d before), %d netgofer processes; want them to exit", passt, passtBefore, netgofer)
}

// TestImplicitRootlessRun runs "runsc run" as a non-root user without
// --rootless, with a user namespace in the spec.
func TestImplicitRootlessRun(t *testing.T) {
	e := setup(t)
	bundleDir, rootDir := setupBundle(t, e.workloadSpec(t, true /* userns */))
	id := testutil.RandomContainerID()
	passtBefore, _ := countProcesses(id)

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	args := append(e.runscFlags(t, rootDir, "--ignore-cgroups"), "run", "--bundle="+bundleDir, id)
	out, err := e.runscCmd(ctx, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("runsc run failed: %v; output:\n%s", err, out)
	}
	e.checkOutput(t, string(out))
	checkProcessesExit(t, id, passtBefore)
}

// TestImplicitRootlessCreateStart runs the OCI create, start, and delete
// commands as a non-root user. passt and netgofer start in "runsc start" and
// must keep running after it exits.
func TestImplicitRootlessCreateStart(t *testing.T) {
	e := setup(t)
	bundleDir, rootDir := setupBundle(t, e.workloadSpec(t, true /* userns */))
	id := testutil.RandomContainerID()
	passtBefore, _ := countProcesses(id)
	flags := e.runscFlags(t, rootDir, "--ignore-cgroups")

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// The container writes to the stdout of "runsc create". Use files, not
	// pipes: the sandbox processes keep them open after "runsc create" exits.
	outDir := t.TempDir()
	stdout, err := os.Create(filepath.Join(outDir, "stdout"))
	if err != nil {
		t.Fatalf("os.Create() failed: %v", err)
	}
	defer stdout.Close()
	stderr, err := os.Create(filepath.Join(outDir, "stderr"))
	if err != nil {
		t.Fatalf("os.Create() failed: %v", err)
	}
	defer stderr.Close()
	create := e.runscCmd(ctx, append(flags, "create", "--bundle="+bundleDir, id)...)
	create.Stdout = stdout
	create.Stderr = stderr
	if err := create.Run(); err != nil {
		errOut, _ := os.ReadFile(stderr.Name())
		t.Fatalf("runsc create failed: %v; stderr:\n%s", err, errOut)
	}
	t.Cleanup(func() {
		_ = e.runscCmd(context.Background(), append(flags, "delete", "--force", id)...).Run()
	})
	if passt, _ := countProcesses(id); passt != passtBefore {
		t.Errorf("after runsc create: %d passt processes, want %d (passt starts in runsc start)", passt, passtBefore)
	}

	if out, err := e.runscCmd(ctx, append(flags, "start", id)...).CombinedOutput(); err != nil {
		t.Fatalf("runsc start failed: %v; output:\n%s", err, out)
	}

	// "runsc wait" cannot be used: the sandbox exits with the container and
	// keeps no exit status. Wait for the workload output instead.
	var out []byte
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		out, err = os.ReadFile(stdout.Name())
		if err != nil {
			t.Fatalf("os.ReadFile() failed: %v", err)
		}
		if bytes.Contains(out, []byte(doneLine)) {
			break
		}
	}
	e.checkOutput(t, string(out))

	if out, err := e.runscCmd(ctx, append(flags, "delete", id)...).CombinedOutput(); err != nil {
		t.Errorf("runsc delete failed: %v; output:\n%s", err, out)
	}
	checkProcessesExit(t, id, passtBefore)
}

// TestRootlessRun runs "runsc --rootless run".
func TestRootlessRun(t *testing.T) {
	e := setup(t)
	bundleDir, rootDir := setupBundle(t, e.workloadSpec(t, false /* userns */))
	id := testutil.RandomContainerID()
	passtBefore, _ := countProcesses(id)

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	args := append(e.runscFlags(t, rootDir, "--rootless"), "run", "--bundle="+bundleDir, id)
	out, err := e.runscCmd(ctx, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("runsc --rootless run failed: %v; output:\n%s", err, out)
	}
	e.checkOutput(t, string(out))
	checkProcessesExit(t, id, passtBefore)
}

// TestRootlessDo runs "runsc --rootless do".
func TestRootlessDo(t *testing.T) {
	e := setup(t)
	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("SetupRootDir() failed: %v", err)
	}
	t.Cleanup(cleanupRoot)

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	args := append(e.runscFlags(t, rootDir, "--rootless"), "do")
	args = append(args, workloadPath(t))
	args = append(args, e.targets()...)
	cmd := e.runscCmd(ctx, args...)
	// "runsc do" gives the sandbox the environment of runsc.
	cmd.Env = append(os.Environ(), workloadEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runsc --rootless do failed: %v; output:\n%s", err, out)
	}
	e.checkOutput(t, string(out))
}

// TestRootlessRunPasstFails checks that runsc reports a passt start error.
func TestRootlessRunPasstFails(t *testing.T) {
	e := setup(t)
	bundleDir, rootDir := setupBundle(t, e.workloadSpec(t, false /* userns */))
	id := testutil.RandomContainerID()

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	e.passt = filepath.Join(t.TempDir(), "no-such-passt")
	args := append(e.runscFlags(t, rootDir, "--rootless"), "run", "--bundle="+bundleDir, id)
	out, err := e.runscCmd(ctx, args...).CombinedOutput()
	if err == nil {
		t.Fatalf("runsc --rootless run with a missing passt binary succeeded; output:\n%s", out)
	}
	if !strings.Contains(string(out), "starting passt") {
		t.Errorf("runsc output = %q, want it to report the passt start error", out)
	}
}
