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
// default 8.8.8.8:53). Setting PASST_E2E_REQUIRED=1 turns these skips into
// test failures.
package passt_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
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

	// holdFileEnv, when set to a file path, keeps the workload running after
	// it prints doneLine until that file is removed.
	holdFileEnv = "PASST_E2E_HOLD_FILE"

	// defaultTarget is the external address that the sandbox must reach.
	defaultTarget = "8.8.8.8:53"

	// dialTimeout bounds each connection attempt in the workload.
	dialTimeout = 5 * time.Second

	// commandTimeout bounds each runsc command.
	commandTimeout = 2 * time.Minute

	// doneLine is the last line that the workload prints.
	doneLine = "workload done"

	// wantPasstMTU is the expected sandbox eth0 MTU in passt mode (matching
	// passtMTU in runsc/sandbox/passt.go).
	wantPasstMTU = 65520

	// largeUDPPayloadSize exceeds the 1472-byte IPv4 UDP payload limit of a
	// 1500-byte MTU link, verifying that Netstack does not fragment the
	// datagram (passt drops IPv4 fragments).
	largeUDPPayloadSize = 3000

	// passtMAC is the --mac-addr value that runsc passes to passt. It must
	// match passtMAC in runsc/sandbox/passt.go.
	passtMAC = "02:02:02:02:02:03"
)

// init runs the workload when the test binary is started in the sandbox. Each
// argument is "name=value". The workload runs all checks concurrently and
// prints "name: ok" or "name: fail: <error>" for each.
func init() {
	if os.Getenv(workloadEnv) == "" {
		return
	}
	args := os.Args[1:]
	results := make([]string, len(args))
	var wg sync.WaitGroup
	for i, arg := range args {
		name, val, _ := strings.Cut(arg, "=")
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = fmt.Sprintf("%s: %s", name, runWorkloadCheck(name, val))
		}()
	}
	wg.Wait()
	for _, r := range results {
		fmt.Println(r)
	}
	fmt.Println(doneLine)
	if holdFile := os.Getenv(holdFileEnv); holdFile != "" {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if _, err := os.Stat(holdFile); os.IsNotExist(err) {
				break
			}
		}
	}
	os.Exit(0)
}

func runWorkloadCheck(name, addr string) string {
	switch name {
	case "tcpdns":
		return tcpDNS(addr)
	case "udpdns":
		return udpDNS(addr)
	case "largeudp":
		return largeUDP(addr)
	case "resolv":
		return checkResolvConf()
	default:
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err != nil {
			return fmt.Sprintf("fail: %v", err)
		}
		_ = conn.Close()
		return "ok"
	}
}

// tcpDNS sends a DNS query for google.com over TCP and reads the reply header,
// verifying that TCP payload bytes flow in both directions.
func tcpDNS(addr string) string {
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return fmt.Sprintf("fail: dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	query := []byte{
		0, 28, 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
	}
	if _, err := conn.Write(query); err != nil {
		return fmt.Sprintf("fail: write: %v", err)
	}
	var replyHdr [4]byte
	if _, err := io.ReadFull(conn, replyHdr[:]); err != nil {
		return fmt.Sprintf("fail: read: %v", err)
	}
	if replyHdr[2] != 0x12 || replyHdr[3] != 0x34 {
		return fmt.Sprintf("fail: unexpected transaction ID %x%x", replyHdr[2], replyHdr[3])
	}
	return "ok"
}

// udpDNS sends a DNS query for google.com over UDP and reads the reply.
func udpDNS(addr string) string {
	conn, err := net.DialTimeout("udp", addr, dialTimeout)
	if err != nil {
		return fmt.Sprintf("fail: dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	query := []byte{
		0x56, 0x78, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
	}
	if _, err := conn.Write(query); err != nil {
		return fmt.Sprintf("fail: write: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Sprintf("fail: read: %v", err)
	}
	if n < 12 || buf[0] != 0x56 || buf[1] != 0x78 {
		return fmt.Sprintf("fail: bad reply (len=%d)", n)
	}
	return "ok"
}

// largeUDP checks that eth0 has the 65520-byte passt MTU and sends a UDP
// datagram larger than 1472 bytes so that it traverses Netstack unfragmented.
func largeUDP(addr string) string {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		return fmt.Sprintf("fail: InterfaceByName(eth0): %v", err)
	}
	if iface.MTU != wantPasstMTU {
		return fmt.Sprintf("fail: eth0 MTU = %d, want %d", iface.MTU, wantPasstMTU)
	}
	conn, err := net.DialTimeout("udp", addr, dialTimeout)
	if err != nil {
		return fmt.Sprintf("fail: dial: %v", err)
	}
	defer conn.Close()
	payload := make([]byte, largeUDPPayloadSize)
	if _, err := conn.Write(payload); err != nil {
		return fmt.Sprintf("fail: write %d bytes: %v", len(payload), err)
	}
	return "ok"
}

// checkResolvConf checks that /etc/resolv.conf has a non-loopback IPv4
// nameserver and that DNS resolution works in "runsc --rootless do".
func checkResolvConf() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Sprintf("fail: read /etc/resolv.conf: %v", err)
	}
	hasValidNS := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ip := net.ParseIP(fields[1])
			if ip == nil || ip.To4() == nil || ip.IsLoopback() {
				return fmt.Sprintf("fail: unreachable nameserver %q in /etc/resolv.conf", fields[1])
			}
			hasValidNS = true
		}
	}
	if !hasValidNS {
		return fmt.Sprintf("fail: no nameserver in /etc/resolv.conf: %q", string(data))
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, "google.com")
	if err != nil || len(addrs) == 0 {
		return fmt.Sprintf("fail: LookupHost(google.com): %v", err)
	}
	return "ok"
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

func skipOrFatal(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("PASST_E2E_REQUIRED") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// setupBase checks only that the test runs as a non-root user with
// unprivileged user namespaces and locates runsc. Tests that do not need an
// installed passt binary or external network access can use it directly.
func setupBase(t *testing.T) *env {
	t.Helper()
	if os.Geteuid() == 0 {
		skipOrFatal(t, "these tests check rootless mode and must run as a non-root user")
	}
	userns := exec.Command("/bin/true")
	userns.SysProcAttr = &unix.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := userns.Run(); err != nil {
		skipOrFatal(t, "unprivileged user namespaces are not available: %v", err)
	}
	runsc, err := testutil.FindRunsc()
	if err != nil {
		t.Fatalf("testutil.FindRunsc() failed: %v", err)
	}
	return &env{runsc: runsc}
}

// setup checks all requirements and skips (or fails when PASST_E2E_REQUIRED=1)
// if one is missing.
func setup(t *testing.T) *env {
	t.Helper()
	e := setupBase(t)
	passt := os.Getenv("PASST_BINARY")
	if passt == "" {
		var err error
		if passt, err = exec.LookPath("passt"); err != nil {
			skipOrFatal(t, "passt not found ($PASST_BINARY or $PATH): %v", err)
		}
	}
	if !filepath.IsAbs(passt) {
		abs, err := filepath.Abs(passt)
		if err != nil {
			t.Fatalf("filepath.Abs(%q) failed: %v", passt, err)
		}
		passt = abs
	}
	target := os.Getenv("PASST_E2E_TARGET")
	if target == "" {
		target = defaultTarget
	}
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		skipOrFatal(t, "the host cannot connect to %s: %v", target, err)
	}
	_ = conn.Close()
	if res := udpDNS(target); res != "ok" {
		skipOrFatal(t, "the host cannot query DNS over UDP at %s: %s", target, res)
	}

	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	l := &countingListener{Listener: ln}
	go l.serve()
	t.Cleanup(func() { _ = ln.Close() })

	e.passt = passt
	e.target = target
	e.listener = l
	e.hostIP = hostIPv4()
	return e
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

// targets returns the workload arguments: allowed external TCP/UDP/large-UDP
// checks, and the addresses that the sandbox must not reach.
func (e *env) targets() []string {
	port := e.listener.Addr().(*net.TCPAddr).Port
	args := []string{
		"external=" + e.target,
		"tcpdns=" + e.target,
		"udpdns=" + e.target,
		"largeudp=" + e.target,
		// passt runs with --no-map-gw, so the gateway is not host loopback.
		fmt.Sprintf("hostloopback=10.0.2.2:%d", port),
		// The egress filter blocks link-local addresses. Outside GCE, this
		// address is also unreachable without the filter; hostip below tests
		// the filter on any host with a non-loopback IPv4 address.
		"metadata=169.254.169.254:80",
	}
	if e.hostIP != nil {
		// The egress filter blocks the host's own addresses.
		args = append(args, fmt.Sprintf("hostip=%s", net.JoinHostPort(e.hostIP.String(), fmt.Sprint(port))))
	}
	return args
}

// checkOutput checks the workload output.
func (e *env) checkOutput(t *testing.T, out string, extraOK ...string) {
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
	wantOK := append([]string{"external", "tcpdns", "udpdns", "largeudp"}, extraOK...)
	for _, name := range wantOK {
		if got := results[name]; got != "ok" {
			t.Errorf("check %q from the sandbox: %q, want ok", name, got)
		}
	}
	wantFail := []string{"hostloopback", "metadata"}
	if e.hostIP != nil {
		wantFail = append(wantFail, "hostip")
	}
	for _, name := range wantFail {
		got, ok := results[name]
		if !ok {
			t.Errorf("missing result for %q; output:\n%s", name, out)
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
	var targetArgs []string
	if e.listener != nil {
		targetArgs = e.targets()
	}
	spec := testutil.NewSpecWithArgs(append([]string{workloadPath(t)}, targetArgs...)...)
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

// procKey returns a unique key ("pid:starttime") for a live non-zombie
// process, or "" if the process is gone or a zombie.
func procKey(pid string) string {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		return ""
	}
	s := string(data)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return pid
	}
	fields := strings.Fields(s[closeParen+2:])
	if len(fields) < 20 {
		return pid
	}
	if fields[0] == "Z" {
		return ""
	}
	// Field 22 of /proc/<pid>/stat (index 19 after the comm field) is
	// starttime.
	return pid + ":" + fields[19]
}

// scanProcesses returns the set of passt processes started by runsc in the
// current PID namespace, and the number of netgofer processes for id.
//
// Note: passt processes do not carry the container ID in their command line,
// so concurrent passt sandboxes in the same PID namespace (for example during
// a manual workstation run) can affect the passt set.
func scanProcesses(id string) (passt map[string]bool, netgofer int) {
	passt = make(map[string]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return passt, 0
	}
	for _, e := range entries {
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || len(cmdline) == 0 {
			continue
		}
		key := procKey(e.Name())
		if key == "" {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		switch {
		case filepath.Base(args[0]) == "passt" && strings.Contains(string(cmdline), passtMAC):
			passt[key] = true
		case id != "" && args[0] == "runsc-netgofer" && args[len(args)-1] == id:
			netgofer++
		}
	}
	return passt, netgofer
}

// newPasstProcesses returns the passt process keys that were not present in
// before.
func newPasstProcesses(before, current map[string]bool) []string {
	var added []string
	for k := range current {
		if !before[k] {
			added = append(added, k)
		}
	}
	return added
}

// checkProcessesExit checks that any passt processes started since passtBefore
// and any netgofer processes for id exit.
func checkProcessesExit(t *testing.T, id string, passtBefore map[string]bool) {
	t.Helper()
	var added []string
	var netgofer int
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		current, ng := scanProcesses(id)
		added = newPasstProcesses(passtBefore, current)
		netgofer = ng
		if len(added) == 0 && netgofer == 0 {
			return
		}
	}
	t.Errorf("after the container stopped: %d new passt processes %v, %d netgofer processes; want them to exit", len(added), added, netgofer)
}

// waitForStopped waits until "runsc state" reports that container id has
// stopped, so that a plain "runsc delete" (without --force) does not race with
// container exit.
func (e *env) waitForStopped(t *testing.T, ctx context.Context, flags []string, id string) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		out, err := e.runscCmd(ctx, append(append([]string{}, flags...), "state", id)...).CombinedOutput()
		if err == nil && bytes.Contains(out, []byte(`"status": "stopped"`)) {
			return
		}
	}
	t.Fatalf("timed out waiting for container %s to reach stopped state", id)
}

// TestImplicitRootlessRun runs "runsc run" as a non-root user without
// --rootless, with a user namespace in the spec.
func TestImplicitRootlessRun(t *testing.T) {
	e := setup(t)
	bundleDir, rootDir := setupBundle(t, e.workloadSpec(t, true /* userns */))
	id := testutil.RandomContainerID()
	passtBefore, _ := scanProcesses(id)

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
// commands as a non-root user. passt and netgofer start in "runsc start",
// must stay alive while the container runs after "runsc start" exits, and must
// exit when the container stops or is force-deleted.
func TestImplicitRootlessCreateStart(t *testing.T) {
	for _, forceDeleteRunning := range []bool{false, true} {
		name := "stop_then_delete"
		if forceDeleteRunning {
			name = "force_delete_running"
		}
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			spec := e.workloadSpec(t, true /* userns */)
			holdFile := filepath.Join(t.TempDir(), "hold")
			if err := os.WriteFile(holdFile, nil, 0644); err != nil {
				t.Fatalf("os.WriteFile(%q) failed: %v", holdFile, err)
			}
			spec.Process.Env = append(spec.Process.Env, holdFileEnv+"="+holdFile)

			bundleDir, rootDir := setupBundle(t, spec)
			id := testutil.RandomContainerID()
			passtBefore, _ := scanProcesses(id)
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
			create := e.runscCmd(ctx, append(append([]string{}, flags...), "create", "--bundle="+bundleDir, id)...)
			create.Stdout = stdout
			create.Stderr = stderr
			if err := create.Run(); err != nil {
				errOut, _ := os.ReadFile(stderr.Name())
				t.Fatalf("runsc create failed: %v; stderr:\n%s", err, errOut)
			}
			t.Cleanup(func() {
				_ = os.Remove(holdFile)
				_ = e.runscCmd(context.Background(), append(append([]string{}, flags...), "delete", "--force", id)...).Run()
			})
			if current, ng := scanProcesses(id); len(newPasstProcesses(passtBefore, current)) != 0 || ng != 0 {
				t.Errorf("after runsc create: new passt=%v, netgofer=%d, want none (they start in runsc start)", newPasstProcesses(passtBefore, current), ng)
			}

			if out, err := e.runscCmd(ctx, append(append([]string{}, flags...), "start", id)...).CombinedOutput(); err != nil {
				t.Fatalf("runsc start failed: %v; output:\n%s", err, out)
			}

			// Wait for the workload to finish its network checks while holdFile
			// keeps the container running.
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

			// Positive control: while the container is still running after
			// "runsc start" has exited, both passt and netgofer must be alive.
			current, ng := scanProcesses(id)
			addedPasst := newPasstProcesses(passtBefore, current)
			if len(addedPasst) != 1 || ng != 1 {
				t.Errorf("while container is running after runsc start: new passt=%v (want 1), netgofer=%d (want 1)", addedPasst, ng)
			}

			if forceDeleteRunning {
				if out, err := e.runscCmd(ctx, append(append([]string{}, flags...), "delete", "--force", id)...).CombinedOutput(); err != nil {
					t.Errorf("runsc delete --force failed: %v; output:\n%s", err, out)
				}
			} else {
				if err := os.Remove(holdFile); err != nil {
					t.Fatalf("os.Remove(%q) failed: %v", holdFile, err)
				}
				e.waitForStopped(t, ctx, flags, id)
				if out, err := e.runscCmd(ctx, append(append([]string{}, flags...), "delete", id)...).CombinedOutput(); err != nil {
					t.Errorf("runsc delete failed: %v; output:\n%s", err, out)
				}
			}
			checkProcessesExit(t, id, passtBefore)
		})
	}
}

// TestRootlessRun runs "runsc --rootless run".
func TestRootlessRun(t *testing.T) {
	e := setup(t)
	bundleDir, rootDir := setupBundle(t, e.workloadSpec(t, false /* userns */))
	id := testutil.RandomContainerID()
	passtBefore, _ := scanProcesses(id)

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

// TestRootlessDo runs "runsc --rootless do" and verifies that the generated
// /etc/resolv.conf allows DNS resolution inside the sandbox.
func TestRootlessDo(t *testing.T) {
	e := setup(t)
	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("SetupRootDir() failed: %v", err)
	}
	t.Cleanup(cleanupRoot)
	passtBefore, _ := scanProcesses("")

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	args := append(e.runscFlags(t, rootDir, "--rootless"), "do")
	args = append(args, workloadPath(t))
	args = append(args, append(e.targets(), "resolv=1")...)
	cmd := e.runscCmd(ctx, args...)
	// "runsc do" gives the sandbox the environment of runsc.
	cmd.Env = append(os.Environ(), workloadEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runsc --rootless do failed: %v; output:\n%s", err, out)
	}
	e.checkOutput(t, string(out), "resolv")
	checkProcessesExit(t, "", passtBefore)
}

// TestRootlessRunPasstFails checks that runsc reports a passt start error and
// leaves no netgofer process behind.
func TestRootlessRunPasstFails(t *testing.T) {
	e := setupBase(t)
	bundleDir, rootDir := setupBundle(t, e.workloadSpec(t, false /* userns */))
	id := testutil.RandomContainerID()
	passtBefore, _ := scanProcesses(id)

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
	checkProcessesExit(t, id, passtBefore)
}
