// Copyright 2018 The gVisor Authors.
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/sandboxsetup"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/console"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

var errNoDefaultInterface = errors.New("no default interface found")

// Do implements subcommands.Command for the "do" command. It sets up a simple
// sandbox and executes the command inside it. See Usage() for more details.
type Do struct {
	root    string
	cwd     string
	erofs   string
	ip      string
	quiet   bool
	overlay bool
	uidMap  idMapSlice
	gidMap  idMapSlice
	volumes volumes
	out     io.Writer
	errOut  io.Writer

	// cached values for FetchSpec().
	spec *specs.Spec
	cid  string
}

// Name implements subcommands.Command.Name.
func (*Do) Name() string {
	return "do"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Do) Synopsis() string {
	return "Simplistic way to execute a command inside the sandbox. It's to be used for testing only."
}

// Usage implements subcommands.Command.Usage.
func (*Do) Usage() string {
	return `do [flags] <cmd> - runs a command.

This command starts a sandbox with host filesystem mounted inside as readonly,
with a writable tmpfs overlay on top of it. The given command is executed inside
the sandbox. It's to be used to quickly test applications without having to
install or run docker. It doesn't give nearly as many options and it's to be
used for testing only.
`
}

type idMapSlice []specs.LinuxIDMapping

// String implements flag.Value.String.
func (is *idMapSlice) String() string {
	idMappings := make([]string, 0, len(*is))
	for _, m := range *is {
		idMappings = append(idMappings, fmt.Sprintf("%d %d %d", m.ContainerID, m.HostID, m.Size))
	}
	return strings.Join(idMappings, ",")
}

// Get implements flag.Value.Get.
func (is *idMapSlice) Get() any {
	return is
}

// Set implements flag.Value.Set. Set(String()) should be idempotent.
func (is *idMapSlice) Set(s string) error {
	for _, idMap := range strings.Split(s, ",") {
		fs := strings.Fields(idMap)
		if len(fs) != 3 {
			return fmt.Errorf("invalid mapping: %s", idMap)
		}
		cid, err := strconv.ParseUint(fs[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid container ID in mapping %q: %w", idMap, err)
		}
		hid, err := strconv.ParseUint(fs[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid host ID in mapping %q: %w", idMap, err)
		}
		size, err := strconv.ParseUint(fs[2], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid size in mapping %q: %w", idMap, err)
		}
		m := specs.LinuxIDMapping{
			ContainerID: uint32(cid),
			HostID:      uint32(hid),
			Size:        uint32(size),
		}
		*is = append(*is, m)
	}
	return nil
}

type volumes []string

// Set implements flag.Value.Get.
func (v *volumes) Set(value string) error {
	*v = append(*v, value)
	return nil
}

// Get implements flag.Value.Get.
func (v *volumes) Get() any {
	return v
}

// String implements flag.Value.String.
func (v *volumes) String() string {
	return strings.Join(*v, ",")
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Do) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.root, "root", "/", `path to the root directory, defaults to "/"`)
	f.StringVar(&c.cwd, "cwd", ".", "path to the current directory, defaults to the current directory")
	f.StringVar(&c.erofs, "erofs", "", "path to the erofs root image")
	f.StringVar(&c.ip, "ip", "192.168.10.2", "IPv4 address for the sandbox")
	f.BoolVar(&c.quiet, "quiet", false, "suppress runsc messages. Application output is still sent to stdout and stderr")
	f.BoolVar(&c.overlay, "force-overlay", true, "use an overlay. WARNING: disabling gives the command write access to the host")
	f.Var(&c.uidMap, "uid-map", "Add a user id mapping [ContainerID, HostID, Size]")
	f.Var(&c.gidMap, "gid-map", "Add a group id mapping [ContainerID, HostID, Size]")
	f.Var(&c.volumes, "volume", "Add a volume path SRC[:DST]. This option can be used multiple times to add several volumes.")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (c *Do) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	if c.spec != nil {
		return c.cid, c.spec, nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", nil, fmt.Errorf("error to retrieve hostname: %v", err)
	}

	// If c.overlay is set, then enable overlay.
	conf.Overlay = false // conf.Overlay is deprecated.
	if c.overlay {
		conf.Overlay2.Set("all:memory")
	} else {
		conf.Overlay2.Set("none")
	}
	absRoot, err := resolvePath(c.root)
	if err != nil {
		return "", nil, fmt.Errorf("error resolving root: %v", err)
	}
	absCwd, err := resolvePath(c.cwd)
	if err != nil {
		return "", nil, fmt.Errorf("error resolving current directory: %v", err)
	}

	c.cid = fmt.Sprintf("runsc-%06d", rand.Int31n(1000000))
	c.spec = &specs.Spec{
		Root: &specs.Root{
			Path: absRoot,
		},
		Process: &specs.Process{
			Cwd:          absCwd,
			Args:         f.Args(),
			Env:          os.Environ(),
			Capabilities: specutils.AllCapabilities(),
			Terminal:     console.StdioIsPty(),
		},
		Hostname: hostname,
	}
	if c.erofs != "" {
		c.spec.Annotations = map[string]string{
			"dev.gvisor.spec.rootfs.source":  c.erofs,
			"dev.gvisor.spec.rootfs.type":    "erofs",
			"dev.gvisor.spec.rootfs.overlay": "memory",
		}
	}
	for _, v := range c.volumes {
		parts := strings.SplitN(v, ":", 2)
		var src, dst string
		if len(parts) == 2 {
			src, dst = parts[0], parts[1]
		} else {
			src, dst = v, v
		}
		c.spec.Mounts = append(c.spec.Mounts, specs.Mount{
			Type:        "bind",
			Source:      src,
			Destination: dst,
		})
	}
	if c.uidMap != nil || c.gidMap != nil {
		addNamespace(c.spec, specs.LinuxNamespace{Type: specs.UserNamespace})
		c.spec.Linux.UIDMappings = c.uidMap
		c.spec.Linux.GIDMappings = c.gidMap
	}

	return c.cid, c.spec, nil
}

// Execute implements subcommands.Command.Execute.
func (c *Do) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if len(f.Args()) == 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	if conf.Rootless {
		if err := specutils.MaybeRunAsRoot(); err != nil {
			return util.Errorf("Error executing inside namespace: %v", err)
		}
		// Execution will continue here if no more capabilities are needed...
	}

	cid, spec, err := c.FetchSpec(conf, f)
	if err != nil {
		return util.Errorf("FetchSpec failed: %v", err)
	}

	if conf.Network == config.NetworkNone {
		addNamespace(spec, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	} else if conf.Rootless {
		clean, err := c.setupRootlessNet(conf, 0, spec, readHostResolvConf)
		if err != nil {
			return util.Errorf("Error setting up rootless network: %v", err)
		}
		defer clean()
	} else {
		switch clean, err := c.setupNet(cid, spec); err {
		case errNoDefaultInterface:
			log.Warningf("Network interface not found, using internal network")
			addNamespace(spec, specs.LinuxNamespace{Type: specs.NetworkNamespace})
			conf.Network = config.NetworkHost

		case nil:
			// Setup successful.
			defer clean()

		default:
			return util.Errorf("Error setting up network: %v", err)
		}
	}

	return startContainerAndWait(spec, conf, cid, waitStatus)
}

func addNamespace(spec *specs.Spec, ns specs.LinuxNamespace) {
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	spec.Linux.Namespaces = append(spec.Linux.Namespaces, ns)
}

const maxResolvConfBytes = 64 << 10

var passtSandboxIPv4 = [4]byte{10, 0, 2, 15}

// readHostResolvConf reads up to maxResolvConfBytes from /etc/resolv.conf if it
// is a regular file, returning "" on error.
func readHostResolvConf() string {
	f, err := os.OpenFile("/etc/resolv.conf", os.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(f, maxResolvConfBytes))
	if err != nil {
		return ""
	}
	return string(b)
}

func hasResolvConfMount(spec *specs.Spec) bool {
	for _, m := range spec.Mounts {
		clean := filepath.Clean(m.Destination)
		if clean == "/etc" || clean == "/etc/resolv.conf" || strings.HasPrefix(clean, "/etc/resolv.conf/") {
			return true
		}
	}
	return false
}

// setupRootlessNet configures rootless sandbox networking on conf and spec. It
// returns a cleanup function that removes any temporary files mounted into
// spec.
func (c *Do) setupRootlessNet(conf *config.Config, euid int, spec *specs.Spec, readResolvConf func() string) (func(), error) {
	if conf.Network != config.NetworkSandbox {
		return func() {}, nil
	}
	if passtBin := conf.ResolvePasstBinary(euid); passtBin != "" {
		c.notifyInfo("*** Using passt (%s) for rootless sandbox networking ***", passtBin)
		// passt and netgofer give the sandbox its network. The sandbox
		// gets a new, empty network namespace.
		addNamespace(spec, specs.LinuxNamespace{Type: specs.NetworkNamespace})
		if hasResolvConfMount(spec) {
			return func() {}, nil
		}
		if c.erofs != "" {
			// The image cannot get a new mount point if its /etc/resolv.conf
			// is a dangling symlink, so keep the image file.
			log.Infof("Skipping /etc/resolv.conf mount in passt mode: --erofs images keep their own /etc/resolv.conf")
			return func() {}, nil
		}
		if spec.Root != nil && spec.Root.Path != "" {
			resolved, err := sandboxsetup.ResolveSymlinks(spec.Root.Path, "/etc/resolv.conf")
			if err != nil {
				log.Warningf("Skipping /etc/resolv.conf mount in passt mode: resolving /etc/resolv.conf in %q: %v", spec.Root.Path, err)
				return func() {}, nil
			}
			if fi, err := os.Lstat(resolved); err != nil || !fi.Mode().IsRegular() {
				log.Warningf("Skipping /etc/resolv.conf mount in passt mode: %q is not an existing regular file (%v)", resolved, err)
				return func() {}, nil
			}
		}
		var hostResolvConf string
		if readResolvConf != nil {
			hostResolvConf = readResolvConf()
		}
		return mountPrivateReadonlyFile("/etc/resolv.conf", passtResolvConf(hostResolvConf, readHostIPv4Addrs), spec)
	}
	if conf.UseNetworkProxy() || conf.XDP.Mode != config.XDPModeOff {
		c.notifyUser("*** Warning: sandbox network with --rootless requires passt and is incompatible with --netgofer, --network-proxy-path, and XDP, switching to host ***")
	} else {
		c.notifyUser("*** Warning: sandbox network with --rootless requires passt (https://passt.top) at %s or --passt-binary, switching to host ***", config.DefaultPasstBinary)
	}
	conf.Network = config.NetworkHost
	return func() {}, nil
}

func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b < 0x20 && b != '\t') || b == 0x7f {
			return true
		}
	}
	return false
}

// readHostIPv4Addrs returns the IPv4 addresses of the host network
// interfaces, or nil on error.
func readHostIPv4Addrs() map[[4]byte]struct{} {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Warningf("Failed to read host interface addresses for resolv.conf filtering: %v", err)
		return nil
	}
	m := make(map[[4]byte]struct{}, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			m[[4]byte(ip4)] = struct{}{}
		}
	}
	return m
}

// passtNameserverCandidate reports whether ip4 can be a sandbox nameserver in
// passt mode. The netgofer egress filter drops traffic to the addresses that
// it rejects. Host interface addresses are checked separately.
func passtNameserverCandidate(ip4 [4]byte) bool {
	if ip4 == passtSandboxIPv4 || ip4[0] == 0 || ip4 == [4]byte{255, 255, 255, 255} {
		return false
	}
	addr := netip.AddrFrom4(ip4)
	return !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsMulticast()
}

// passtResolvConf builds /etc/resolv.conf contents for passt mode from
// hostResolvConf. It keeps IPv4 nameservers that the netgofer egress filter
// allows (plus search, domain, and options lines), or falls back to 8.8.8.8
// without host search or domain suffixes when no nameserver remains.
// readHostAddrs returns the host interface addresses, which the egress filter
// blocks. passtResolvConf calls it at most once, and only for a candidate
// nameserver.
func passtResolvConf(hostResolvConf string, readHostAddrs func() map[[4]byte]struct{}) string {
	var (
		hostAddrs     map[[4]byte]struct{}
		hostAddrsRead bool
	)
	var nameservers []string
	var searchLines []string
	var optionLines []string
	for line := range strings.SplitSeq(hostResolvConf, "\n") {
		line = strings.TrimRight(line, "\r")
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = line[:idx]
		}
		if hasControlChars(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		sep := strings.IndexAny(trimmed, " \t")
		if sep < 0 {
			continue
		}
		directive := trimmed[:sep]
		rest := strings.TrimSpace(trimmed[sep+1:])
		if rest == "" {
			continue
		}
		switch directive {
		case "nameserver":
			token := rest
			if end := strings.IndexAny(rest, " \t"); end >= 0 {
				token = rest[:end]
			}
			addr, err := netip.ParseAddr(token)
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			if !addr.Is4() {
				continue
			}
			ip4 := addr.As4()
			if !passtNameserverCandidate(ip4) {
				continue
			}
			if !hostAddrsRead {
				hostAddrsRead = true
				if readHostAddrs != nil {
					hostAddrs = readHostAddrs()
				}
			}
			if _, ok := hostAddrs[ip4]; ok {
				continue
			}
			if nameservers == nil {
				nameservers = make([]string, 0, 3)
			}
			nameservers = append(nameservers, "nameserver "+addr.String())
		case "search", "domain":
			searchLines = append(searchLines, directive+" "+strings.Join(strings.Fields(rest), " "))
		case "options":
			optionLines = append(optionLines, "options "+strings.Join(strings.Fields(rest), " "))
		}
	}
	if len(nameservers) == 0 {
		if len(optionLines) == 0 {
			return "nameserver 8.8.8.8\n"
		}
		var b strings.Builder
		b.WriteString("nameserver 8.8.8.8\n")
		for _, opt := range optionLines {
			b.WriteString(opt)
			b.WriteByte('\n')
		}
		return b.String()
	}
	var b strings.Builder
	for _, ns := range nameservers {
		b.WriteString(ns)
		b.WriteByte('\n')
	}
	for _, s := range searchLines {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	for _, opt := range optionLines {
		b.WriteString(opt)
		b.WriteByte('\n')
	}
	return b.String()
}

func (c *Do) notifyInfo(format string, v ...any) {
	if !c.quiet {
		w := c.errOut
		if w == nil {
			w = os.Stderr
		}
		fmt.Fprintf(w, format+"\n", v...)
	}
	log.Infof(format, v...)
}

func (c *Do) notifyUser(format string, v ...any) {
	if !c.quiet {
		w := c.out
		if w == nil {
			w = os.Stdout
		}
		fmt.Fprintf(w, format+"\n", v...)
	}
	log.Warningf(format, v...)
}

func resolvePath(path string) (string, error) {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %v", path, err)
	}
	path = filepath.Clean(path)
	if err := unix.Access(path, 0); err != nil {
		return "", fmt.Errorf("unable to access %q: %v", path, err)
	}
	return path, nil
}

// setupNet setups up the sandbox network, including the creation of a network
// namespace, and iptable rules to redirect the traffic. Returns a cleanup
// function to tear down the network. Returns errNoDefaultInterface when there
// is no network interface available to setup the network.
func (c *Do) setupNet(cid string, spec *specs.Spec) (func(), error) {
	dev, err := defaultDevice()
	if err != nil {
		return nil, errNoDefaultInterface
	}
	mtu, err := deviceMTU(dev)
	if err != nil {
		return nil, err
	}
	peerIP, err := calculatePeerIP(c.ip)
	if err != nil {
		return nil, err
	}
	veth, peer := deviceNames(cid)

	cmds := []string{
		fmt.Sprintf("ip link add %s mtu %v type veth peer name %s", veth, mtu, peer),

		// Setup device outside the namespace.
		fmt.Sprintf("ip addr add %s/24 dev %s", peerIP, peer),
		fmt.Sprintf("ip link set %s up", peer),

		// Setup device inside the namespace.
		fmt.Sprintf("ip netns add %s", cid),
		fmt.Sprintf("ip link set %s netns %s", veth, cid),
		fmt.Sprintf("ip netns exec %s ip addr add %s/24 dev %s", cid, c.ip, veth),
		fmt.Sprintf("ip netns exec %s ip link set %s up", cid, veth),
		fmt.Sprintf("ip netns exec %s ip link set lo up", cid),
		fmt.Sprintf("ip netns exec %s ip route add default via %s", cid, peerIP),

		// Enable network access.
		"sysctl -w net.ipv4.ip_forward=1",
		fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -m comment --comment runsc-%s -j MASQUERADE", c.ip, dev, peer),
		fmt.Sprintf("iptables -A FORWARD -i %s -o %s -j ACCEPT", dev, peer),
		fmt.Sprintf("iptables -A FORWARD -o %s -i %s -j ACCEPT", dev, peer),
	}

	for _, cmd := range cmds {
		log.Debugf("Run %q", cmd)
		args := strings.Split(cmd, " ")
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Run(); err != nil {
			c.cleanupNet(cid, dev, "", "", "")
			return nil, fmt.Errorf("failed to run %q: %v", cmd, err)
		}
	}

	resolvPath, err := makeFile("/etc/resolv.conf", "nameserver 8.8.8.8\n", spec)
	if err != nil {
		c.cleanupNet(cid, dev, "", "", "")
		return nil, err
	}
	hostnamePath, err := makeFile("/etc/hostname", cid+"\n", spec)
	if err != nil {
		c.cleanupNet(cid, dev, resolvPath, "", "")
		return nil, err
	}
	hosts := fmt.Sprintf("127.0.0.1\tlocalhost\n%s\t%s\n", c.ip, cid)
	hostsPath, err := makeFile("/etc/hosts", hosts, spec)
	if err != nil {
		c.cleanupNet(cid, dev, resolvPath, hostnamePath, "")
		return nil, err
	}

	netns := specs.LinuxNamespace{
		Type: specs.NetworkNamespace,
		Path: filepath.Join("/var/run/netns", cid),
	}
	addNamespace(spec, netns)

	return func() { c.cleanupNet(cid, dev, resolvPath, hostnamePath, hostsPath) }, nil
}

// cleanupNet tries to cleanup the network setup in setupNet.
//
// It may be called when setupNet is only partially complete, in which case it
// will cleanup as much as possible, logging warnings for the rest.
//
// Unfortunately none of this can be automatically cleaned up on process exit,
// we must do so explicitly.
func (c *Do) cleanupNet(cid, dev, resolvPath, hostnamePath, hostsPath string) {
	_, peer := deviceNames(cid)

	cmds := []string{
		fmt.Sprintf("ip link delete %s", peer),
		fmt.Sprintf("ip netns delete %s", cid),
		fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -m comment --comment runsc-%s -j MASQUERADE", c.ip, dev, peer),
		fmt.Sprintf("iptables -D FORWARD -i %s -o %s -j ACCEPT", dev, peer),
		fmt.Sprintf("iptables -D FORWARD -o %s -i %s -j ACCEPT", dev, peer),
	}

	for _, cmd := range cmds {
		log.Debugf("Run %q", cmd)
		args := strings.Split(cmd, " ")
		c := exec.Command(args[0], args[1:]...)
		if err := c.Run(); err != nil {
			log.Warningf("Failed to run %q: %v", cmd, err)
		}
	}

	tryRemove(resolvPath)
	tryRemove(hostnamePath)
	tryRemove(hostsPath)
}

func deviceNames(cid string) (string, string) {
	// Device name is limited to 15 letters.
	return "ve-" + cid, "vp-" + cid

}

func defaultDevice() (string, error) {
	out, err := exec.Command("ip", "route", "list", "default").CombinedOutput()
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(out), " ")
	if len(parts) < 5 {
		return "", fmt.Errorf("malformed %q output: %q", "ip route list default", string(out))
	}
	return parts[4], nil
}

func deviceMTU(dev string) (int, error) {
	intf, err := net.InterfaceByName(dev)
	if err != nil {
		return 0, err
	}
	return intf.MTU, nil
}

func mountPrivateReadonlyFile(dest, content string, spec *specs.Spec) (func(), error) {
	tmpDir, err := os.MkdirTemp("", "runsc-do-net-")
	if err != nil {
		return nil, err
	}
	clean := func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Warningf("Failed to remove %q: %v", tmpDir, err)
		}
	}
	src := filepath.Join(tmpDir, filepath.Base(dest))
	f, err := os.OpenFile(src, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		clean()
		return nil, err
	}
	if err := f.Chmod(0644); err != nil {
		_ = f.Close()
		clean()
		return nil, err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		clean()
		return nil, err
	}
	if err := f.Close(); err != nil {
		clean()
		return nil, err
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Source:      src,
		Destination: dest,
		Type:        "bind",
		Options:     []string{"ro", "nosuid", "nodev", "noexec"},
	})
	return clean, nil
}

func makeFile(dest, content string, spec *specs.Spec) (string, error) {
	tmpFile, err := os.CreateTemp("", filepath.Base(dest))
	if err != nil {
		return "", err
	}
	if err := tmpFile.Chmod(0644); err != nil {
		_ = tmpFile.Close()
		tryRemove(tmpFile.Name())
		return "", err
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		_ = tmpFile.Close()
		tryRemove(tmpFile.Name())
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		tryRemove(tmpFile.Name())
		return "", err
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Source:      tmpFile.Name(),
		Destination: dest,
		Type:        "bind",
		Options:     []string{"ro"},
	})
	return tmpFile.Name(), nil
}

func tryRemove(path string) {
	if path == "" {
		return
	}

	if err := os.Remove(path); err != nil {
		log.Warningf("Failed to remove %q: %v", path, err)
	}
}

func calculatePeerIP(ip string) (string, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid IP format %q", ip)
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", fmt.Errorf("invalid IP format %q: %v", ip, err)
	}
	n++
	if n > 255 {
		n = 1
	}
	return fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], n), nil
}

func startContainerAndWait(spec *specs.Spec, conf *config.Config, cid string, waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	specutils.LogSpecDebug(spec, conf.OCISeccomp)

	out, err := json.Marshal(spec)
	if err != nil {
		return util.Errorf("Error to marshal spec: %v", err)
	}
	tmpDir, err := os.MkdirTemp("", "runsc-do")
	if err != nil {
		return util.Errorf("Error to create tmp dir: %v", err)
	}
	defer func() {
		specutils.UnmountNullNetNS(tmpDir)
		os.RemoveAll(tmpDir)
	}()

	log.Infof("Changing configuration RootDir to %q", tmpDir)
	conf.RootDir = tmpDir

	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgPath, out, 0755); err != nil {
		return util.Errorf("Error write spec: %v", err)
	}

	containerArgs := container.Args{
		ID:        cid,
		Spec:      spec,
		BundleDir: tmpDir,
		Attached:  true,
	}

	ct, err := container.New(conf, containerArgs)
	if err != nil {
		return util.Errorf("creating container: %v", err)
	}
	defer ct.Destroy()

	if err := ct.Start(conf); err != nil {
		return util.Errorf("starting container: %v", err)
	}

	// Forward signals to init in the container. Thus if we get SIGINT from
	// ^C, the container gracefully exit, and we can clean up.
	//
	// N.B. There is a still a window before this where a signal may kill
	// this process, skipping cleanup.
	stopForwarding := ct.ForwardSignals(0 /* pid */, spec.Process.Terminal /* fgProcess */)
	defer stopForwarding()

	ws, err := ct.Wait()
	if err != nil {
		return util.Errorf("waiting for container: %v", err)
	}

	*waitStatus = ws
	return subcommands.ExitSuccess
}
