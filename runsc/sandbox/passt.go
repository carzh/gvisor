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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
)

// passt mode gives a rootless sandbox network access. runsc starts passt
// (https://passt.top) and netgofer. The sentry sends IP packets to netgofer,
// netgofer sends them to passt as Ethernet frames, and passt opens host
// sockets as the current user. See runsc/gofer/net/passt.go.
//
// The sandbox network configuration is fixed. It uses the same addresses as
// QEMU user networking.

var (
	// passtGuestAddr is the IPv4 address of the sandbox eth0.
	passtGuestAddr = net.IPv4(10, 0, 2, 15).To4()

	// passtGateway is the default gateway of the sandbox. passt answers for
	// it.
	passtGateway = net.IPv4(10, 0, 2, 2).To4()
)

const (
	// passtPrefixLen is the prefix length of the sandbox eth0 subnet.
	passtPrefixLen = 24

	// passtMTU is the MTU of the sandbox eth0.
	passtMTU = defaultMTU

	// passtMAC is the MAC address of passt. It must match PasstMAC in
	// runsc/gofer/net/passt.go, because netgofer uses it as the destination
	// MAC address of the frames it sends to passt.
	passtMAC = "02:02:02:02:02:03"

	// passtStartTimeout bounds how long runsc waits for passt to start.
	passtStartTimeout = 30 * time.Second
)

// passtLinksAndRoutes returns the sandbox network configuration for passt
// mode: a loopback link and an eth0 proxy link backed by udsFile.
func passtLinksAndRoutes(conf *config.Config, udsFile *os.File) sentryapi.CreateLinksAndRoutesArgs {
	lo := sentryapi.DefaultLoopbackLink
	lo.GVisorGRO = conf.GVisorGRO

	mask := net.CIDRMask(passtPrefixLen, net.IPv4len*8)
	eth0 := sentryapi.FDBasedLink{
		Name:                 defaultPrimaryInterfaceName,
		MTU:                  passtMTU,
		Addresses:            []sentryapi.IPWithPrefix{{Address: passtGuestAddr, PrefixLen: passtPrefixLen}},
		Routes:               []sentryapi.Route{{Destination: net.IPNet{IP: passtGuestAddr.Mask(mask), Mask: mask}}},
		TXChecksumOffload:    conf.TXChecksumOffload,
		RXChecksumOffload:    conf.RXChecksumOffload,
		NumChannels:          1,
		ProcessorsPerChannel: conf.NetworkProcessorsPerChannel,
		QDisc:                conf.QDisc,
		TBFRate:              conf.TBFRate,
		TBFBurst:             uint32(conf.TBFBurst),
		GVisorGRO:            conf.GVisorGRO,
	}
	configureProxyLink(&eth0)

	args := sentryapi.CreateLinksAndRoutesArgs{
		LoopbackLinks: []sentryapi.LoopbackLink{lo},
		FDBasedLinks:  []sentryapi.FDBasedLink{eth0},
		Defaultv4Gateway: sentryapi.DefaultRoute{
			Route: sentryapi.Route{
				Destination: net.IPNet{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)},
				Gateway:     passtGateway,
			},
			Name: eth0.Name,
		},
		PauseExternalNetworking: conf.PauseExternalNetworking,
		AllowConnectedOnSave:    conf.AllowConnectedOnSave,
	}
	args.FilePayload.Files = append(args.FilePayload.Files, udsFile)
	return args
}

// createPasstInterfacesAndRoutes creates the passt mode network links in the
// sandbox. It returns the MTU of the eth0 link.
func createPasstInterfacesAndRoutes(conn *urpc.Client, conf *config.Config, isRestore bool, udsFile *os.File) (int, error) {
	if udsFile == nil {
		return 0, fmt.Errorf("passt mode enabled but the sandbox UDS is nil")
	}
	args := passtLinksAndRoutes(conf, udsFile)
	if err := pcapAndNAT(&args, conf); err != nil {
		return 0, err
	}
	args.IsRestore = isRestore
	log.Debugf("Setting up passt network, config: %+v", args)
	if err := conn.Call(sentryapi.ContMgrSetNetworkArgs, &args, nil); err != nil {
		return 0, fmt.Errorf("creating links and routes: %w", err)
	}
	return passtMTU, nil
}

// passtArgs returns the passt command line arguments. fd is the passt end of
// the connected socket to netgofer.
func passtArgs(fd int) []string {
	return []string{
		// passt exits when this socket is closed (--fd implies --one-off).
		"--fd", strconv.Itoa(fd),
		"--ipv4-only",
		"--address", passtGuestAddr.String(),
		"--netmask", strconv.Itoa(passtPrefixLen),
		"--gateway", passtGateway.String(),
		"--mac-addr", passtMAC,
		// Do not map the gateway address to the host loopback address, so
		// that the sandbox cannot connect to services that listen only on
		// host loopback.
		"--no-map-gw",
		"--no-dhcp",
		"--quiet",
	}
}

// startPasst starts passt with one end of a new connected SOCK_STREAM socket
// pair, and returns the other end for netgofer.
//
// Without --foreground, passt forks a daemon after its setup is complete, and
// the first process exits. So this function returns after passt is ready,
// and it returns passt setup errors. runsc does not track the daemon: it
// exits when the socket to netgofer is closed.
func startPasst(conf *config.Config) (*os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("creating passt socket pair: %w", err)
	}
	for _, fd := range fds {
		setUDSBufSizes(fd)
	}
	passtEnd := os.NewFile(uintptr(fds[0]), "passt")
	defer passtEnd.Close()
	netgoferEnd := os.NewFile(uintptr(fds[1]), "passt-netgofer")

	ctx, cancel := context.WithTimeout(context.Background(), passtStartTimeout)
	defer cancel()
	passtBinary := conf.PasstBinaryPath()
	if passtBinary == "" {
		_ = netgoferEnd.Close()
		return nil, fmt.Errorf("passt not found at %q and --passt-binary is not set", config.DefaultPasstBinary)
	}
	cmd := exec.CommandContext(ctx, passtBinary, passtArgs(3)...)
	cmd.ExtraFiles = []*os.File{passtEnd}
	// The passt daemon should not keep the output pipe open. If it does,
	// stop waiting for the pipe after a short delay.
	cmd.WaitDelay = time.Second
	log.Infof("Starting passt: %s %v", cmd.Path, cmd.Args)
	out, err := cmd.CombinedOutput()
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		_ = netgoferEnd.Close()
		return nil, fmt.Errorf("starting passt %q: %w, output: %q", passtBinary, err, out)
	}
	if len(out) > 0 {
		log.Infof("passt output: %s", out)
	}
	log.Infof("passt started")
	return netgoferEnd, nil
}
