// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package service

import (
	"context"
	"net"

	"github.com/Jigsaw-Code/outline-sdk/transport"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
)

type udpListener struct {
	// fwmark can be used in conjunction with other Linux networking features like cgroups, network
	// namespaces, and TC (Traffic Control) for sophisticated network management.
	// Value of 0 disables fwmark (SO_MARK) (Linux only)
	fwmark uint
}

// NewPacketListener creates a new PacketListener that listens on UDP
// and optionally sets a firewall mark on the socket (Linux only).
func MakeTargetUDPListener(fwmark uint) transport.PacketListener {
	return &udpListener{fwmark: fwmark}
}

func (ln *udpListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to create UDP socket", err)
	}

	if ln.fwmark > 0 {
		rawConn, err := conn.SyscallConn()
		if err != nil {
			conn.Close()
			return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to get UDP raw connection", err)
		}
		var fwErr error
		err = rawConn.Control(func(fd uintptr) {
			err := SetFwmark(fd, ln.fwmark)
			if err != nil {
				fwErr = err
			}
		})
		if err != nil {
			conn.Close()
			return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Set UDPDialer Control func failed.", err)
		}
		if fwErr != nil {
			conn.Close()
			return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Set fwmark failed.", fwErr)
		}
	}
	return conn, nil
}
