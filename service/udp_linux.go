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
	"log/slog"
	"net"
	"os"
	"syscall"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
)

// fwmark can be used in conjunction with other Linux networking features like cgroups, network namespaces, and TC (Traffic Control) for sophisticated network management.
// Value of 0 disables fwmark (SO_MARK) (Linux Only)
func MakeTargetPacketListener(fwmark uint) UDPDialer {
	return func() (net.PacketConn, *onet.ConnectionError) {
		udpConn, err := net.ListenPacket("udp", "")
		if err != nil {
			return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to create UDP socket", err)
		}

		if fwmark > 0 {
			rawConn, err := udpConn.(*net.UDPConn).SyscallConn()
			if err != nil {
				udpConn.Close()
				return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to get UDP raw connection", err)
			}
			err = rawConn.Control(func(fd uintptr) {
				err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(fwmark))
				if err != nil {
					slog.Error("Set fwmark failed.", "err", os.NewSyscallError("failed to set fwmark for UDP socket", err))
				}
			})
			if err != nil {
				udpConn.Close()
				return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Set UDPDialer Control func failed.", err)
			}
		}
		return udpConn, nil
	}
}
