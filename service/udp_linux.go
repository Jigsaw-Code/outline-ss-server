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
	"net"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
)

// fwmark can be used in conjunction with other Linux networking features like cgroups, network namespaces, and TC (Traffic Control) for sophisticated network management.
// Value of 0 disables fwmark (SO_MARK) (Linux Only)
func MakeTargetPacketListener(fwmark uint) UDPDialer {
	return func() (net.PacketConn, *onet.ConnectionError) {
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to create UDP socket", err)
		}

		if fwmark > 0 {
			rawConn, err := udpConn.SyscallConn()
			if err != nil {
				udpConn.Close()
				return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to get UDP raw connection", err)
			}
			var fwErr error
			err = rawConn.Control(func(fd uintptr) {
				err := SetFwmark(fd, fwmark)
				if err != nil {
					fwErr = err
				}
			})
			if err != nil {
				udpConn.Close()
				return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Set UDPDialer Control func failed.", err)
			}
			if fwErr != nil {
				udpConn.Close()
				return nil, onet.NewConnectionError("ERR_CREATE_SOCKET", "Set fwmark failed.", fwErr)
			}
		}
		return udpConn, nil
	}
}
