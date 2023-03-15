// Copyright 2019 Jigsaw Operations LLC
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

package net

import "net"

// PacketEndpoint represents an endpoint that can be used to established packet connections (like UDP)
type PacketEndpoint interface {
	// Connect creates a connection bound to an endpoint, returning the connection.
	Connect() (net.Conn, error)
}

// PacketListener provides a way to create a local unbound packet connection to send packets to different destinations.
type PacketListener interface {
	// ListenPacket created a PacketConn that can be used to relays UDP packets though a Shadowsocks proxy.
	ListenPacket() (net.PacketConn, error)
}
