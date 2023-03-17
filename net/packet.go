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

import (
	"context"
	"net"
)

// PacketEndpoint represents an endpoint that can be used to established packet connections (like UDP)
type PacketEndpoint interface {
	// Connect creates a connection bound to an endpoint, returning the connection.
	Connect(ctx context.Context) (net.Conn, error)
}

// PacketListener provides a way to create a local unbound packet connection to send packets to different destinations.
type PacketListener interface {
	// ListenPacket creates a PacketConn that can be used to relay packets (such as UDP) through some proxy.
	ListenPacket(ctx context.Context) (net.PacketConn, error)
}

// UDPEndpoint is a PacketEndpoint that connects to the given address via UDP
type UDPEndpoint struct {
	// The Dialer used to create the net.Conn on Connect().
	Dialer net.Dialer
	// The remote address to pass to Dial.
	RemoteAddr net.UDPAddr
}

func (e UDPEndpoint) Connect(ctx context.Context) (net.Conn, error) {
	conn, err := e.Dialer.DialContext(ctx, "udp", e.RemoteAddr.String())
	if err != nil {
		return nil, err
	}
	return conn, nil
}
