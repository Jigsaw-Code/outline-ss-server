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

package client

import (
	"context"
	"io"
	"net"

	"github.com/Jigsaw-Code/outline-ss-server/transport"
)

// StreamEndpoint represents an endpoint that can be used to established stream connections (like TCP)
type StreamEndpoint interface {
	// Connect establishes a connection with the endpoint, returning the connection.
	Connect(ctx context.Context) (transport.DuplexConn, error)
}

// StreamDialer provides a way to establish stream connections to a destination.
type StreamDialer interface {
	// Dial connects to `raddr`.
	// `raddr` has the form `host:port`, where `host` can be a domain name or IP address.
	Dial(ctx context.Context, raddr string) (transport.DuplexConn, error)
}

// TCPEndpoint is a StreamEndpoint that connects to the given address via TCP
type TCPEndpoint struct {
	// The Dialer used to create the connection on Connect().
	Dialer net.Dialer
	// The remote address to pass to DialTCP.
	RemoteAddr net.TCPAddr
}

func (e TCPEndpoint) Connect(ctx context.Context) (transport.DuplexConn, error) {
	conn, err := e.Dialer.DialContext(ctx, "tcp", e.RemoteAddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// Relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
// Relay allows for half-closed connections: if one side is done writing, it can
// still read all remaining data from its peer.
func Relay(leftConn, rightConn transport.DuplexConn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := copyOneWay(rightConn, leftConn)
		ch <- res{n, err}
	}()

	n, err := copyOneWay(leftConn, rightConn)
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}

func copyOneWay(leftConn, rightConn transport.DuplexConn) (int64, error) {
	n, err := io.Copy(leftConn, rightConn)
	// Send FIN to indicate EOF
	leftConn.CloseWrite()
	// Release reader resources
	rightConn.CloseRead()
	return n, err
}
