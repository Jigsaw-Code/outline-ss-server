// Copyright 2023 Jigsaw Operations LLC
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
	"errors"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type StreamDialer interface {
	onet.StreamDialer

	// SetTCPSaltGenerator controls the SaltGenerator used for TCP upstream.
	// `salter` may be `nil`.
	// This method is not thread-safe.
	SetTCPSaltGenerator(shadowsocks.SaltGenerator)
}

// NewShadowsocksStreamDialer creates a client that routes connections to a Shadowsocks proxy listening at
// the given StreamEndpoint, with `cipher` as the Shadowsocks crypto.
func NewShadowsocksStreamDialer(endpoint onet.StreamEndpoint, cipher *shadowsocks.Cipher) (StreamDialer, error) {
	if endpoint == nil {
		return nil, errors.New("Argument endpoint must not be nil")
	}
	if cipher == nil {
		return nil, errors.New("Argument cipher must not be nil")
	}
	d := streamDialer{endpoint: endpoint, cipher: cipher}
	return &d, nil
}

type streamDialer struct {
	endpoint onet.StreamEndpoint
	cipher   *shadowsocks.Cipher
	salter   shadowsocks.SaltGenerator
}

func (c *streamDialer) SetTCPSaltGenerator(salter shadowsocks.SaltGenerator) {
	c.salter = salter
}

// This code contains an optimization to send the initial client payload along with
// the Shadowsocks handshake.  This saves one packet during connection, and also
// reduces the distinctiveness of the connection pattern.
//
// Normally, the initial payload will be sent as soon as the socket is connected,
// except for delays due to inter-process communication.  However, some protocols
// expect the server to send data first, in which case there is no client payload.
// We therefore use a short delay, longer than any reasonable IPC but shorter than
// typical network latency.  (In an Android emulator, the 90th percentile delay
// was ~1 ms.)  If no client payload is received by this time, we connect without it.
const helloWait = 10 * time.Millisecond

// Dial implements StreamDialer.Dial via a Shadowsocks server.
//
// The Shadowsocks StreamDialer returns a connection after the connection to the proxy is established,
// but before the connection to the target is established. That means we cannot signal "connection refused"
// or "connection timeout" errors from the target to the application.
//
// This behavior breaks IPv6 Happy Eyeballs because the application IPv6 socket will connect successfully,
// even if the proxy fails to connect to the IPv6 destination. The broken Happy Eyeballs behavior makes
// IPv6 unusable if the proxy cannot use IPv6.
//
// We can't easily fix that issue because Shadowsocks, unlike SOCKS, does not have a way to indicate
// whether the target connection is successful. Even if that was possible, we want to wait until we have
// initial data from the application in order to send the Shadowsocks salt, SOCKS address and initial data
// all in one packet. This makes the size of the initial packet hard to predict, avoiding packet size
// fingerprinting. We can only get the application initial data if we return a connection first.
func (c *streamDialer) Dial(ctx context.Context, remoteAddr string) (onet.DuplexConn, error) {
	socksTargetAddr := socks.ParseAddr(remoteAddr)
	if socksTargetAddr == nil {
		return nil, errors.New("Failed to parse target address")
	}
	proxyConn, err := c.endpoint.Connect(ctx)
	if err != nil {
		return nil, err
	}
	ssw := shadowsocks.NewShadowsocksWriter(proxyConn, c.cipher)
	if c.salter != nil {
		ssw.SetSaltGenerator(c.salter)
	}
	_, err = ssw.LazyWrite(socksTargetAddr)
	if err != nil {
		proxyConn.Close()
		return nil, errors.New("Failed to write target address")
	}
	time.AfterFunc(helloWait, func() {
		ssw.Flush()
	})
	ssr := shadowsocks.NewShadowsocksReader(proxyConn, c.cipher)
	return onet.WrapConn(proxyConn, ssr, ssw), nil
}
