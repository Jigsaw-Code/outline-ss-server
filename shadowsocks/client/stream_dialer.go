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
	"errors"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type StreamDialer interface {
	onet.StreamDialer

	// SetTCPSaltGenerator controls the SaltGenerator used for TCP upstream.
	// `salter` may be `nil`.
	// This method is not thread-safe.
	SetTCPSaltGenerator(ss.SaltGenerator)
}

// NewShadowsocksStreamDialer creates a client that routes connections to a Shadowsocks proxy listening at
// the given StreamEndpoint, with `cipher` as the Shadowsocks crypto.
func NewShadowsocksStreamDialer(endpoint onet.StreamEndpoint, cipher *ss.Cipher) (StreamDialer, error) {
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
	cipher   *ss.Cipher
	salter   ss.SaltGenerator
}

func (c *streamDialer) SetTCPSaltGenerator(salter ss.SaltGenerator) {
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

func (c *streamDialer) Dial(remoteAddr string) (onet.DuplexConn, error) {
	socksTargetAddr := socks.ParseAddr(remoteAddr)
	if socksTargetAddr == nil {
		return nil, errors.New("Failed to parse target address")
	}
	proxyConn, err := c.endpoint.Connect()
	if err != nil {
		return nil, err
	}
	ssw := ss.NewShadowsocksWriter(proxyConn, c.cipher)
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
	ssr := ss.NewShadowsocksReader(proxyConn, c.cipher)
	return onet.WrapConn(proxyConn, ssr, ssw), nil
}
