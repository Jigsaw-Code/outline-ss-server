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
	"fmt"
	"io"
	"net"

	"github.com/Jigsaw-Code/outline-ss-server/internal/slicepool"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// clientUDPBufferSize is the maximum supported UDP packet size in bytes.
const clientUDPBufferSize = 16 * 1024

// udpPool stores the byte slices used for storing encrypted packets.
var udpPool = slicepool.MakePool(clientUDPBufferSize)

type packetListener struct {
	endpoint onet.PacketEndpoint
	cipher   *shadowsocks.Cipher
}

func NewShadowsocksPacketListener(endpoint onet.PacketEndpoint, cipher *shadowsocks.Cipher) (onet.PacketListener, error) {
	if endpoint == nil {
		return nil, errors.New("Argument endpoint must not be nil")
	}
	if cipher == nil {
		return nil, errors.New("Argument cipher must not be nil")
	}
	return &packetListener{endpoint: endpoint, cipher: cipher}, nil
}

func (c *packetListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	proxyConn, err := c.endpoint.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("Could not connect to endpoint: %x", err)
	}
	conn := packetConn{Conn: proxyConn, cipher: c.cipher}
	return &conn, nil
}

type packetConn struct {
	net.Conn
	cipher *shadowsocks.Cipher
}

// WriteTo encrypts `b` and writes to `addr` through the proxy.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	socksTargetAddr := socks.ParseAddr(addr.String())
	if socksTargetAddr == nil {
		return 0, errors.New("Failed to parse target address")
	}
	lazySlice := udpPool.LazySlice()
	cipherBuf := lazySlice.Acquire()
	defer lazySlice.Release()
	saltSize := c.cipher.SaltSize()
	// Copy the SOCKS target address and payload, reserving space for the generated salt to avoid
	// partially overlapping the plaintext and cipher slices since `Pack` skips the salt when calling
	// `AEAD.Seal` (see https://golang.org/pkg/crypto/cipher/#AEAD).
	plaintextBuf := append(append(cipherBuf[saltSize:saltSize], socksTargetAddr...), b...)
	buf, err := shadowsocks.Pack(cipherBuf, plaintextBuf, c.cipher)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(buf)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts into `b`.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	lazySlice := udpPool.LazySlice()
	cipherBuf := lazySlice.Acquire()
	defer lazySlice.Release()
	n, err := c.Conn.Read(cipherBuf)
	if err != nil {
		return 0, nil, err
	}
	// Decrypt in-place.
	buf, err := shadowsocks.Unpack(nil, cipherBuf[:n], c.cipher)
	if err != nil {
		return 0, nil, err
	}
	socksSrcAddr := socks.SplitAddr(buf)
	if socksSrcAddr == nil {
		return 0, nil, errors.New("Failed to read source address")
	}
	srcAddr := newAddr(socksSrcAddr.String(), "udp")
	n = copy(b, buf[len(socksSrcAddr):]) // Strip the SOCKS source address
	if len(b) < len(buf)-len(socksSrcAddr) {
		return n, srcAddr, io.ErrShortBuffer
	}
	return n, srcAddr, nil
}

type addr struct {
	address string
	network string
}

func (a *addr) String() string {
	return a.address
}

func (a *addr) Network() string {
	return a.network
}

// newAddr returns a net.Addr that holds an address of the form `host:port` with a domain name or IP as host.
// Used for SOCKS addressing.
func newAddr(address, network string) net.Addr {
	return &addr{address: address, network: network}
}
