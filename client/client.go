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

// Deprecated: Use the StreamDialer and PacketListener types under github.com/Jigsaw-Code/outline-ss-server/net instead.
package client

import (
	"context"
	"fmt"
	"net"

	"github.com/Jigsaw-Code/outline-internal-sdk/transport"
	"github.com/Jigsaw-Code/outline-internal-sdk/transport/shadowsocks"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
)

// Client is a client for Shadowsocks TCP and UDP connections.
//
// Deprecated: Use shadowsocks.StreamDialer and shadowsocks.PacketListener instead.
type Client interface {
	// DialTCP connects to `raddr` over TCP though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil.
	// `raddr` has the form `host:port`, where `host` can be a domain name or IP address.
	//
	// Deprecated: use StreamDialer.Dial instead.
	DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error)

	// ListenUDP relays UDP packets though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil.
	//
	// Deprecated: use PacketDialer.ListenPacket instead.
	ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error)

	// SetTCPSaltGenerator controls the SaltGenerator used for TCP upstream.
	// `salter` may be `nil`.
	// This method is not thread-safe.
	SetTCPSaltGenerator(shadowsocks.SaltGenerator)
}

// NewClient creates a client that routes connections to a Shadowsocks proxy listening at
// `host:port`, with authentication parameters `cipher` (AEAD) and `password`.
//
// Deprecated: Use ssclient.StreamDialer and ssclient.PacketListener instead.
func NewClient(host string, port int, password, cipherName string) (Client, error) {
	// TODO: consider using net.LookupIP to get a list of IPs, and add logic for optimal selection.
	proxyIP, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy address: %w", err)
	}
	key, err := shadowsocks.NewEncryptionKey(cipherName, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption key: %w", err)
	}
	return &ssClient{
		key:          key,
		proxyAddress: net.JoinHostPort(proxyIP.String(), fmt.Sprint(port)),
	}, nil
}

type ssClient struct {
	key          *shadowsocks.EncryptionKey
	proxyAddress string
	salter       shadowsocks.SaltGenerator
}

// ListenUDP implements the Client.ListenUDP API.
func (c *ssClient) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	endpoint := transport.UDPEndpoint{Address: c.proxyAddress}
	if laddr != nil {
		endpoint.Dialer.LocalAddr = laddr
	}
	packetListener, err := shadowsocks.NewPacketListener(endpoint, c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create PacketListener: %w", err)
	}
	return packetListener.ListenPacket(context.Background())
}

func (c *ssClient) SetTCPSaltGenerator(salter shadowsocks.SaltGenerator) {
	c.salter = salter
}

// DialTCP implements the Client.DialTCP API.
func (c *ssClient) DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error) {
	endpoint := transport.TCPEndpoint{Address: c.proxyAddress}
	if laddr != nil {
		endpoint.Dialer.LocalAddr = laddr
	}
	streamDialer, err := shadowsocks.NewStreamDialer(&endpoint, c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create StreamDialer: %w", err)
	}
	streamDialer.SaltGenerator = c.salter
	return streamDialer.Dial(context.Background(), raddr)
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
//
// Deprecated: use [net.UDPAddr] or [net.TCPAddr] instead.
func NewAddr(address, network string) net.Addr {
	return &addr{address: address, network: network}
}
