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
	"fmt"
	"net"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	ss_client "github.com/Jigsaw-Code/outline-ss-server/shadowsocks/client"
)

// Client is a client for Shadowsocks TCP and UDP connections.
//
// Deprecated: Use ss_client.StreamDialer and ss_client.PacketListener instead.
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
	SetTCPSaltGenerator(ss.SaltGenerator)
}

// NewClient creates a client that routes connections to a Shadowsocks proxy listening at
// `host:port`, with authentication parameters `cipher` (AEAD) and `password`.
//
// Deprecated: Use ss_client.StreamDialer and ss_client.PacketListener instead.
func NewClient(host string, port int, password, cipherName string) (Client, error) {
	// TODO: consider using net.LookupIP to get a list of IPs, and add logic for optimal selection.
	proxyIP, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, fmt.Errorf("Failed to resolve proxy address: %w", err)
	}
	cipher, err := ss.NewCipher(cipherName, password)
	if err != nil {
		return nil, fmt.Errorf("Failed to create Shadowsocks cipher: %w", err)
	}
	streamDialer, err := ss_client.NewStreamDialer(proxyIP.String(), port, cipher)
	if err != nil {
		return nil, fmt.Errorf("Failed to create StreamDialer: %w", err)
	}
	packetListener, err := ss_client.NewPacketListener(proxyIP.String(), port, cipher)
	if err != nil {
		return nil, fmt.Errorf("Failed to create PacketListener: %w", err)
	}
	d := ssClient{StreamDialer: streamDialer, PacketListener: packetListener}
	return &d, nil
}

type ssClient struct {
	ss_client.StreamDialer
	onet.PacketListener
}

func (c *ssClient) SetTCPSaltGenerator(salter ss.SaltGenerator) {
	c.StreamDialer.SetTCPSaltGenerator(salter)
}

func (c *ssClient) DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error) {
	// TODO: restore laddr support
	return c.Dial(raddr)
}

func (c *ssClient) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	// TODO: restore laddr support
	return c.ListenPacket()
}
