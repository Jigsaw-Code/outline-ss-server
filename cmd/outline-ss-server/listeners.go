// Copyright 2024 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type NetworkAddr struct {
	network string
	Host    string
	Port    uint
}

// String returns a human-readable representation of the [NetworkAddr].
func (na *NetworkAddr) Network() string {
	return na.network
}

// String returns a human-readable representation of the [NetworkAddr].
func (na *NetworkAddr) String() string {
	return na.JoinHostPort()
}

// JoinHostPort is a convenience wrapper around [net.JoinHostPort].
func (na *NetworkAddr) JoinHostPort() string {
	return net.JoinHostPort(na.Host, strconv.Itoa(int(na.Port)))
}

// Listen creates a new listener for the [NetworkAddr].
func (na *NetworkAddr) Listen() (io.Closer, error) {
	address := na.JoinHostPort()

	switch na.network {

	case "tcp":
		return net.Listen(na.network, address)
	case "udp":
		return net.ListenPacket(na.network, address)
	default:
		return nil, fmt.Errorf("unsupported network: %s", na.network)
	}
}

// ParseNetworkAddr parses an address into a [NetworkAddr]. The input
// string is expected to be of the form "network/host:port" where any part is
// optional.
//
// Examples:
//
//	tcp/127.0.0.1:8000
//	udp/127.0.0.1:9000
func ParseNetworkAddr(addr string) (NetworkAddr, error) {
	var host, port string
	network, host, port, err := SplitNetworkAddr(addr)
	if err != nil {
		return NetworkAddr{}, err
	}
	if network == "" {
		return NetworkAddr{}, errors.New("missing network")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return NetworkAddr{}, fmt.Errorf("invalid port: %v", err)
	}
	return NetworkAddr{
		network: network,
		Host:    host,
		Port:    uint(p),
	}, nil
}

// SplitNetworkAddr splits a into its network, host, and port components.
func SplitNetworkAddr(a string) (network, host, port string, err error) {
	beforeSlash, afterSlash, slashFound := strings.Cut(a, "/")
	if slashFound {
		network = strings.ToLower(strings.TrimSpace(beforeSlash))
		a = afterSlash
	}
	host, port, err = net.SplitHostPort(a)
	return
}
