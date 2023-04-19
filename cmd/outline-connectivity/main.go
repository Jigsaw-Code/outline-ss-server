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

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Jigsaw-Code/outline-internal-sdk/transport"
	"github.com/Jigsaw-Code/outline-internal-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-internal-sdk/transport/shadowsocks/client"
)

type sessionConfig struct {
	Hostname string
	Port     int
	Cipher   *shadowsocks.Cipher
}

func ParseAccessKey(accessKey string) (*sessionConfig, error) {
	var config sessionConfig
	accessKeyURL, err := url.Parse(accessKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access key: %v", err)
	}
	var portString string
	// Host is a <host>:<port> string
	config.Hostname, portString, err = net.SplitHostPort(accessKeyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint address: %v", err)
	}
	config.Port, err = strconv.Atoi(portString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port number: %v", err)
	}
	cipherInfoBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(accessKeyURL.User.String())
	if err != nil {
		return nil, fmt.Errorf("failed to decode cipher info [%v]: %v", accessKeyURL.User.String(), err)
	}
	cipherName, secret, found := strings.Cut(string(cipherInfoBytes), ":")
	if !found {
		return nil, fmt.Errorf("invalid cipher info: no ':' separator")
	}
	config.Cipher, err = shadowsocks.NewCipher(cipherName, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}
	return &config, nil
}

func ResolveHostname(hostname string) ([]net.IP, error) {
	hostnameAsIP := net.ParseIP(hostname)
	if hostnameAsIP != nil {
		return []net.IP{hostnameAsIP}, nil
	}
	return net.DefaultResolver.LookupIP(context.Background(), "ip", hostname)
}

type boundPacketConn struct {
	net.PacketConn
	remoteAddr net.UDPAddr
}

func dialPacket(ctx context.Context, listener transport.PacketListener, remoteAddr net.UDPAddr) (net.Conn, error) {
	packetConn, err := listener.ListenPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create PacketConn: %v", err)
	}
	return &boundPacketConn{PacketConn: packetConn, remoteAddr: remoteAddr}, nil
}

func (c *boundPacketConn) Read(packet []byte) (int, error) {
	for {
		n, remoteAddr, err := c.PacketConn.ReadFrom(packet)
		if err != nil {
			if err != nil {
				log.Printf("UDP Read error: %v", err)
			}
			return n, err
		}
		if remoteAddr.String() != c.remoteAddr.String() {
			continue
		}
		return n, nil
	}
}

func (c *boundPacketConn) Write(packet []byte) (int, error) {
	n, err := c.PacketConn.WriteTo(packet, &c.remoteAddr)
	if err != nil {
		log.Printf("UDP Write error: %v", err)
	}
	return n, err
}

func (c *boundPacketConn) RemoteAddr() net.Addr {
	return &c.remoteAddr
}

func main() {
	accessKeyFlag := flag.String("key", "", "Outline access key")
	domainFlag := flag.String("domain", "example.com", "Domain name to resolve")
	// protoFlag := flag.String("proto", "", "DNS protocol to use ('tcp' or 'udp')")
	flag.Parse()
	if *accessKeyFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	config, err := ParseAccessKey(*accessKeyFlag)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Printf("Config: %v", config)

	hostIPs, err := ResolveHostname(config.Hostname)
	if err != nil {
		log.Fatalf("Failed to resolve host name: %v", err)
	}

	// TODO: loop through IPs
	if len(hostIPs) == 0 {
		log.Fatal("No IPs for hostname found")
	}

	// TCP
	tcpEndpoint := transport.TCPEndpoint{RemoteAddr: net.TCPAddr{IP: hostIPs[0], Port: config.Port}}
	proxyDialer, err := client.NewShadowsocksStreamDialer(tcpEndpoint, config.Cipher)
	if err != nil {
		log.Fatalf("Failed to create Shadowsocks stream dialer: %v", err)
	}
	tcpResolver := net.Resolver{StrictErrors: true,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			log.Printf("Resolver address for TCP is %v %v", network, address)
			conn, err := proxyDialer.Dial(ctx, "8.8.8.8:53")
			if err != nil {
				log.Printf("TCP Dial failed: %v", err)
			}
			return conn, err
		},
	}
	ips, err := tcpResolver.LookupIP(context.Background(), "ip", *domainFlag)
	if err != nil {
		log.Fatalf("Failed to resolve test domain: %v", err)
	}
	log.Printf("TCP DNS Resolution succeeded: %v", ips)

	// UDP
	udpEndpoint := transport.UDPEndpoint{RemoteAddr: net.UDPAddr{IP: hostIPs[0], Port: config.Port}}
	proxyListener, err := client.NewShadowsocksPacketListener(udpEndpoint, config.Cipher)
	if err != nil {
		log.Fatalf("Failed to create Shadowsocks stream dialer: %v", err)
	}
	udpResolver := net.Resolver{
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			log.Printf("Resolver address for UDP is %v %v", network, address)
			conn, err := dialPacket(ctx, proxyListener, net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53})
			if err != nil {
				log.Printf("UDP Dial failed: %v", err)
			}
			return conn, err
		},
	}
	ips, err = udpResolver.LookupIP(context.Background(), "ip", *domainFlag)
	if err != nil {
		log.Fatalf("Failed to resolve test domain: %v", err)
	}
	log.Printf("UDP DNS Resolution succeeded: %v", ips)
}
