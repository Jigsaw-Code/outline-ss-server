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
	"errors"
	"flag"
	"fmt"
	"io"
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

var debugLog log.Logger = *log.Default()

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
	remoteAddr udpAddr
}

type udpAddr string

func (a udpAddr) String() string {
	return string(a)
}

func (a udpAddr) Network() string {
	return "udp"
}

func dialPacket(ctx context.Context, listener transport.PacketListener, remoteAddr string) (net.Conn, error) {
	packetConn, err := listener.ListenPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create PacketConn: %v", err)
	}
	return &boundPacketConn{PacketConn: packetConn, remoteAddr: udpAddr(remoteAddr)}, nil
}

func (c *boundPacketConn) Read(packet []byte) (int, error) {
	for {
		n, remoteAddr, err := c.PacketConn.ReadFrom(packet)
		if err != nil {
			if err != nil {
				debugLog.Printf("UDP Read error: %v", debugError(err))
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
		debugLog.Printf("UDP Write error: %#v", err)
	}
	return n, err
}

func (c *boundPacketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func testTCP(proxyDialer transport.StreamDialer, resolverAddress string, domain string) error {
	tcpResolver := net.Resolver{
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			conn, err := proxyDialer.Dial(ctx, resolverAddress)
			if err != nil {
				debugLog.Printf("TCP Dial failed: %v", debugError(err))
			}
			return conn, err
		},
	}
	ips, err := tcpResolver.LookupIP(context.Background(), "ip4", domain)
	if err == nil {
		debugLog.Printf("TCP DNS Resolution succeeded: %v", ips)
	}
	return err
}

func testUDP(proxyListener transport.PacketListener, resolverAddress string, domain string) error {
	udpResolver := net.Resolver{
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			// TODO: use string, porbably the host name "dns.google"
			conn, err := dialPacket(ctx, proxyListener, resolverAddress)
			if err != nil {
				debugLog.Printf("UDP Dial failed: %v", debugError(err))
			}
			return conn, err
		},
	}
	ips, err := udpResolver.LookupIP(context.Background(), "ip4", domain)
	if err == nil {
		debugLog.Printf("UDP DNS Resolution succeeded: %v", ips)
	}
	return err
}

func debugError(err error) string {
	// var netErr *net.OpError
	var syscallErr *os.SyscallError
	// errors.As(err, &netErr)
	errors.As(err, &syscallErr)
	return fmt.Sprintf("%#v %#v %v", err, syscallErr, err.Error())
}

func main() {

	verboseFlag := flag.Bool("v", false, "Enable debug output")
	accessKeyFlag := flag.String("key", "", "Outline access key")
	domainFlag := flag.String("domain", "example.com.", "Domain name to resolve")
	resolver4Flag := flag.String("resolver4", "8.8.8.8", "IPv4 of the DNS resolver to use for the test")
	resolver6Flag := flag.String("resolver6", "2001:4860:4860::8888", "IPv6 of the DNS resolver to use for the test")

	flag.Parse()
	if *verboseFlag {
		debugLog = *log.New(os.Stderr, "[DEBUG] ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	} else {
		debugLog = *log.New(io.Discard, "", log.LstdFlags)
	}

	if *accessKeyFlag == "" {
		flag.Usage()
		os.Exit(1)
	}
	if ip := net.ParseIP(*resolver4Flag); ip == nil || ip.To4() == nil {
		log.Fatalf("Flag --resolver4 must be an IPv4 address. Got %v", *resolver4Flag)
	}
	resolver4Address := net.JoinHostPort(*resolver4Flag, "53")
	if ip := net.ParseIP(*resolver6Flag); ip == nil || ip.To16() == nil {
		log.Fatalf("Flag --resolver6 must be an IPv6 address. Got %v", *resolver6Flag)
	}
	resolver6Address := net.JoinHostPort(*resolver6Flag, "53")

	// Things to test:
	// - TCP working. Where's the error?
	// - UDP working
	// - Different server IPs
	// - Server IPv4 dial support
	// - Server IPv6 dial support

	config, err := ParseAccessKey(*accessKeyFlag)
	if err != nil {
		log.Fatal(err.Error())
	}
	debugLog.Printf("Config: %+v", config)

	hostIPs, err := ResolveHostname(config.Hostname)
	if err != nil {
		log.Fatalf("Failed to resolve host name: %v", err)
	}

	// TODO: limit number of IPs. Or force an input IP?
	for _, hostIP := range hostIPs {
		proxyAddress := net.JoinHostPort(hostIP.String(), fmt.Sprint(config.Port))

		// TCP
		tcpEndpoint := transport.TCPEndpoint{RemoteAddr: net.TCPAddr{IP: hostIP, Port: config.Port}}
		proxyDialer, err := client.NewShadowsocksStreamDialer(tcpEndpoint, config.Cipher)
		if err != nil {
			log.Fatalf("Failed to create Shadowsocks stream dialer: %#v", err)
		}
		err = testTCP(proxyDialer, resolver4Address, *domainFlag)
		fmt.Printf("proxy: %v, resolver: %v, proto: tcp, error: %#v\n", proxyAddress, resolver4Address, err)
		err = testTCP(proxyDialer, resolver6Address, *domainFlag)
		fmt.Printf("proxy: %v, resolver: %v, proto: tcp, error: %#v\n", proxyAddress, resolver6Address, err)

		// UDP
		udpEndpoint := transport.UDPEndpoint{RemoteAddr: net.UDPAddr{IP: hostIP, Port: config.Port}}
		proxyListener, err := client.NewShadowsocksPacketListener(udpEndpoint, config.Cipher)
		if err != nil {
			log.Fatalf("Failed to create Shadowsocks packet listener: %#v", err)
		}
		err = testUDP(proxyListener, resolver4Address, *domainFlag)
		fmt.Printf("proxy: %v, resolver: %v, proto: udp, error: %#v\n", proxyAddress, resolver4Address, err)
		err = testUDP(proxyListener, resolver6Address, *domainFlag)
		fmt.Printf("proxy: %v, resolver: %v, proto: udp, error: %#v\n", proxyAddress, resolver6Address, err)
	}
}
