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

package service

import (
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/stretchr/testify/require"
)

// Simulates receiving invalid TCP connection attempts on a server with 100 ciphers.
func BenchmarkTCPFindCipherFail(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	clientIP := netip.MustParseAddr("127.0.0.1")
	cipherList, err := MakeTestCiphers(makeTestSecrets(100))
	if err != nil {
		b.Fatal(err)
	}
	testPayload := makeTestPayload(50)
	for n := 0; n < b.N; n++ {
		b.StartTimer()
		findAccessKey(clientIP, 2, testPayload, cipherList, NewDebugLogger("TCP"))
		b.StopTimer()
	}
}

// Simulates receiving valid TCP connection attempts from 100 different users,
// each with their own cipher and their own IP address.
func BenchmarkTCPFindCipherRepeat(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	const numCiphers = 100 // Must be <256
	cipherList, err := MakeTestCiphers(makeTestSecrets(numCiphers))
	if err != nil {
		b.Fatal(err)
	}
	cipherEntries := [numCiphers]*CipherEntry{}
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	for cipherNumber, element := range snapshot {
		cipherEntries[cipherNumber] = element.Value.(*CipherEntry)
	}
	testPayload := makeTestPayload(50)
	for n := 0; n < b.N; n++ {
		cipherNumber := byte(n % numCiphers)
		reader, writer := io.Pipe()
		clientIP := netip.AddrFrom4([4]byte{192, 0, 2, cipherNumber})
		addr := netip.AddrPortFrom(clientIP, 54321)
		c := conn{clientAddr: net.TCPAddrFromAddrPort(addr), reader: reader, writer: writer}
		cipher := cipherEntries[cipherNumber].CryptoKey
		go shadowsocks.NewWriter(writer, cipher).Write(makeTestPayload(50))
		b.StartTimer()
		_, _, _, err := findAccessKey(clientIP, 2, testPayload, cipherList, NewDebugLogger("TCP"))
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		c.Close()
	}
}

// Simulates receiving invalid UDP packets on a server with 100 ciphers.
func BenchmarkUDPUnpackFail(b *testing.B) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(100))
	if err != nil {
		b.Fatal(err)
	}
	testPayload := makeTestPayload(50)
	testIP := netip.MustParseAddr("192.0.2.1")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		findAccessKey(testIP, serverUDPBufferSize, testPayload, cipherList, NewDebugLogger("UDP"))
	}
}

// Simulates receiving valid UDP packets from 100 different users, each with
// their own cipher and IP address.
func BenchmarkUDPUnpackRepeat(b *testing.B) {
	const numCiphers = 100 // Must be <256
	cipherList, err := MakeTestCiphers(makeTestSecrets(numCiphers))
	if err != nil {
		b.Fatal(err)
	}
	packets := [numCiphers][]byte{}
	ips := [numCiphers]netip.Addr{}
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	for i, element := range snapshot {
		packets[i] = make([]byte, 0, serverUDPBufferSize)
		plaintext := makeTestPayload(50)
		packets[i], err = shadowsocks.Pack(make([]byte, serverUDPBufferSize), plaintext, element.Value.(*CipherEntry).CryptoKey)
		if err != nil {
			b.Error(err)
		}
		ips[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		cipherNumber := n % numCiphers
		ip := ips[cipherNumber]
		packet := packets[cipherNumber]
		_, _, _, err := findAccessKey(ip, serverUDPBufferSize, packet, cipherList, NewDebugLogger("UDP"))
		if err != nil {
			b.Error(err)
		}
	}
}

// Simulates receiving valid UDP packets from 100 different IP addresses,
// all using the same cipher.
func BenchmarkUDPUnpackSharedKey(b *testing.B) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(1)) // One widely shared key
	if err != nil {
		b.Fatal(err)
	}
	plaintext := makeTestPayload(50)
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	cryptoKey := snapshot[0].Value.(*CipherEntry).CryptoKey
	packet, err := shadowsocks.Pack(make([]byte, serverUDPBufferSize), plaintext, cryptoKey)
	require.Nil(b, err)

	const numIPs = 100 // Must be <256
	ips := [numIPs]netip.Addr{}
	for i := 0; i < numIPs; i++ {
		ips[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ip := ips[n%numIPs]
		_, _, _, err := findAccessKey(ip, serverUDPBufferSize, packet, cipherList, NewDebugLogger("UDP"))
		if err != nil {
			b.Error(err)
		}
	}
}
