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
	"io"
	"net"
	"sync"
	"testing"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func TestShadowsocksPacketListener_ListenPacket(t *testing.T) {
	cipher := makeTestCipher(t)
	proxy, running := startShadowsocksUDPEchoServer(cipher, testTargetAddr, t)
	proxyEndpoint := onet.UDPEndpoint{RemoteAddr: *proxy.LocalAddr().(*net.UDPAddr)}
	d, err := NewShadowsocksPacketListener(proxyEndpoint, cipher)
	if err != nil {
		t.Fatalf("Failed to create PacketListener: %v", err)
	}
	conn, err := d.ListenPacket(context.Background())
	if err != nil {
		t.Fatalf("PacketListener.ListenPacket failed: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	pcrw := &packetConnReadWriter{PacketConn: conn, targetAddr: newAddr(testTargetAddr, "udp")}
	expectEchoPayload(pcrw, shadowsocks.MakeTestPayload(1024), make([]byte, 1024), t)

	proxy.Close()
	running.Wait()
}

func BenchmarkShadowsocksPacketListener_ListenPacket(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	cipher := makeTestCipher(b)
	proxy, running := startShadowsocksUDPEchoServer(cipher, testTargetAddr, b)
	proxyEndpoint := onet.UDPEndpoint{RemoteAddr: *proxy.LocalAddr().(*net.UDPAddr)}
	d, err := NewShadowsocksPacketListener(proxyEndpoint, cipher)
	if err != nil {
		b.Fatalf("Failed to create PacketListener: %v", err)
	}
	conn, err := d.ListenPacket(context.Background())
	if err != nil {
		b.Fatalf("PacketListener.ListenPacket failed: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	buf := make([]byte, clientUDPBufferSize)
	for n := 0; n < b.N; n++ {
		payload := shadowsocks.MakeTestPayload(1024)
		pcrw := &packetConnReadWriter{PacketConn: conn, targetAddr: newAddr(testTargetAddr, "udp")}
		b.StartTimer()
		expectEchoPayload(pcrw, payload, buf, b)
		b.StopTimer()
	}

	proxy.Close()
	running.Wait()
}

func startShadowsocksUDPEchoServer(cipher *shadowsocks.Cipher, expectedTgtAddr string, t testing.TB) (net.Conn, *sync.WaitGroup) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Proxy ListenUDP failed: %v", err)
	}
	t.Logf("Starting SS UDP echo proxy at %v\n", conn.LocalAddr())
	cipherBuf := make([]byte, clientUDPBufferSize)
	clientBuf := make([]byte, clientUDPBufferSize)
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		defer conn.Close()
		for {
			n, clientAddr, err := conn.ReadFromUDP(cipherBuf)
			if err != nil {
				t.Logf("Failed to read from UDP conn: %v", err)
				return
			}
			buf, err := shadowsocks.Unpack(clientBuf, cipherBuf[:n], cipher)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}
			tgtAddr := socks.SplitAddr(buf)
			if tgtAddr == nil {
				t.Fatalf("Failed to read target address: %v", err)
			}
			if tgtAddr.String() != expectedTgtAddr {
				t.Fatalf("Expected target address '%v'. Got '%v'", expectedTgtAddr, tgtAddr)
			}
			// Echo both the payload and SOCKS address.
			buf, err = shadowsocks.Pack(cipherBuf, buf, cipher)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}
			conn.WriteTo(buf, clientAddr)
			if err != nil {
				t.Fatalf("Failed to write: %v", err)
			}
		}
	}()
	return conn, &running
}

// io.ReadWriter adapter for net.PacketConn. Used to share code between UDP and TCP tests.
type packetConnReadWriter struct {
	net.PacketConn
	io.ReadWriter
	targetAddr net.Addr
}

func (pc *packetConnReadWriter) Read(b []byte) (n int, err error) {
	n, _, err = pc.PacketConn.ReadFrom(b)
	return
}

func (pc *packetConnReadWriter) Write(b []byte) (int, error) {
	return pc.PacketConn.WriteTo(b, pc.targetAddr)
}
