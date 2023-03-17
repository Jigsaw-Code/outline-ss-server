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

func TestShadowsocksStreamDialer_Dial(t *testing.T) {
	cipher := makeTestCipher(t)
	proxy, running := startShadowsocksTCPEchoProxy(cipher, testTargetAddr, t)
	proxyEndpoint := onet.TCPEndpoint{RemoteAddr: *proxy.Addr().(*net.TCPAddr)}
	d, err := NewShadowsocksStreamDialer(proxyEndpoint, cipher)
	if err != nil {
		t.Fatalf("Failed to create StreamDialer: %v", err)
	}
	conn, err := d.Dial(context.Background(), testTargetAddr)
	if err != nil {
		t.Fatalf("StreamDialer.Dial failed: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	expectEchoPayload(conn, shadowsocks.MakeTestPayload(1024), make([]byte, 1024), t)
	conn.Close()

	proxy.Close()
	running.Wait()
}

func TestShadowsocksStreamDialer_DialNoPayload(t *testing.T) {
	cipher := makeTestCipher(t)
	proxy, running := startShadowsocksTCPEchoProxy(cipher, testTargetAddr, t)
	proxyEndpoint := onet.TCPEndpoint{RemoteAddr: *proxy.Addr().(*net.TCPAddr)}
	d, err := NewShadowsocksStreamDialer(proxyEndpoint, cipher)
	if err != nil {
		t.Fatalf("Failed to create StreamDialer: %v", err)
	}
	conn, err := d.Dial(context.Background(), testTargetAddr)
	if err != nil {
		t.Fatalf("StreamDialer.Dial failed: %v", err)
	}

	// Wait for more than 10 milliseconds to ensure that the target
	// address is sent.
	time.Sleep(20 * time.Millisecond)
	// Force the echo server to verify the target address.
	conn.Close()

	proxy.Close()
	running.Wait()
}

func TestShadowsocksStreamDialer_DialFastClose(t *testing.T) {
	// Set up a listener that verifies no data is sent.
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Error(err)
		}
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if n > 0 || err != io.EOF {
			t.Errorf("Expected EOF, got %v, %v", buf[:n], err)
		}
		listener.Close()
		close(done)
	}()

	cipher := makeTestCipher(t)
	proxyEndpoint := onet.TCPEndpoint{RemoteAddr: *listener.Addr().(*net.TCPAddr)}
	d, err := NewShadowsocksStreamDialer(proxyEndpoint, cipher)
	if err != nil {
		t.Fatalf("Failed to create StreamDialer: %v", err)
	}
	conn, err := d.Dial(context.Background(), testTargetAddr)
	if err != nil {
		t.Fatalf("StreamDialer.Dial failed: %v", err)
	}

	// Wait for less than 10 milliseconds to ensure that the target
	// address is not sent.
	time.Sleep(1 * time.Millisecond)
	// Close the connection before the target address is sent.
	conn.Close()
	// Wait for the listener to verify the close.
	<-done
}

func TestShadowsocksStreamDialer_TCPPrefix(t *testing.T) {
	prefix := []byte("test prefix")

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		defer listener.Close()
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			t.Logf("AcceptTCP failed: %v", err)
			return
		}
		defer clientConn.Close()
		prefixReceived := make([]byte, len(prefix))
		if _, err := io.ReadFull(clientConn, prefixReceived); err != nil {
			t.Error(err)
		}
		for i := range prefix {
			if prefixReceived[i] != prefix[i] {
				t.Error("prefix contents mismatch")
			}
		}
	}()

	cipher := makeTestCipher(t)
	proxyEndpoint := onet.TCPEndpoint{RemoteAddr: *listener.Addr().(*net.TCPAddr)}
	d, err := NewShadowsocksStreamDialer(proxyEndpoint, cipher)
	if err != nil {
		t.Fatalf("Failed to create StreamDialer: %v", err)
	}
	d.SetTCPSaltGenerator(NewPrefixSaltGenerator(prefix))
	conn, err := d.Dial(context.Background(), testTargetAddr)
	if err != nil {
		t.Fatalf("StreamDialer.Dial failed: %v", err)
	}
	conn.Write(nil)
	conn.Close()
	running.Wait()
}

func BenchmarkShadowsocksStreamDialer_Dial(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	cipher := makeTestCipher(b)
	proxy, running := startShadowsocksTCPEchoProxy(cipher, testTargetAddr, b)
	proxyEndpoint := onet.TCPEndpoint{RemoteAddr: *proxy.Addr().(*net.TCPAddr)}
	d, err := NewShadowsocksStreamDialer(proxyEndpoint, cipher)
	if err != nil {
		b.Fatalf("Failed to create StreamDialer: %v", err)
	}
	conn, err := d.Dial(context.Background(), testTargetAddr)
	if err != nil {
		b.Fatalf("StreamDialer.Dial failed: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	buf := make([]byte, 1024)
	for n := 0; n < b.N; n++ {
		payload := shadowsocks.MakeTestPayload(1024)
		b.StartTimer()
		expectEchoPayload(conn, payload, buf, b)
		b.StopTimer()
	}

	conn.Close()
	proxy.Close()
	running.Wait()
}

func startShadowsocksTCPEchoProxy(cipher *shadowsocks.Cipher, expectedTgtAddr string, t testing.TB) (net.Listener, *sync.WaitGroup) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	t.Logf("Starting SS TCP echo proxy at %v\n", listener.Addr())
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		defer listener.Close()
		for {
			clientConn, err := listener.AcceptTCP()
			if err != nil {
				t.Logf("AcceptTCP failed: %v", err)
				return
			}
			running.Add(1)
			go func() {
				defer running.Done()
				defer clientConn.Close()
				ssr := shadowsocks.NewShadowsocksReader(clientConn, cipher)
				ssw := shadowsocks.NewShadowsocksWriter(clientConn, cipher)
				ssClientConn := onet.WrapConn(clientConn, ssr, ssw)

				tgtAddr, err := socks.ReadAddr(ssClientConn)
				if err != nil {
					t.Fatalf("Failed to read target address: %v", err)
				}
				if tgtAddr.String() != expectedTgtAddr {
					t.Fatalf("Expected target address '%v'. Got '%v'", expectedTgtAddr, tgtAddr)
				}
				io.Copy(ssw, ssr)
			}()
		}
	}()
	return listener, &running
}
