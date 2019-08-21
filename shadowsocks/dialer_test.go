package shadowsocks

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const (
	testCipher     = "chacha20-ietf-poly1305"
	testPassword   = "testPassword"
	testTargetAddr = "test.local:1111"
)

func TestShadowsocksDialer_DialTCP(t *testing.T) {
	proxyAddr := startShadowsocksTCPEchoProxy(testTargetAddr, t)
	proxyHost, proxyPort, err := SplitHostPortNumber(proxyAddr.String())
	if err != nil {
		t.Fatalf("Failed to parse proxy address: %v", err)
	}
	d, err := NewDialer(proxyHost, proxyPort, testPassword, testCipher)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksDialer: %v", err)
	}
	conn, err := d.DialTCP(nil, testTargetAddr)
	if err != nil {
		t.Fatalf("ShadowsocksDialer.DialTCP failed: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	expectEchoPayload(conn, MakeTestPayload(1024), 1024, t)
}

func TestShadowsocksDialer_DialUDP(t *testing.T) {
	proxyAddr := startShadowsocksUDPEchoServer(testTargetAddr, t)
	proxyHost, proxyPort, err := SplitHostPortNumber(proxyAddr.String())
	if err != nil {
		t.Fatalf("Failed to parse proxy address: %v", err)
	}
	d, err := NewDialer(proxyHost, proxyPort, testPassword, testCipher)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksDialer: %v", err)
	}
	conn, err := d.DialUDP(nil, testTargetAddr)
	if err != nil {
		t.Fatalf("ShadowsocksDialer.DialUDP failed: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	expectEchoPayload(conn, MakeTestPayload(1024), udpBufSize, t)
}

func BenchmarkShadowsocksDialer_DialTCP(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	proxyAddr := startShadowsocksTCPEchoProxy(testTargetAddr, b)
	proxyHost, proxyPort, err := SplitHostPortNumber(proxyAddr.String())
	if err != nil {
		b.Fatalf("Failed to parse proxy address: %v", err)
	}
	d, err := NewDialer(proxyHost, proxyPort, testPassword, testCipher)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksDialer: %v", err)
	}
	conn, err := d.DialTCP(nil, testTargetAddr)
	if err != nil {
		b.Fatalf("ShadowsocksDialer.DialTCP failed: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	for n := 0; n < b.N; n++ {
		payload := MakeTestPayload(1024)
		b.StartTimer()
		expectEchoPayload(conn, payload, len(payload), b)
		b.StopTimer()
	}
}

func BenchmarkShadowsocksDialer_DialUDP(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	proxyAddr := startShadowsocksUDPEchoServer(testTargetAddr, b)
	proxyHost, proxyPort, err := SplitHostPortNumber(proxyAddr.String())
	if err != nil {
		b.Fatalf("Failed to parse proxy address: %v", err)
	}
	d, err := NewDialer(proxyHost, proxyPort, testPassword, testCipher)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksDialer: %v", err)
	}
	conn, err := d.DialUDP(nil, testTargetAddr)
	if err != nil {
		b.Fatalf("ShadowsocksDialer.DialUDP failed: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	for n := 0; n < b.N; n++ {
		payload := MakeTestPayload(1024)
		b.StartTimer()
		expectEchoPayload(conn, payload, udpBufSize, b)
		b.StopTimer()
	}
}

func startShadowsocksTCPEchoProxy(expectedTgtAddr string, t testing.TB) net.Addr {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	t.Logf("Starting SS TCP echo proxy at %v\n", listener.Addr())
	cipher, err := newAeadCipher(testCipher, testPassword)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	go func() {
		defer listener.Close()
		for {
			clientConn, err := listener.AcceptTCP()
			if err != nil {
				t.Fatalf("AcceptTCP failed: %v", err)
			}
			defer clientConn.Close()
			go func() {
				ssr := NewShadowsocksReader(clientConn, cipher)
				ssw := NewShadowsocksWriter(clientConn, cipher)
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
	return listener.Addr()
}

func startShadowsocksUDPEchoServer(expectedTgtAddr string, t testing.TB) net.Addr {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Proxy ListenUDP failed: %v", err)
	}
	t.Logf("Starting SS UDP echo proxy at %v\n", conn.LocalAddr())
	cipherBuf := make([]byte, udpBufSize)
	clientBuf := make([]byte, udpBufSize)
	cipher, err := newAeadCipher(testCipher, testPassword)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	go func() {
		defer conn.Close()
		for {
			n, clientAddr, err := conn.ReadFromUDP(cipherBuf)
			if err != nil {
				t.Fatalf("Failed to read from UDP conn: %v", err)
			}
			buf, err := shadowaead.Unpack(clientBuf, cipherBuf[:n], cipher)
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
			buf, err = shadowaead.Pack(cipherBuf, buf, cipher)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}
			conn.WriteTo(buf, clientAddr)
			if err != nil {
				t.Fatalf("Failed to write: %v", err)
			}
		}
	}()
	return conn.LocalAddr()
}

func expectEchoPayload(conn io.ReadWriter, payload []byte, bufSize int, t testing.TB) {
	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Failed to write payload: %v", err)
	}
	buf := make([]byte, bufSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read payload: %v", err)
	}
	if !bytes.Equal(payload, buf[:n]) {
		t.Fatalf("Expected output '%v'. Got '%v'", payload, buf[:n])
	}
}
