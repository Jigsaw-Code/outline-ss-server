package shadowsocks

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const (
	testCipher   = "chacha20-ietf-poly1305"
	testPassword = "testPassword"
	testPayload  = "!!!test~payload!!!"
)

func TestShadowsocksDialer_DialTCP(t *testing.T) {
	// Let the OS pick an available port
	listenTCPAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	proxyListener, err := net.ListenTCP("tcp", listenTCPAddr)
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	go startShadowsocksTCPProxy(proxyListener, t)

	targetListener, err := net.ListenTCP("tcp", listenTCPAddr)
	go startTCPEchoServer(targetListener, t)

	proxyHost, proxyPortStr, err := net.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to parse proxy address: %v", err)
	}
	proxyPort, _ := strconv.Atoi(proxyPortStr)
	d, err := NewDialer(proxyHost, testPassword, testCipher, proxyPort)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksDialer: %v", err)
	}
	conn, err := d.DialTCP(targetListener.Addr().String())
	if err != nil {
		t.Fatalf("ShadowsocksDialer.DialTCP failed: %v", err)
	}
	expectEchoPayload(conn, len(testPayload), t)
}

func TestShadowsocksDialer_DialUDP(t *testing.T) {
	// Let the OS pick an available port
	listenUDPAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	proxyConn, err := net.ListenUDP("udp", listenUDPAddr)
	if err != nil {
		t.Fatalf("Proxy ListenUDP failed: %v", err)
	}
	go startShadowsocksUDPProxy(proxyConn, t)

	targetConn, err := net.ListenUDP("udp", listenUDPAddr)
	if err != nil {
		t.Fatalf("Target ListenUDP failed: %v", err)
	}
	go startUDPEchoServer(targetConn, t)

	proxyHost, proxyPortStr, err := net.SplitHostPort(proxyConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Failed to parse proxy address: %v", err)
	}
	proxyPort, _ := strconv.Atoi(proxyPortStr)
	d, err := NewDialer(proxyHost, testPassword, testCipher, proxyPort)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksDialer: %v", err)
	}
	conn, err := d.DialUDP(targetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("ShadowsocksDialer.DialUDP failed: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	expectEchoPayload(conn, udpBufSize, t)
}

func startShadowsocksTCPProxy(listener *net.TCPListener, t *testing.T) {
	t.Logf("Starting SS TCP proxy at %v\n", listener.Addr())
	cipher, err := newAeadCipher(testCipher, testPassword)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	defer listener.Close()
	for {
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			t.Fatalf("AcceptTCP failed: %v", err)
		}
		go func() {
			ssr := NewShadowsocksReader(clientConn, cipher)
			ssw := NewShadowsocksWriter(clientConn, cipher)
			ssClientConn := onet.WrapConn(clientConn, ssr, ssw)

			tgtAddr, err := socks.ReadAddr(ssClientConn)
			if err != nil {
				t.Fatalf("Failed to read target address: %v", err)
			}
			tgtTCPAddr, err := net.ResolveTCPAddr("tcp", tgtAddr.String())
			if err != nil {
				t.Fatalf("Failed to resolve target address: %v", err)
			}
			tgtTCPConn, err := net.DialTCP("tcp", nil, tgtTCPAddr)
			if err != nil {
				t.Fatalf("Failed to connect to target")
			}
			defer tgtTCPConn.Close()
			tgtTCPConn.SetKeepAlive(true)

			_, _, err = onet.Relay(ssClientConn, tgtTCPConn)
			if err != nil {
				t.Fatalf("Failed to relay connection: %v", err)
			}
		}()
	}
}

func startShadowsocksUDPProxy(conn *net.UDPConn, t *testing.T) {
	t.Logf("Starting SS UDP proxy at %v\n", conn.LocalAddr())
	nm := newNATmap(5*time.Second, metrics.NewShadowsocksMetrics(nil))
	cipherBuf := make([]byte, udpBufSize)
	clientBuf := make([]byte, udpBufSize)
	cipher, err := newAeadCipher(testCipher, testPassword)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
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
		tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
		if err != nil {
			t.Fatalf("Failed to resolve target address: %v", err)
		}
		targetConn := nm.Get(clientAddr.String())
		if targetConn == nil {
			targetConn, err = net.ListenUDP("udp", nil)
			if err != nil {
				t.Fatalf("Failed create UDP socket: %v", err)
			}
			nm.Add(clientAddr, conn, cipher, targetConn, "", "")
		}
		payload := buf[len(tgtAddr):]
		_, err = targetConn.WriteTo(payload, tgtUDPAddr)
		if err != nil {
			t.Fatalf("Failed to write to target conn: %v", err)
		}
	}
}

func startTCPEchoServer(listener net.Listener, t *testing.T) {
	t.Logf("Starting TCP echo server at %v\n", listener.Addr())
	buf := make([]byte, 1024)
	for {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("Accept failed: %v", err)
		}
		go func() {
			defer conn.Close()
			for {
				n, err := conn.Read(buf)
				if err != nil {
					t.Fatalf("Echo server read failed: %v", err)
				}
				conn.Write(buf[:n])
			}
		}()
	}
}

func startUDPEchoServer(conn *net.UDPConn, t *testing.T) {
	t.Logf("Starting UDP echo server at %v\n", conn.LocalAddr())
	defer conn.Close()
	buf := make([]byte, udpBufSize)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("Failed to read from UDP: %v", err)
		}
		conn.WriteTo(buf[:n], addr)
	}
}

func expectEchoPayload(conn io.ReadWriter, bufSize int, t *testing.T) {
	_, err := conn.Write([]byte(testPayload))
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}
	buf := make([]byte, bufSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}
	if string(buf[:n]) != testPayload {
		t.Fatalf("Expected output '%v'. Got '%v'", testPayload, string(buf))
	}
}
