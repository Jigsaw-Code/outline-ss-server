package client

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/websocket"
)

const (
	testWSPath = "/test"
)

func TestWebsocketClient(t *testing.T) {
	testCases := []struct {
		name     string
		opts     WebsocketOptions
		wantHost string
		wantSNI  string
	}{
		{
			name:     "with_ip_host",
			opts:     WebsocketOptions{Addr: "127.0.0.1", Host: "example.com"},
			wantHost: "example.com",
			wantSNI:  "example.com",
		},
		{
			name:     "with_ip_host_sni",
			opts:     WebsocketOptions{Addr: "127.0.0.1", Host: "example.com", SNI: "sni.com"},
			wantHost: "example.com",
			wantSNI:  "sni.com",
		},
		{
			name:     "with_domain",
			opts:     WebsocketOptions{Addr: "localhost"},
			wantHost: "localhost",
			wantSNI:  "localhost",
		},
		{
			name:     "with_domain_host",
			opts:     WebsocketOptions{Addr: "localhost", Host: "example.com"},
			wantHost: "example.com",
			wantSNI:  "example.com",
		},
		{
			name:     "with_domain_host_sni",
			opts:     WebsocketOptions{Addr: "localhost", Host: "example.com", SNI: "sni.com"},
			wantHost: "example.com",
			wantSNI:  "sni.com",
		},
	}

	proxy, hostCh, sniCh := startWebsocketShadowsocksEchoProxy(t)
	defer close(hostCh)
	defer close(sniCh)
	defer proxy.Close()
	_, proxyPort, err := splitHostPortNumber(proxy.Addr().String())
	if err != nil {
		t.Fatalf("Failed to parse proxy address: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Password = testPassword
			tc.opts.Cipher = ss.TestCipher
			tc.opts.Port = proxyPort
			tc.opts.Path = testWSPath

			d, err := NewWebsocketClient(tc.opts)
			if err != nil {
				t.Fatalf("Failed to create WebsocketClient: %v", err)
			}
			conn, err := d.DialTCP(nil, testTargetAddr)
			if err != nil {
				t.Fatalf("WebsocketClient.DialTCP failed: %v", err)
			}

			select {
			case sni := <-sniCh:
				if sni != tc.wantSNI {
					t.Fatalf("Wrong server name in TLS handshake server. got='%v' want='%v'", sni, tc.wantSNI)
				}
			case <-time.After(50 * time.Millisecond):
				t.Fatal("TLS connection state not recevied")
			}
			select {
			case host := <-hostCh:
				if host != tc.wantHost {
					t.Fatalf("Wrong host header. got='%v' want='%v'", host, tc.wantHost)
				}
			case <-time.After(50 * time.Millisecond):
				t.Fatal("HTTP request not recevied")
			}

			conn.SetReadDeadline(time.Now().Add(time.Second * 5))
			expectEchoPayload(conn, ss.MakeTestPayload(1024), make([]byte, 1024), t)
			conn.Close()
		})
	}
}

func startWebsocketShadowsocksEchoProxy(t *testing.T) (net.Listener, chan string, chan string) {
	proxy, _ := startShadowsocksTCPEchoProxy(testTargetAddr, t)

	hostCh := make(chan string, 1)
	sniCh := make(chan string, 1)

	handler := func(w http.ResponseWriter, r *http.Request) {
		u := websocket.Upgrader{HandshakeTimeout: 50 * time.Millisecond}
		c, err := u.Upgrade(w, r, nil)
		defer c.Close()

		hostCh <- r.Host

		if r.URL.Path != testWSPath {
			t.Logf("Wrong Path received on request. got='%v' want='%v'", testWSPath, r.URL.Path)
			return
		}

		targetC, err := net.Dial("tcp", proxy.Addr().String())
		if err != nil {
			t.Logf("Failed to connect to TCP echo server: %v", err)
			return
		}

		onet.Relay(c, targetC.(*net.TCPConn))
	}

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Starting websocket listener failed: %v", err)
	}

	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(handler)}
		srv.TLSConfig = &tls.Config{
			VerifyConnection: func(cs tls.ConnectionState) error {
				sniCh <- cs.ServerName
				return nil
			},
		}
		srv.ServeTLS(l, websocket.TestCert, websocket.TestKey)
	}()

	return l, hostCh, sniCh
}
