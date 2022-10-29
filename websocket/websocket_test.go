package websocket

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
)

func TestWebsocket(t *testing.T) {
	l, err := net.ListenTCP("tcp", nil)
	if err != nil {
		t.Fatalf("Starting listener failed: %v", err)
	}
	defer l.Close()

	connCh := make(chan onet.DuplexConn)
	defer close(connCh)
	handler := func(w http.ResponseWriter, r *http.Request) {
		u := Upgrader{HandshakeTimeout: 50 * time.Millisecond}
		c, err := u.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Upgrading websocket failed: %v", err)
		}
		connCh <- c
	}
	go func() {
		http.ServeTLS(l, http.HandlerFunc(handler), TestCert, TestKey)
	}()

	d := Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 50 * time.Millisecond,
	}
	clientConn, err := d.Dial(fmt.Sprintf("wss://127.0.0.1:%d/", addrPort(t, l.Addr())), nil)
	if err != nil {
		t.Fatalf("Connecting to websocket server failed: %v", err)
	}

	var serverConn onet.DuplexConn
	select {
	case <-time.After(50 * time.Millisecond):
		t.Fatal("Websocket connection not accepted")
	case serverConn = <-connCh:
	}

	testOneWay := func(left, right onet.DuplexConn) {
		payload := ss.MakeTestPayload(1200)
		n, err := left.Write(payload)
		if err != nil {
			t.Fatalf("Writing payload failed: %v", err)
		} else if n != len(payload) {
			t.Fatalf("Write(), want=%d got=%d", len(payload), n)
		}

		right.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		b := make([]byte, 500)
		for i := 0; i < 3; i++ {
			n, err = right.Read(b)
			if err != nil {
				t.Fatalf("Reading payload failed: %v", err)
			}
			if bytes.Compare(b[:n], payload[len(b)*i:len(b)*i+n]) != 0 {
				t.Fatal("Read payload does not match write payload")
			}

			// Close write to show connection can still be drained afterwards
			if i == 0 {
				left.CloseWrite()
			}
		}

		n, err = right.Read(b)
		if err != io.EOF {
			t.Fatalf("Read after finish has no error: want=EOF got=%v", err)
		}
		right.CloseRead()

		_, err = left.Write(payload)
		if err == nil {
			t.Fatalf("Write after close: want=err got=%v", err)
		}
	}

	testOneWay(clientConn, serverConn)
	testOneWay(serverConn, clientConn)
}

func addrPort(t *testing.T, a net.Addr) int {
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatalf(err.Error())
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf(err.Error())
	}
	return port
}
