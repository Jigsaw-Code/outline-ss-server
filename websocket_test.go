package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/websocket"
)

func TestRunWebsocketServer(t *testing.T) {
	ss := &SSServer{ports: make(map[int]*ssPort)}
	ws, err := RunWebsocketServer(ss, 0, websocket.TestCert, websocket.TestKey)
	if err != nil {
		t.Fatalf("Failed running websocket server: %v", err)
	}

	testPort := 2000
	port := &ssPort{cipherList: service.NewCipherList()}
	ss.ports[testPort] = port
	tcpService := &fakeTCPService{connCh: make(chan onet.DuplexConn)}
	port.tcpService = tcpService

	t.Run("with registered port", func(t *testing.T) {
		d := websocket.Dialer{
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
			HandshakeTimeout: 50 * time.Millisecond,
		}
		u := fmt.Sprintf("wss://127.0.0.1:%d/%d", addrPort(t, ws.listener.Addr()), testPort)
		clientConn, err := d.Dial(u, nil)
		if err != nil {
			t.Errorf("Failed to connect to websocket server: %v", err)
		}

		var serverConn onet.DuplexConn
		select {
		case <-time.After(50 * time.Millisecond):
			t.Fatal("Failed to receive connection on server")
		case serverConn = <-tcpService.connCh:
		}
		defer tcpService.running.Done()

		payload := shadowsocks.MakeTestPayload(1000)
		b := make([]byte, 1024)

		_, err = clientConn.Write(payload)
		if err != nil {
			t.Errorf("Writing payload failed: %v", err)
		}
		n, err := serverConn.Read(b)
		if err != nil {
			t.Fatalf("Reading payload failed: %v", err)
		} else if bytes.Compare(payload, b[:n]) != 0 {
			t.Fatal("Read payload does not match write payload")
		}

		_, err = serverConn.Write(payload)
		if err != nil {
			t.Errorf("Writing payload failed: %v", err)
		}
		n, err = clientConn.Read(b)
		if err != nil {
			t.Fatalf("Reading payload failed: %v", err)
		} else if bytes.Compare(payload, b[:n]) != 0 {
			t.Fatal("Read payload does not match write payload")
		}
	})

	t.Run("with non registered port", func(t *testing.T) {
		d := websocket.Dialer{
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
			HandshakeTimeout: 50 * time.Millisecond,
		}
		u := fmt.Sprintf("wss://127.0.0.1:%d/%d", addrPort(t, ws.listener.Addr()), 3456)
		_, err := d.Dial(u, nil)
		if err != nil {
			t.Fatalf("Failed to connect to websocket server: %v", err)
		}

		select {
		case <-tcpService.connCh:
			t.Fatalf("Expected not to receive connection on non existing port, but received one")
		case <-time.After(50 * time.Millisecond):
		}
	})
}

type fakeTCPService struct {
	connCh  chan onet.DuplexConn
	running sync.WaitGroup
}

func (f *fakeTCPService) HandleConnection(listenerPort int, clientTCPConn onet.DuplexConn) {
	f.running.Add(1)
	f.connCh <- clientTCPConn
	f.running.Wait()
}

func (f *fakeTCPService) SetTargetIPValidator(targetIPValidator onet.TargetIPValidator) {}

func (f *fakeTCPService) Serve(listener *net.TCPListener) error {
	return nil
}

func (f *fakeTCPService) Stop() error {
	return nil
}

func (f *fakeTCPService) GracefulStop() error {
	return nil
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
