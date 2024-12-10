// Copyright 2018 Jigsaw Operations LLC
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

package service

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 5 * time.Minute

var clientAddr = net.UDPAddr{IP: []byte{192, 0, 2, 1}, Port: 12345}
var targetAddr = net.UDPAddr{IP: []byte{192, 0, 2, 2}, Port: 54321}
var localAddr = net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 9}
var dnsAddr = net.UDPAddr{IP: []byte{192, 0, 2, 3}, Port: 53}
var natCryptoKey *shadowsocks.EncryptionKey

func init() {
	logging.SetLevel(logging.INFO, "")
	natCryptoKey, _ = shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, "test password")
}

type packet struct {
	addr    net.Addr
	payload []byte
	err     error
}

type fakePacketConn struct {
	net.PacketConn
	send     chan packet
	recv     chan packet
	deadline time.Time
	mu       sync.Mutex
}

func makePacketConn() *fakePacketConn {
	return &fakePacketConn{
		send: make(chan packet, 1),
		recv: make(chan packet),
	}
}

func (conn *fakePacketConn) getReadDeadline() time.Time {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.deadline
}

func (conn *fakePacketConn) SetReadDeadline(deadline time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.deadline = deadline
	return nil
}

func (conn *fakePacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	var err error
	defer func() {
		if recover() != nil {
			err = net.ErrClosed
		}
	}()

	conn.send <- packet{addr, payload, nil}
	return len(payload), err
}

func (conn *fakePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	pkt, ok := <-conn.recv
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(buffer, pkt.payload)
	if n < len(pkt.payload) {
		return n, pkt.addr, errors.New("buffer was too short")
	}
	return n, pkt.addr, pkt.err
}

func (conn *fakePacketConn) Close() error {
	fmt.Println("closing fakePacketConn")
	conn.mu.Lock()
	defer conn.mu.Unlock()
	close(conn.send)
	close(conn.recv)
	return nil
}

func (conn *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999}
}

func (conn *fakePacketConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8888}
}

type udpReport struct {
	accessKey, status                  string
	clientProxyBytes, proxyTargetBytes int64
}

// Stub metrics implementation for testing NAT behaviors.

type natTestMetrics struct {
	natEntriesAdded int
}

var _ NATMetrics = (*natTestMetrics)(nil)

func (m *natTestMetrics) AddNATEntry() {
	m.natEntriesAdded++
}
func (m *natTestMetrics) RemoveNATEntry() {}

type fakeUDPAssocationMetrics struct {
	accessKey       string
	upstreamPackets []udpReport
	mu              sync.Mutex
}

var _ UDPAssocationMetrics = (*fakeUDPAssocationMetrics)(nil)

func (m *fakeUDPAssocationMetrics) AddAuthenticated(key string) {
	m.accessKey = key
}

func (m *fakeUDPAssocationMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamPackets = append(m.upstreamPackets, udpReport{m.accessKey, status, clientProxyBytes, proxyTargetBytes})
}

func (m *fakeUDPAssocationMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
}

func (m *fakeUDPAssocationMetrics) AddClosed() {}

// sendSSPayload sends a single Shadowsocks packet to the provided connection.
// The packet is constructed with the given address, cipher, and payload.
func sendSSPayload(conn *fakePacketConn, addr net.Addr, cipher *shadowsocks.EncryptionKey, payload []byte) {
	socksAddr := socks.ParseAddr(addr.String())
	plaintext := append(socksAddr, payload...)
	ciphertext := make([]byte, cipher.SaltSize()+len(plaintext)+cipher.TagSize())
	shadowsocks.Pack(ciphertext, plaintext, cipher)
	conn.recv <- packet{
		addr:    &clientAddr,
		payload: ciphertext,
	}
}

// startTestHandler creates a new association handler with a fake
// client and target connection for testing purposes. It also starts a
// PacketServe goroutine to handle incoming packets on the client connection.
func startTestHandler() (AssociationHandler, func(target net.Addr, payload []byte), *fakePacketConn) {
	ciphers, _ := MakeTestCiphers([]string{"asdf"})
	cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
	handler := NewAssociationHandler(10*time.Second, ciphers, nil)
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	handler.SetTargetConnFactory(func() (net.PacketConn, error) {
		return targetConn, nil
	})
	go PacketServe(clientConn, func(conn net.Conn) { handler.Handle(conn, &NoOpUDPAssocationMetrics{}) }, &natTestMetrics{})
	return handler, func(target net.Addr, payload []byte) {
		sendSSPayload(clientConn, target, cipher, payload)
	}, targetConn
}

func TestNatconnCloseWhileReading(t *testing.T) {
	nc := &natconn{
		PacketConn:  makePacketConn(),
		raddr:       &clientAddr,
		doneCh:      make(chan struct{}),
		readBufCh:   make(chan []byte, 1),
		bytesReadCh: make(chan int, 1),
	}
	go func() {
		buf := make([]byte, 1024)
		nc.Read(buf)
	}()

	err := nc.Close()

	assert.NoError(t, err, "Close should not panic or return an error")
}

func TestAssociationHandler_Handle_IPFilter(t *testing.T) {
	t.Run("RequirePublicIP blocks localhost", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetIPValidator(onet.RequirePublicIP)

		sendPayload(&localAddr, []byte{1, 2, 3})

		select {
		case <-targetConn.send:
			t.Errorf("Expected no packets to be sent")
		case <-time.After(100 * time.Millisecond):
			return
		}
	})

	t.Run("allowAll allows localhost", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetIPValidator(allowAll)

		sendPayload(&localAddr, []byte{1, 2, 3})

		sent := <-targetConn.send
		if !bytes.Equal([]byte{1, 2, 3}, sent.payload) {
			t.Errorf("Expected %v, but got %v", []byte{1, 2, 3}, sent.payload)
		}
	})
}

func TestUpstreamMetrics(t *testing.T) {
	ciphers, _ := MakeTestCiphers([]string{"asdf"})
	cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
	handler := NewAssociationHandler(10*time.Second, ciphers, nil)
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	handler.SetTargetConnFactory(func() (net.PacketConn, error) {
		return targetConn, nil
	})
	metrics := &fakeUDPAssocationMetrics{}
	go PacketServe(clientConn, func(conn net.Conn) { handler.Handle(conn, metrics) }, &natTestMetrics{})

	// Test both the first-packet and subsequent-packet cases.
	const N = 10
	for i := 1; i <= N; i++ {
		sendSSPayload(clientConn, &targetAddr, cipher, make([]byte, i))
		<-targetConn.send
	}

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	assert.Equal(t, N, len(metrics.upstreamPackets), "Expected %d reports, not %d", N, len(metrics.upstreamPackets))
	for i, report := range metrics.upstreamPackets {
		assert.Equal(t, int64(i+1), report.proxyTargetBytes, "Expected %d payload bytes, not %d", i+1, report.proxyTargetBytes)
		assert.Greater(t, report.clientProxyBytes, report.proxyTargetBytes, "Expected nonzero input overhead (%d > %d)", report.clientProxyBytes, report.proxyTargetBytes)
		assert.Equal(t, "id-0", report.accessKey, "Unexpected access key name: %s", report.accessKey)
		assert.Equal(t, "OK", report.status, "Wrong status: %s", report.status)
	}
}

func assertAlmostEqual(t *testing.T, a, b time.Time) {
	delta := a.Sub(b)
	limit := 100 * time.Millisecond
	if delta > limit || -delta > limit {
		t.Errorf("Times are not close: %v, %v", a, b)
	}
}

func assertUDPAddrEqual(t *testing.T, a net.Addr, b *net.UDPAddr) {
	addr, ok := a.(*net.UDPAddr)
	if !ok || !addr.IP.Equal(b.IP) || addr.Port != b.Port || addr.Zone != b.Zone {
		t.Errorf("Mismatched address: %v != %v", a, b)
	}
}

// Implements net.Error
type fakeTimeoutError struct {
	error
}

func (e *fakeTimeoutError) Timeout() bool {
	return true
}

func (e *fakeTimeoutError) Temporary() bool {
	return false
}

func TestTimedPacketConn(t *testing.T) {
	t.Run("Write", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetConnFactory(func() (net.PacketConn, error) {
			return &timedPacketConn{PacketConn: targetConn, defaultTimeout: timeout}, nil
		})

		buf := []byte{1}
		sendPayload(&targetAddr, buf)

		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
		sent := <-targetConn.send
		if !bytes.Equal(sent.payload, buf) {
			t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
		}
		assertUDPAddrEqual(t, sent.addr, &targetAddr)
	})

	t.Run("WriteDNS", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetConnFactory(func() (net.PacketConn, error) {
			return &timedPacketConn{PacketConn: targetConn, defaultTimeout: timeout}, nil
		})

		// Simulate one DNS query being sent.
		buf := []byte{1}
		sendPayload(&dnsAddr, buf)

		// DNS-only connections have a fixed timeout of 17 seconds.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
		sent := <-targetConn.send
		if !bytes.Equal(sent.payload, buf) {
			t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
		}
		assertUDPAddrEqual(t, sent.addr, &dnsAddr)
	})

	t.Run("WriteDNSMultiple", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetConnFactory(func() (net.PacketConn, error) {
			return &timedPacketConn{PacketConn: targetConn, defaultTimeout: timeout}, nil
		})

		// Simulate three DNS queries being sent.
		buf := []byte{1}
		sendPayload(&dnsAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send

		// DNS-only connections have a fixed timeout of 17 seconds.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
	})

	t.Run("WriteMixed", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetConnFactory(func() (net.PacketConn, error) {
			return &timedPacketConn{PacketConn: targetConn, defaultTimeout: timeout}, nil
		})

		// Simulate both non-DNS and DNS packets being sent.
		buf := []byte{1}
		sendPayload(&targetAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send

		// Mixed DNS and non-DNS connections should have the user-specified timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
	})

	t.Run("FastClose", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(10*time.Second, ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetConnFactory(func() (net.PacketConn, error) {
			return &timedPacketConn{PacketConn: targetConn, defaultTimeout: timeout}, nil
		})
		go PacketServe(clientConn, func(conn net.Conn) { handler.Handle(conn, &NoOpUDPAssocationMetrics{}) }, &natTestMetrics{})

		// Send one DNS query.
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{1})
		sent := <-targetConn.send
		require.Len(t, sent.payload, 1)
		// Send the response.
		response := []byte{1, 2, 3, 4, 5}
		received := packet{addr: &dnsAddr, payload: response}
		targetConn.recv <- received
		sent, ok := <-clientConn.send
		if !ok {
			t.Error("clientConn was closed")
		}

		// targetConn should be scheduled to close immediately.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now())
	})

	t.Run("NoFastClose_NotDNS", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(10*time.Second, ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetConnFactory(func() (net.PacketConn, error) {
			return &timedPacketConn{PacketConn: targetConn, defaultTimeout: timeout}, nil
		})
		go PacketServe(clientConn, func(conn net.Conn) { handler.Handle(conn, &NoOpUDPAssocationMetrics{}) }, &natTestMetrics{})

		// Send one non-DNS packet.
		sendSSPayload(clientConn, &targetAddr, cipher, []byte{1})
		sent := <-targetConn.send
		require.Len(t, sent.payload, 1)
		// Send the response.
		response := []byte{1, 2, 3, 4, 5}
		received := packet{addr: &targetAddr, payload: response}
		targetConn.recv <- received
		sent, ok := <-clientConn.send
		if !ok {
			t.Error("clientConn was closed")
		}

		// targetConn should be scheduled to close after the full timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
	})

	t.Run("NoFastClose_MultipleDNS", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(10*time.Second, ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetConnFactory(func() (net.PacketConn, error) {
			return &timedPacketConn{PacketConn: targetConn, defaultTimeout: timeout}, nil
		})
		go PacketServe(clientConn, func(conn net.Conn) { handler.Handle(conn, &NoOpUDPAssocationMetrics{}) }, &natTestMetrics{})

		// Send two DNS packets.
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{1})
		<-targetConn.send
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{2})
		<-targetConn.send

		// Send a response.
		response := []byte{1, 2, 3, 4, 5}
		received := packet{addr: &dnsAddr, payload: response}
		targetConn.recv <- received
		<-clientConn.send

		// targetConn should be scheduled to close after the DNS timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
	})

	t.Run("Timeout", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetConnFactory(func() (net.PacketConn, error) {
			return &timedPacketConn{PacketConn: targetConn, defaultTimeout: timeout}, nil
		})

		// Simulate a non-DNS initial packet.
		sendPayload(&targetAddr, []byte{1})
		<-targetConn.send
		// Simulate a read timeout.
		received := packet{err: &fakeTimeoutError{}}
		before := time.Now()
		targetConn.recv <- received
		// Wait for targetConn to close.
		if _, ok := <-targetConn.send; ok {
			t.Error("targetConn should be closed due to read timeout")
		}

		// targetConn should be closed as soon as the timeout error is received.
		assertAlmostEqual(t, before, time.Now())
	})
}

func TestNATMap(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		nat := newNATmap()
		if nat.Get("foo") != nil {
			t.Error("Expected nil value from empty NAT map")
		}
	})

	t.Run("Add", func(t *testing.T) {
		nat := newNATmap()
		addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		conn1 := &natconn{}

		nat.Add(addr1, conn1)
		assert.Equal(t, conn1, nat.Get(addr1.String()), "Get should return the correct connection")

		conn2 := &natconn{}
		nat.Add(addr1, conn2)
		assert.Equal(t, conn2, nat.Get(addr1.String()), "Adding with the same address should overwrite the entry")
	})

	t.Run("Get", func(t *testing.T) {
		nat := newNATmap()
		addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		conn1 := &natconn{}
		nat.Add(addr1, conn1)

		assert.Equal(t, conn1, nat.Get(addr1.String()), "Get should return the correct connection for an existing address")

		addr2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5678}
		assert.Nil(t, nat.Get(addr2.String()), "Get should return nil for a non-existent address")
	})

	t.Run("closure_deletes", func(t *testing.T) {
		nat := newNATmap()
		addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		conn1 := &natconn{}
		deleteEntry := nat.Add(addr1, conn1)

		deleteEntry()

		assert.Nil(t, nat.Get(addr1.String()), "Get should return nil after deleting the entry")
	})

	t.Run("Close", func(t *testing.T) {
		nat := newNATmap()
		addr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		pc := makePacketConn()
		conn1 := &natconn{PacketConn: pc, raddr: addr1}
		nat.Add(addr1, conn1)

		err := nat.Close()
		assert.NoError(t, err, "Close should not return an error")

		// The underlying connection should be scheduled to close immediately.
		assertAlmostEqual(t, pc.deadline, time.Now())
	})
}

// Simulates receiving invalid UDP packets on a server with 100 ciphers.
func BenchmarkUDPUnpackFail(b *testing.B) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(100))
	if err != nil {
		b.Fatal(err)
	}
	testPayload := makeTestPayload(50)
	textBuf := make([]byte, serverUDPBufferSize)
	testIP := netip.MustParseAddr("192.0.2.1")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		findAccessKeyUDP(testIP, textBuf, testPayload, cipherList, noopLogger())
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
	testBuf := make([]byte, serverUDPBufferSize)
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
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList, noopLogger())
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
	testBuf := make([]byte, serverUDPBufferSize)
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
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList, noopLogger())
		if err != nil {
			b.Error(err)
		}
	}
}

func TestUDPEarlyClose(t *testing.T) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	if err != nil {
		t.Fatal(err)
	}
	const testTimeout = 200 * time.Millisecond
	ph := NewAssociationHandler(testTimeout, cipherList, &fakeShadowsocksMetrics{})

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	require.Nil(t, clientConn.Close())
	// This should return quickly without timing out.
	PacketServe(clientConn, func(conn net.Conn) { ph.Handle(conn, &NoOpUDPAssocationMetrics{}) }, &natTestMetrics{})
}

// Makes sure the UDP listener returns [io.ErrClosed] on reads and writes after Close().
func TestClosedUDPListenerError(t *testing.T) {
	var packetConn net.PacketConn
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	err = packetConn.Close()
	require.NoError(t, err)

	_, _, err = packetConn.ReadFrom(nil)
	require.ErrorIs(t, err, net.ErrClosed)

	_, err = packetConn.WriteTo(nil, &net.UDPAddr{})
	require.ErrorIs(t, err, net.ErrClosed)
}
