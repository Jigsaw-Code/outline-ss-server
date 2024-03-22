// Copyright 2020 Jigsaw Operations LLC
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

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	logging "github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const maxUDPPacketSize = 64 * 1024

func init() {
	logging.SetLevel(logging.INFO, "")
}

// makeTestPayload returns a slice of `size` arbitrary bytes.
func makeTestPayload(size int) []byte {
	payload := make([]byte, size)
	for i := 0; i < size; i++ {
		payload[i] = byte(i)
	}
	return payload
}

// makeTestSecrets returns a slice of `n` test passwords.  Not secure!
func makeTestSecrets(n int) []string {
	secrets := make([]string, n)
	for i := 0; i < n; i++ {
		secrets[i] = fmt.Sprintf("secret-%v", i)
	}
	return secrets
}

func allowAll(ip net.IP) error {
	// Allow access to localhost so that we can run integration tests with
	// an actual destination server.
	return nil
}

func startTCPEchoServer(t testing.TB) (*net.TCPListener, *sync.WaitGroup) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		for {
			clientConn, err := listener.AcceptTCP()
			if err != nil {
				t.Logf("AcceptTCP failed: %v", err)
				return
			}
			running.Add(1)
			go func() {
				defer running.Done()
				io.Copy(clientConn, clientConn)
				clientConn.Close()
			}()
		}
	}()
	return listener, &running
}

func startUDPEchoServer(t testing.TB) (*net.UDPConn, *sync.WaitGroup) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Proxy ListenUDP failed: %v", err)
	}
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		defer conn.Close()
		buf := make([]byte, maxUDPPacketSize)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				t.Logf("Failed to read from UDP conn: %v", err)
				return
			}
			conn.WriteTo(buf[:n], clientAddr)
			if err != nil {
				t.Fatalf("Failed to write: %v", err)
			}
		}
	}()
	return conn, &running
}

func TestTCPEcho(t *testing.T) {
	echoListener, echoRunning := startTCPEchoServer(t)

	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	secrets := []string{"secret"}
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		t.Fatal(err)
	}
	replayCache := service.NewReplayCache(5)
	const testTimeout = 200 * time.Millisecond
	testMetrics := &service.NoOpTCPMetrics{}
	authFunc := service.NewShadowsocksStreamAuthenticator(cipherList, &replayCache, testMetrics)
	handler := service.NewTCPHandler(proxyListener.Addr().(*net.TCPAddr).Port, authFunc, testMetrics, testTimeout)
	handler.SetTargetDialer(&transport.TCPDialer{})
	done := make(chan struct{})
	go func() {
		service.StreamServe(func() (transport.StreamConn, error) { return proxyListener.AcceptTCP() }, handler.Handle)
		done <- struct{}{}
	}()

	cryptoKey, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secrets[0])
	require.NoError(t, err)
	client, err := shadowsocks.NewStreamDialer(&transport.TCPEndpoint{Address: proxyListener.Addr().String()}, cryptoKey)
	require.NoError(t, err)
	conn, err := client.DialStream(context.Background(), echoListener.Addr().String())
	require.NoError(t, err)

	const N = 1000
	up := make([]byte, N)
	for i := 0; i < N; i++ {
		up[i] = byte(i)
	}
	n, err := conn.Write(up)
	if err != nil {
		t.Fatal(err)
	}
	if n != N {
		t.Fatalf("Tried to upload %d bytes, but only sent %d", N, n)
	}

	down := make([]byte, N)
	n, err = conn.Read(down)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n != N {
		t.Fatalf("Expected to download %d bytes, but only received %d", N, n)
	}

	if !bytes.Equal(up, down) {
		t.Fatal("Echo mismatch")
	}

	conn.Close()
	proxyListener.Close()
	<-done
	echoListener.Close()
	echoRunning.Wait()
}

type statusMetrics struct {
	service.NoOpTCPMetrics
	sync.Mutex
	statuses []string
}

func (m *statusMetrics) AddClosedTCPConnection(clientInfo ipinfo.IPInfo, ip net.Addr, accessKey string, status string, data metrics.ProxyMetrics, duration time.Duration) {
	m.Lock()
	m.statuses = append(m.statuses, status)
	m.Unlock()
}

func TestRestrictedAddresses(t *testing.T) {
	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err, "ListenTCP failed: %v", err)
	secrets := []string{"secret"}
	cipherList, err := service.MakeTestCiphers(secrets)
	require.NoError(t, err)
	const testTimeout = 200 * time.Millisecond
	testMetrics := &statusMetrics{}
	authFunc := service.NewShadowsocksStreamAuthenticator(cipherList, nil, testMetrics)
	handler := service.NewTCPHandler(proxyListener.Addr().(*net.TCPAddr).Port, authFunc, testMetrics, testTimeout)
	done := make(chan struct{})
	go func() {
		service.StreamServe(service.WrapStreamListener(proxyListener.AcceptTCP), handler.Handle)
		done <- struct{}{}
	}()

	cryptoKey, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secrets[0])
	require.NoError(t, err)
	dialer, err := shadowsocks.NewStreamDialer(&transport.TCPEndpoint{Address: proxyListener.Addr().String()}, cryptoKey)
	require.NoError(t, err, "Failed to create ShadowsocksClient")

	buf := make([]byte, 10)

	addresses := []string{
		"localhost:9999",
		"[::1]:80",
		"10.0.0.1:1234",
		"[fc00::1]:54321",
	}

	expectedStatus := []string{
		"ERR_ADDRESS_INVALID",
		"ERR_ADDRESS_INVALID",
		"ERR_ADDRESS_PRIVATE",
		"ERR_ADDRESS_PRIVATE",
	}

	for _, address := range addresses {
		conn, err := dialer.DialStream(context.Background(), address)
		require.NoError(t, err, "Failed to dial %v", address)
		n, err := conn.Read(buf)
		assert.Equal(t, 0, n, "Server should close without replying on rejected address")
		assert.Equal(t, io.EOF, err)
		conn.Close()
	}

	proxyListener.Close()
	<-done
	assert.ElementsMatch(t, testMetrics.statuses, expectedStatus)
}

// Metrics about one UDP packet.
type udpRecord struct {
	clientInfo        ipinfo.IPInfo
	accessKey, status string
	in, out           int
}

// Fake metrics implementation for UDP
type fakeUDPMetrics struct {
	up, down []udpRecord
	natAdded int
}

var _ service.UDPMetrics = (*fakeUDPMetrics)(nil)

func (m *fakeUDPMetrics) GetIPInfo(ip net.IP) (ipinfo.IPInfo, error) {
	return ipinfo.IPInfo{CountryCode: "QQ"}, nil
}
func (m *fakeUDPMetrics) AddUDPPacketFromClient(clientInfo ipinfo.IPInfo, accessKey, status string, clientProxyBytes, proxyTargetBytes int) {
	m.up = append(m.up, udpRecord{clientInfo, accessKey, status, clientProxyBytes, proxyTargetBytes})
}
func (m *fakeUDPMetrics) AddUDPPacketFromTarget(clientInfo ipinfo.IPInfo, accessKey, status string, targetProxyBytes, proxyClientBytes int) {
	m.down = append(m.down, udpRecord{clientInfo, accessKey, status, targetProxyBytes, proxyClientBytes})
}
func (m *fakeUDPMetrics) AddUDPNatEntry(clientAddr net.Addr, accessKey string) {
	m.natAdded++
}
func (m *fakeUDPMetrics) RemoveUDPNatEntry(clientAddr net.Addr, accessKey string) {
	// Not tested because it requires waiting for a long timeout.
}
func (m *fakeUDPMetrics) AddUDPCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {}

func TestUDPEcho(t *testing.T) {
	echoConn, echoRunning := startUDPEchoServer(t)

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	secrets := []string{"secret"}
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		t.Fatal(err)
	}
	testMetrics := &fakeUDPMetrics{}
	proxy := service.NewPacketHandler(time.Hour, cipherList, testMetrics)
	proxy.SetTargetIPValidator(allowAll)
	done := make(chan struct{})
	go func() {
		proxy.Handle(proxyConn)
		done <- struct{}{}
	}()

	cryptoKey, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secrets[0])
	require.NoError(t, err)
	client, err := shadowsocks.NewPacketListener(&transport.UDPEndpoint{Address: proxyConn.LocalAddr().String()}, cryptoKey)
	require.NoError(t, err)
	conn, err := client.ListenPacket(context.Background())
	require.NoError(t, err)

	const N = 1000
	up := makeTestPayload(N)
	n, err := conn.WriteTo(up, echoConn.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	if n != N {
		t.Fatalf("Tried to upload %d bytes, but only sent %d", N, n)
	}

	down := make([]byte, N)
	n, addr, err := conn.ReadFrom(down)
	if err != nil {
		t.Fatal(err)
	}
	if n != N {
		t.Errorf("Tried to download %d bytes, but only sent %d", N, n)
	}
	if addr.String() != echoConn.LocalAddr().String() {
		t.Errorf("Reported address mismatch: %s != %s", addr.String(), echoConn.LocalAddr().String())
	}

	if !bytes.Equal(up, down) {
		t.Fatal("Echo mismatch")
	}

	conn.Close()
	echoConn.Close()
	echoRunning.Wait()
	proxyConn.Close()
	<-done
	// Verify that the expected metrics were reported.
	snapshot := cipherList.SnapshotForClientIP(nil)
	keyID := snapshot[0].Value.(*service.CipherEntry).ID

	if testMetrics.natAdded != 1 {
		t.Errorf("Wrong NAT add count: %d", testMetrics.natAdded)
	}
	if len(testMetrics.up) != 1 {
		t.Errorf("Wrong number of packets sent: %v", testMetrics.up)
	} else {
		record := testMetrics.up[0]
		require.Equal(t, "XL", record.clientInfo.CountryCode.String())
		if record.clientInfo.CountryCode != "XL" ||
			record.accessKey != keyID ||
			record.status != "OK" ||
			record.in <= record.out ||
			record.out != N {
			t.Errorf("Bad upstream metrics: %v", record)
		}
	}
	if len(testMetrics.down) != 1 {
		t.Errorf("Wrong number of packets received: %v", testMetrics.down)
	} else {
		record := testMetrics.down[0]
		if record.clientInfo.CountryCode != "XL" ||
			record.accessKey != keyID ||
			record.status != "OK" ||
			record.in != N ||
			record.out <= record.in {
			t.Errorf("Bad upstream metrics: %v", record)
		}
	}
}

func BenchmarkTCPThroughput(b *testing.B) {
	echoListener, echoRunning := startTCPEchoServer(b)

	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	secrets := []string{"secret"}
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		b.Fatal(err)
	}
	const testTimeout = 200 * time.Millisecond
	testMetrics := &service.NoOpTCPMetrics{}
	authFunc := service.NewShadowsocksStreamAuthenticator(cipherList, nil, testMetrics)
	handler := service.NewTCPHandler(proxyListener.Addr().(*net.TCPAddr).Port, authFunc, testMetrics, testTimeout)
	handler.SetTargetDialer(&transport.TCPDialer{})
	done := make(chan struct{})
	go func() {
		service.StreamServe(service.WrapStreamListener(proxyListener.AcceptTCP), handler.Handle)
		done <- struct{}{}
	}()

	cryptoKey, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secrets[0])
	require.NoError(b, err)
	client, err := shadowsocks.NewStreamDialer(&transport.TCPEndpoint{Address: proxyListener.Addr().String()}, cryptoKey)
	require.NoError(b, err)
	conn, err := client.DialStream(context.Background(), echoListener.Addr().String())
	require.NoError(b, err)

	const N = 1000
	up := makeTestPayload(N)
	down := make([]byte, N)

	start := time.Now()
	b.ResetTimer()
	var clientRunning sync.WaitGroup
	clientRunning.Add(1)
	go func() {
		for i := 0; i < b.N; i++ {
			conn.Write(up)
		}
		clientRunning.Done()
	}()

	for i := 0; i < b.N; i++ {
		conn.Read(down)
	}
	b.StopTimer()
	elapsed := time.Since(start)

	megabits := float64(8*1000*b.N) / 1e6
	b.ReportMetric(megabits/elapsed.Seconds(), "mbps")

	conn.Close()
	proxyListener.Close()
	<-done
	echoListener.Close()
	clientRunning.Wait()
	echoRunning.Wait()
}

func BenchmarkTCPMultiplexing(b *testing.B) {
	echoListener, echoRunning := startTCPEchoServer(b)

	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	const numKeys = 50
	secrets := makeTestSecrets(numKeys)
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		b.Fatal(err)
	}
	replayCache := service.NewReplayCache(service.MaxCapacity)
	const testTimeout = 200 * time.Millisecond
	testMetrics := &service.NoOpTCPMetrics{}
	authFunc := service.NewShadowsocksStreamAuthenticator(cipherList, &replayCache, testMetrics)
	handler := service.NewTCPHandler(proxyListener.Addr().(*net.TCPAddr).Port, authFunc, testMetrics, testTimeout)
	handler.SetTargetDialer(&transport.TCPDialer{})
	done := make(chan struct{})
	go func() {
		service.StreamServe(service.WrapStreamListener(proxyListener.AcceptTCP), handler.Handle)
		done <- struct{}{}
	}()

	var clients [numKeys]*shadowsocks.StreamDialer
	for i := 0; i < numKeys; i++ {
		cryptoKey, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secrets[i])
		require.NoError(b, err)
		clients[i], err = shadowsocks.NewStreamDialer(&transport.TCPEndpoint{Address: proxyListener.Addr().String()}, cryptoKey)
		require.NoError(b, err)
	}

	b.ResetTimer()
	var wg sync.WaitGroup
	for i := 0; i < numKeys; i++ {
		k := b.N / numKeys
		if i < b.N%numKeys {
			k++
		}
		client := clients[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < k; i++ {
				conn, err := client.DialStream(context.Background(), echoListener.Addr().String())
				if err != nil {
					b.Errorf("ShadowsocksClient.DialTCP failed: %v", err)
				}

				const N = 1000
				buf := make([]byte, N)
				n, err := conn.Write(buf)
				require.Nil(b, err)
				if n != N {
					b.Errorf("Tried to upload %d bytes, but only sent %d", N, n)
				}
				n, err = conn.Read(buf)
				require.Nil(b, err)
				if n != N {
					b.Errorf("Tried to download %d bytes, but only received %d: %v", N, n, err)
				}
				conn.CloseWrite()
				n, err = conn.Read(buf)
				if n != 0 || err != io.EOF {
					b.Errorf("Expected clean close but got %d bytes: %v", n, err)
				}
			}
		}()
	}
	wg.Wait()

	proxyListener.Close()
	<-done
	echoListener.Close()
	echoRunning.Wait()
}

func BenchmarkUDPEcho(b *testing.B) {
	echoConn, echoRunning := startUDPEchoServer(b)

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	secrets := []string{"secret"}
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		b.Fatal(err)
	}
	proxy := service.NewPacketHandler(time.Hour, cipherList, &service.NoOpUDPMetrics{})
	proxy.SetTargetIPValidator(allowAll)
	done := make(chan struct{})
	go func() {
		proxy.Handle(server)
		done <- struct{}{}
	}()

	cryptoKey, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secrets[0])
	require.NoError(b, err)
	client, err := shadowsocks.NewPacketListener(&transport.UDPEndpoint{Address: server.LocalAddr().String()}, cryptoKey)
	require.NoError(b, err)
	conn, err := client.ListenPacket(context.Background())
	require.NoError(b, err)

	const N = 1000
	buf := make([]byte, N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.WriteTo(buf, echoConn.LocalAddr())
		conn.ReadFrom(buf)
	}
	b.StopTimer()

	require.NoError(b, conn.Close())
	require.Nil(b, server.Close())
	<-done
	echoConn.Close()
	echoRunning.Wait()
}

func BenchmarkUDPManyKeys(b *testing.B) {
	echoConn, echoRunning := startUDPEchoServer(b)

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	const numKeys = 100
	secrets := makeTestSecrets(numKeys)
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		b.Fatal(err)
	}
	proxy := service.NewPacketHandler(time.Hour, cipherList, &service.NoOpUDPMetrics{})
	proxy.SetTargetIPValidator(allowAll)
	done := make(chan struct{})
	go func() {
		proxy.Handle(proxyConn)
		done <- struct{}{}
	}()

	var clients [numKeys]transport.PacketListener
	for i := 0; i < numKeys; i++ {
		cryptoKey, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secrets[i])
		require.NoError(b, err)
		clients[i], err = shadowsocks.NewPacketListener(&transport.UDPEndpoint{Address: proxyConn.LocalAddr().String()}, cryptoKey)
		require.NoError(b, err)
	}

	const N = 1000
	buf := make([]byte, N)
	conns := make([]net.PacketConn, len(clients))
	for i, client := range clients {
		conns[i], _ = client.ListenPacket(context.Background())
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := conns[i%numKeys]
		conn.WriteTo(buf, echoConn.LocalAddr())
		conn.ReadFrom(buf)
	}
	b.StopTimer()
	require.Nil(b, proxyConn.Close())
	<-done
	echoConn.Close()
	echoRunning.Wait()
}
