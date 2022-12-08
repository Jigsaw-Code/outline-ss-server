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
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/client"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	logging "github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const maxUDPPacketSize = 64 * 1024

func init() {
	logging.SetLevel(logging.INFO, "")
}

func allowAll(ip net.IP) *onet.ConnectionError {
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
	secrets := ss.MakeTestSecrets(1)
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		t.Fatal(err)
	}
	replayCache := service.NewReplayCache(5)
	const testTimeout = 200 * time.Millisecond
	proxy := service.NewTCPService(cipherList, &replayCache, &metrics.NoOpMetrics{}, testTimeout)
	proxy.SetTargetIPValidator(allowAll)
	go proxy.Serve(proxyListener)

	proxyHost, proxyPort, err := net.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		t.Fatal(err)
	}
	client, err := client.NewClient(proxyHost, portNum, secrets[0], ss.TestCipher)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := client.DialTCP(nil, echoListener.Addr().String())
	if err != nil {
		t.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
	}

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
	proxy.Stop()
	echoListener.Close()
	echoRunning.Wait()
}

type statusMetrics struct {
	metrics.NoOpMetrics
	sync.Mutex
	statuses []string
}

func (m *statusMetrics) AddClosedTCPConnection(clientLocation, accessKey, status string, data metrics.ProxyMetrics, timeToCipher, duration time.Duration) {
	m.Lock()
	m.statuses = append(m.statuses, status)
	m.Unlock()
}

func TestRestrictedAddresses(t *testing.T) {
	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err, "ListenTCP failed: %v", err)
	secrets := ss.MakeTestSecrets(1)
	cipherList, err := service.MakeTestCiphers(secrets)
	require.NoError(t, err)
	const testTimeout = 200 * time.Millisecond
	testMetrics := &statusMetrics{}
	proxy := service.NewTCPService(cipherList, nil, testMetrics, testTimeout)
	go proxy.Serve(proxyListener)

	proxyHost, proxyPort, err := net.SplitHostPort(proxyListener.Addr().String())
	require.NoError(t, err)
	portNum, err := strconv.Atoi(proxyPort)
	require.NoError(t, err)
	client, err := client.NewClient(proxyHost, portNum, secrets[0], ss.TestCipher)
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
		conn, err := client.DialTCP(nil, address)
		require.NoError(t, err, "Failed to dial %v", address)
		n, err := conn.Read(buf)
		assert.Equal(t, 0, n, "Server should close without replying on rejected address")
		assert.Equal(t, io.EOF, err)
		conn.Close()
	}

	proxy.GracefulStop()
	assert.ElementsMatch(t, testMetrics.statuses, expectedStatus)
}

// Metrics about one UDP packet.
type udpRecord struct {
	location, accessKey, status string
	in, out                     int
}

// Fake metrics implementation for UDP
type fakeUDPMetrics struct {
	metrics.ShadowsocksMetrics
	fakeLocation string
	up, down     []udpRecord
	natAdded     int
}

func (m *fakeUDPMetrics) GetLocation(addr net.Addr) (string, error) {
	return m.fakeLocation, nil
}
func (m *fakeUDPMetrics) AddUDPPacketFromClient(clientLocation, accessKey, status string, clientProxyBytes, proxyTargetBytes int, timeToCipher time.Duration) {
	m.up = append(m.up, udpRecord{clientLocation, accessKey, status, clientProxyBytes, proxyTargetBytes})
}
func (m *fakeUDPMetrics) AddUDPPacketFromTarget(clientLocation, accessKey, status string, targetProxyBytes, proxyClientBytes int) {
	m.down = append(m.down, udpRecord{clientLocation, accessKey, status, targetProxyBytes, proxyClientBytes})
}
func (m *fakeUDPMetrics) AddUDPNatEntry() {
	m.natAdded++
}
func (m *fakeUDPMetrics) RemoveUDPNatEntry() {
	// Not tested because it requires waiting for a long timeout.
}

func TestUDPEcho(t *testing.T) {
	echoConn, echoRunning := startUDPEchoServer(t)

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP failed: %v", err)
	}
	secrets := ss.MakeTestSecrets(1)
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		t.Fatal(err)
	}
	testMetrics := &fakeUDPMetrics{fakeLocation: "QQ"}
	proxy := service.NewUDPService(time.Hour, cipherList, testMetrics)
	proxy.SetTargetIPValidator(allowAll)
	go proxy.Serve(proxyConn)

	proxyHost, proxyPort, err := net.SplitHostPort(proxyConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		t.Fatal(err)
	}
	client, err := client.NewClient(proxyHost, portNum, secrets[0], ss.TestCipher)
	if err != nil {
		t.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := client.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ShadowsocksClient.ListenUDP failed: %v", err)
	}

	const N = 1000
	up := ss.MakeTestPayload(N)
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
	proxy.GracefulStop()
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
		if record.location != "QQ" ||
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
		if record.location != "QQ" ||
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
	secrets := ss.MakeTestSecrets(1)
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		b.Fatal(err)
	}
	const testTimeout = 200 * time.Millisecond
	proxy := service.NewTCPService(cipherList, nil, &metrics.NoOpMetrics{}, testTimeout)
	proxy.SetTargetIPValidator(allowAll)
	go proxy.Serve(proxyListener)

	proxyHost, proxyPort, err := net.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		b.Fatal(err)
	}
	client, err := client.NewClient(proxyHost, portNum, secrets[0], ss.TestCipher)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := client.DialTCP(nil, echoListener.Addr().String())
	if err != nil {
		b.Fatalf("ShadowsocksClient.DialTCP failed: %v", err)
	}

	const N = 1000
	up := ss.MakeTestPayload(N)
	down := make([]byte, N)

	start := time.Now()
	b.ResetTimer()
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		for i := 0; i < b.N; i++ {
			conn.Write(up)
		}
		running.Done()
	}()

	for i := 0; i < b.N; i++ {
		conn.Read(down)
	}
	b.StopTimer()
	elapsed := time.Now().Sub(start)

	megabits := float64(8*1000*b.N) / 1e6
	b.ReportMetric(megabits/elapsed.Seconds(), "mbps")

	conn.Close()
	proxy.Stop()
	echoListener.Close()
	running.Wait()
	echoRunning.Wait()
}

func BenchmarkTCPMultiplexing(b *testing.B) {
	echoListener, echoRunning := startTCPEchoServer(b)

	proxyListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	const numKeys = 50
	secrets := ss.MakeTestSecrets(numKeys)
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		b.Fatal(err)
	}
	replayCache := service.NewReplayCache(service.MaxCapacity)
	const testTimeout = 200 * time.Millisecond
	proxy := service.NewTCPService(cipherList, &replayCache, &metrics.NoOpMetrics{}, testTimeout)
	proxy.SetTargetIPValidator(allowAll)
	go proxy.Serve(proxyListener)

	proxyHost, proxyPort, err := net.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		b.Fatal(err)
	}

	var clients [numKeys]client.Client
	for i := 0; i < numKeys; i++ {
		clients[i], err = client.NewClient(proxyHost, portNum, secrets[i], ss.TestCipher)
		if err != nil {
			b.Fatalf("Failed to create ShadowsocksClient: %v", err)
		}
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
				conn, err := client.DialTCP(nil, echoListener.Addr().String())
				if err != nil {
					b.Errorf("ShadowsocksClient.DialTCP failed: %v", err)
				}

				const N = 1000
				buf := make([]byte, N)
				n, err := conn.Write(buf)
				if n != N {
					b.Errorf("Tried to upload %d bytes, but only sent %d", N, n)
				}
				n, err = conn.Read(buf)
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

	proxy.Stop()
	echoListener.Close()
	echoRunning.Wait()
}

func BenchmarkUDPEcho(b *testing.B) {
	echoConn, echoRunning := startUDPEchoServer(b)

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}
	secrets := ss.MakeTestSecrets(1)
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		b.Fatal(err)
	}
	proxy := service.NewUDPService(time.Hour, cipherList, &metrics.NoOpMetrics{})
	proxy.SetTargetIPValidator(allowAll)
	go proxy.Serve(proxyConn)

	proxyHost, proxyPort, err := net.SplitHostPort(proxyConn.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		b.Fatal(err)
	}
	client, err := client.NewClient(proxyHost, portNum, secrets[0], ss.TestCipher)
	if err != nil {
		b.Fatalf("Failed to create ShadowsocksClient: %v", err)
	}
	conn, err := client.ListenUDP(nil)
	if err != nil {
		b.Fatalf("ShadowsocksClient.ListenUDP failed: %v", err)
	}

	const N = 1000
	buf := make([]byte, N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.WriteTo(buf, echoConn.LocalAddr())
		conn.ReadFrom(buf)
	}
	b.StopTimer()

	conn.Close()
	proxy.Stop()
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
	secrets := ss.MakeTestSecrets(numKeys)
	cipherList, err := service.MakeTestCiphers(secrets)
	if err != nil {
		b.Fatal(err)
	}
	proxy := service.NewUDPService(time.Hour, cipherList, &metrics.NoOpMetrics{})
	proxy.SetTargetIPValidator(allowAll)
	go proxy.Serve(proxyConn)

	proxyHost, proxyPort, err := net.SplitHostPort(proxyConn.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	portNum, err := strconv.Atoi(proxyPort)
	if err != nil {
		b.Fatal(err)
	}
	var clients [numKeys]client.Client
	for i := 0; i < numKeys; i++ {
		clients[i], err = client.NewClient(proxyHost, portNum, secrets[i], ss.TestCipher)
		if err != nil {
			b.Fatalf("Failed to create ShadowsocksClient: %v", err)
		}
	}

	const N = 1000
	buf := make([]byte, N)
	conns := make([]net.PacketConn, len(clients))
	for i, client := range clients {
		conns[i], _ = client.ListenUDP(nil)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := conns[i%numKeys]
		conn.WriteTo(buf, echoConn.LocalAddr())
		conn.ReadFrom(buf)
	}
	b.StopTimer()
	proxy.Stop()
	echoConn.Close()
	echoRunning.Wait()
}
