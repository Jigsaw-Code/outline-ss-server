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

package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	"github.com/op/go-logging"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

type noopMap struct{}

func (*noopMap) GetIPInfo(ip net.IP) (ipinfo.IPInfo, error) {
	return ipinfo.IPInfo{}, nil
}

type fakeAddr string

func (a fakeAddr) String() string  { return string(a) }
func (a fakeAddr) Network() string { return "" }

// Sets the processing clock to be t until changed.
func setNow(t time.Time) {
	now = func() time.Time {
		return t
	}
}

func init() {
	logging.SetLevel(logging.INFO, "")
}

type fakeConn struct {
	net.Conn
}

func (c *fakeConn) LocalAddr() net.Addr {
	return fakeAddr("127.0.0.1:9")
}

func (c *fakeConn) RemoteAddr() net.Addr {
	return fakeAddr("127.0.0.1:10")
}

func TestMethodsDontPanic(t *testing.T) {
	ssMetrics, _ := newPrometheusOutlineMetrics(nil)
	proxyMetrics := metrics.ProxyMetrics{
		ClientProxy: 1,
		ProxyTarget: 2,
		TargetProxy: 3,
		ProxyClient: 4,
	}
	addr := fakeAddr("127.0.0.1:9")
	ssMetrics.SetBuildInfo("0.0.0-test")
	ssMetrics.SetNumAccessKeys(20, 2)

	tcpMetrics := ssMetrics.AddOpenTCPConnection(&fakeConn{})
	tcpMetrics.AddAuthenticated("0")
	tcpMetrics.AddClosed("OK", proxyMetrics, 10*time.Millisecond)
	tcpMetrics.AddProbe("ERR_CIPHER", "eof", proxyMetrics.ClientProxy)

	udpMetrics := ssMetrics.AddUDPNatEntry(addr, "key-1")
	udpMetrics.AddPacketFromClient("OK", 10, 20)
	udpMetrics.AddPacketFromTarget("OK", 10, 20)
	udpMetrics.RemoveNatEntry()

	ssMetrics.tcpServiceMetrics.AddCipherSearch(true, 10*time.Millisecond)
	ssMetrics.udpServiceMetrics.AddCipherSearch(true, 10*time.Millisecond)
}

func TestASNLabel(t *testing.T) {
	require.Equal(t, "", asnLabel(0))
	require.Equal(t, "100", asnLabel(100))
}

func TestTunnelTime(t *testing.T) {
	t.Run("PerKey", func(t *testing.T) {
		setNow(time.Date(2010, 1, 2, 3, 4, 5, .0, time.Local))
		ssMetrics, _ := newPrometheusOutlineMetrics(nil)
		reg := prometheus.NewPedanticRegistry()
		reg.MustRegister(ssMetrics)

		connMetrics := ssMetrics.AddOpenTCPConnection(&fakeConn{})
		connMetrics.AddAuthenticated("key-1")
		setNow(time.Date(2010, 1, 2, 3, 4, 20, .0, time.Local))

		expected := strings.NewReader(`
		# HELP tunnel_time_seconds Tunnel time, per access key.
		# TYPE tunnel_time_seconds counter
		tunnel_time_seconds{access_key="key-1"} 15
	`)
		err := promtest.GatherAndCompare(
			reg,
			expected,
			"tunnel_time_seconds",
		)
		require.NoError(t, err, "unexpected metric value found")
	})

	t.Run("PerLocation", func(t *testing.T) {
		setNow(time.Date(2010, 1, 2, 3, 4, 5, .0, time.Local))
		ssMetrics, _ := newPrometheusOutlineMetrics(&noopMap{})
		reg := prometheus.NewPedanticRegistry()
		reg.MustRegister(ssMetrics)

		connMetrics := ssMetrics.AddOpenTCPConnection(&fakeConn{})
		connMetrics.AddAuthenticated("key-1")
		setNow(time.Date(2010, 1, 2, 3, 4, 10, .0, time.Local))

		expected := strings.NewReader(`
		# HELP tunnel_time_seconds_per_location Tunnel time, per location.
		# TYPE tunnel_time_seconds_per_location counter
		tunnel_time_seconds_per_location{asn="",asorg="",location="XL"} 5
	`)
		err := promtest.GatherAndCompare(
			reg,
			expected,
			"tunnel_time_seconds_per_location",
		)
		require.NoError(t, err, "unexpected metric value found")
	})
}

func TestTunnelTimePerKeyDoesNotPanicOnUnknownClosedConnection(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	ssMetrics, _ := newPrometheusOutlineMetrics(nil)

	connMetrics := ssMetrics.AddOpenTCPConnection(&fakeConn{})
	connMetrics.AddClosed("OK", metrics.ProxyMetrics{}, time.Minute)

	err := promtest.GatherAndCompare(
		reg,
		strings.NewReader(""),
		"tunnel_time_seconds",
	)
	require.NoError(t, err, "unexpectedly found metric value")
}

func BenchmarkOpenTCP(b *testing.B) {
	ssMetrics, _ := newPrometheusOutlineMetrics(nil)
	conn := &fakeConn{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddOpenTCPConnection(conn)
	}
}

func BenchmarkCloseTCP(b *testing.B) {
	ssMetrics, _ := newPrometheusOutlineMetrics(nil)
	connMetrics := ssMetrics.AddOpenTCPConnection(&fakeConn{})
	accessKey := "key 1"
	status := "OK"
	data := metrics.ProxyMetrics{}
	duration := time.Minute
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		connMetrics.AddAuthenticated(accessKey)
		connMetrics.AddClosed(status, data, duration)
	}
}

func BenchmarkProbe(b *testing.B) {
	ssMetrics, _ := newPrometheusOutlineMetrics(nil)
	connMetrics := ssMetrics.AddOpenTCPConnection(&fakeConn{})
	status := "ERR_REPLAY"
	drainResult := "other"
	data := metrics.ProxyMetrics{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		connMetrics.AddProbe(status, drainResult, data.ClientProxy)
	}
}

func BenchmarkClientUDP(b *testing.B) {
	ssMetrics, _ := newPrometheusOutlineMetrics(nil)
	addr := fakeAddr("127.0.0.1:9")
	accessKey := "key 1"
	udpMetrics := ssMetrics.AddUDPNatEntry(addr, accessKey)
	status := "OK"
	size := int64(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		udpMetrics.AddPacketFromClient(status, size, size)
	}
}

func BenchmarkTargetUDP(b *testing.B) {
	ssMetrics, _ := newPrometheusOutlineMetrics(nil)
	addr := fakeAddr("127.0.0.1:9")
	accessKey := "key 1"
	udpMetrics := ssMetrics.AddUDPNatEntry(addr, accessKey)
	status := "OK"
	size := int64(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		udpMetrics.AddPacketFromTarget(status, size, size)
	}
}

func BenchmarkNAT(b *testing.B) {
	ssMetrics, _ := newPrometheusOutlineMetrics(nil)
	addr := fakeAddr("127.0.0.1:9")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		udpMetrics := ssMetrics.AddUDPNatEntry(addr, "key-0")
		udpMetrics.RemoveNatEntry()
	}
}
