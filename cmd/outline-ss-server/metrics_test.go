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

func TestMethodsDontPanic(t *testing.T) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewPedanticRegistry())
	proxyMetrics := metrics.ProxyMetrics{
		ClientProxy: 1,
		ProxyTarget: 2,
		TargetProxy: 3,
		ProxyClient: 4,
	}
	ipInfo := ipinfo.IPInfo{CountryCode: "US", ASN: 100}
	ssMetrics.SetBuildInfo("0.0.0-test")
	ssMetrics.SetNumAccessKeys(20, 2)
	ssMetrics.AddOpenTCPConnection(ipInfo)
	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:9"), "0")
	ssMetrics.AddClosedTCPConnection(ipInfo, fakeAddr("127.0.0.1:9"), "1", "OK", proxyMetrics, 10*time.Millisecond)
	ssMetrics.AddUDPPacketFromClient(ipInfo, "2", "OK", 10, 20)
	ssMetrics.AddUDPPacketFromTarget(ipInfo, "3", "OK", 10, 20)
	ssMetrics.AddUDPNatEntry(fakeAddr("127.0.0.1:9"), "key-1")
	ssMetrics.RemoveUDPNatEntry(fakeAddr("127.0.0.1:9"), "key-1")
	ssMetrics.AddTCPProbe("ERR_CIPHER", "eof", 443, proxyMetrics.ClientProxy)
	ssMetrics.AddTCPCipherSearch(true, 10*time.Millisecond)
	ssMetrics.AddUDPCipherSearch(true, 10*time.Millisecond)
}

func TestASNLabel(t *testing.T) {
	require.Equal(t, "", asnLabel(0))
	require.Equal(t, "100", asnLabel(100))
}

func TestTunnelTimePerKey(t *testing.T) {
	setNow(time.Date(2010, 1, 2, 3, 4, 5, .0, time.Local))
	reg := prometheus.NewPedanticRegistry()
	ssMetrics := newPrometheusOutlineMetrics(nil, reg)

	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:9"), "key-1")
	setNow(time.Date(2010, 1, 2, 3, 4, 20, .0, time.Local))

	expected := strings.NewReader(`
	# HELP shadowsocks_tunnel_time_seconds Tunnel time, per access key.
	# TYPE shadowsocks_tunnel_time_seconds counter
	shadowsocks_tunnel_time_seconds{access_key="key-1"} 15
`)
	err := promtest.GatherAndCompare(
		reg,
		expected,
		"shadowsocks_tunnel_time_seconds",
	)
	require.NoError(t, err, "unexpected metric value found")
}

func TestTunnelTimePerLocation(t *testing.T) {
	setNow(time.Date(2010, 1, 2, 3, 4, 5, .0, time.Local))
	reg := prometheus.NewPedanticRegistry()
	ssMetrics := newPrometheusOutlineMetrics(&noopMap{}, reg)

	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:9"), "key-1")
	setNow(time.Date(2010, 1, 2, 3, 4, 10, .0, time.Local))

	expected := strings.NewReader(`
	# HELP shadowsocks_tunnel_time_seconds_per_location Tunnel time, per location.
	# TYPE shadowsocks_tunnel_time_seconds_per_location counter
	shadowsocks_tunnel_time_seconds_per_location{asn="",location="XL"} 5
`)
	err := promtest.GatherAndCompare(
		reg,
		expected,
		"shadowsocks_tunnel_time_seconds_per_location",
	)
	require.NoError(t, err, "unexpected metric value found")
}

func TestTunnelTimePerKeyDoesNotPanicOnUnknownClosedConnection(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	ssMetrics := newPrometheusOutlineMetrics(nil, reg)

	ssMetrics.AddClosedTCPConnection(ipinfo.IPInfo{}, fakeAddr("127.0.0.1:9"), "key-1", "OK", metrics.ProxyMetrics{}, time.Minute)

	err := promtest.GatherAndCompare(
		reg,
		strings.NewReader(""),
		"shadowsocks_tunnel_time_seconds",
	)
	require.NoError(t, err, "unexpectedly found metric value")
}

func BenchmarkOpenTCP(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry())
	ipinfo := ipinfo.IPInfo{CountryCode: "US", ASN: 100}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddOpenTCPConnection(ipinfo)
	}
}

func BenchmarkCloseTCP(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry())
	ipinfo := ipinfo.IPInfo{CountryCode: "US", ASN: 100}
	addr := fakeAddr("127.0.0.1:9")
	accessKey := "key 1"
	status := "OK"
	data := metrics.ProxyMetrics{}
	timeToCipher := time.Microsecond
	duration := time.Minute
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddClosedTCPConnection(ipinfo, addr, accessKey, status, data, duration)
		ssMetrics.AddTCPCipherSearch(true, timeToCipher)
	}
}

func BenchmarkProbe(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry())
	status := "ERR_REPLAY"
	drainResult := "other"
	port := 12345
	data := metrics.ProxyMetrics{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddTCPProbe(status, drainResult, port, data.ClientProxy)
	}
}

func BenchmarkClientUDP(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry())
	clientInfo := ipinfo.IPInfo{CountryCode: "ZZ", ASN: 100}
	accessKey := "key 1"
	status := "OK"
	size := 1000
	timeToCipher := time.Microsecond
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddUDPPacketFromClient(clientInfo, accessKey, status, size, size)
		ssMetrics.AddUDPCipherSearch(true, timeToCipher)
	}
}

func BenchmarkTargetUDP(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry())
	clientInfo := ipinfo.IPInfo{CountryCode: "ZZ", ASN: 100}
	accessKey := "key 1"
	status := "OK"
	size := 1000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddUDPPacketFromTarget(clientInfo, accessKey, status, size, size)
	}
}

func BenchmarkNAT(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddUDPNatEntry(fakeAddr("127.0.0.1:9"), "key-0")
		ssMetrics.RemoveUDPNatEntry(fakeAddr("127.0.0.1:9"), "key-0")
	}
}
