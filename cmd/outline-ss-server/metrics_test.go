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

func TestMethodsDontPanic(t *testing.T) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewPedanticRegistry(), true)
	proxyMetrics := metrics.ProxyMetrics{
		ClientProxy: 1,
		ProxyTarget: 2,
		TargetProxy: 3,
		ProxyClient: 4,
	}
	ssMetrics.SetBuildInfo("0.0.0-test")
	ssMetrics.SetNumAccessKeys(20, 2)
	ssMetrics.AddOpenTCPConnection(fakeAddr("127.0.0.1:9"))
	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:9"), "key-1")
	ssMetrics.AddClosedTCPConnection(fakeAddr("127.0.0.1:9"), "1", "OK", proxyMetrics, 10*time.Millisecond)
	ssMetrics.AddUDPPacketFromClient(ipinfo.IPInfo{CountryCode: "US", ASN: 100}, "2", "OK", 10, 20)
	ssMetrics.AddUDPPacketFromTarget(ipinfo.IPInfo{CountryCode: "US", ASN: 100}, "3", "OK", 10, 20)
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

func TestIPKeyActivityPerKeyDoesNotReportUnlessAllConnectionsClosed(t *testing.T) {
	since = func(time.Time) time.Duration { return 3 * time.Second }
	reg := prometheus.NewPedanticRegistry()
	ssMetrics := newPrometheusOutlineMetrics(nil, reg, true)
	accessKey := "key-1"
	status := "OK"
	data := metrics.ProxyMetrics{}
	duration := time.Minute

	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:9"), accessKey)
	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:1"), accessKey)
	ssMetrics.AddClosedTCPConnection(fakeAddr("127.0.0.1:9"), accessKey, status, data, duration)

	err := promtest.GatherAndCompare(
		reg,
		strings.NewReader(""),
		"shadowsocks_ip_key_connectivity_seconds",
	)
	require.NoError(t, err, "unexpectedly found metric value")
}

func TestIPKeyActivityPerKey(t *testing.T) {
	since = func(time.Time) time.Duration { return 3 * time.Second }
	reg := prometheus.NewPedanticRegistry()
	ssMetrics := newPrometheusOutlineMetrics(nil, reg, true)
	accessKey := "key-1"
	status := "OK"
	data := metrics.ProxyMetrics{}
	duration := time.Minute

	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:9"), accessKey)
	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:1"), accessKey)
	ssMetrics.AddClosedTCPConnection(fakeAddr("127.0.0.1:9"), accessKey, status, data, duration)
	ssMetrics.AddClosedTCPConnection(fakeAddr("127.0.0.1:1"), accessKey, status, data, duration)

	expected := strings.NewReader(`
	# HELP shadowsocks_ip_key_connectivity_seconds Time at least 1 connection was open for a (IP, access key) pair, per key
	# TYPE shadowsocks_ip_key_connectivity_seconds counter
	shadowsocks_ip_key_connectivity_seconds{access_key="key-1"} 3
`)
	err := promtest.GatherAndCompare(
		reg,
		expected,
		"shadowsocks_ip_key_connectivity_seconds",
	)
	require.NoError(t, err, "unexpected metric value found")
}

func TestIPKeyActivityPerLocation(t *testing.T) {
	since = func(time.Time) time.Duration { return 5 * time.Second }
	reg := prometheus.NewPedanticRegistry()
	ssMetrics := newPrometheusOutlineMetrics(&noopMap{}, reg, true)
	accessKey := "key-1"
	status := "OK"
	data := metrics.ProxyMetrics{}
	duration := time.Minute

	ssMetrics.AddAuthenticatedTCPConnection(fakeAddr("127.0.0.1:9"), accessKey)
	ssMetrics.AddClosedTCPConnection(fakeAddr("127.0.0.1:9"), accessKey, status, data, duration)

	expected := strings.NewReader(`
	# HELP shadowsocks_ip_key_connectivity_seconds_per_location Time at least 1 connection was open for a (IP, access key) pair, per location
	# TYPE shadowsocks_ip_key_connectivity_seconds_per_location counter
	shadowsocks_ip_key_connectivity_seconds_per_location{asn="",location="XL"} 5
`)
	err := promtest.GatherAndCompare(
		reg,
		expected,
		"shadowsocks_ip_key_connectivity_seconds_per_location",
	)
	require.NoError(t, err, "unexpected metric value found")
}

func BenchmarkOpenTCP(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry(), false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddOpenTCPConnection(fakeAddr("127.0.0.1:9"))
	}
}

func BenchmarkCloseTCP(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry(), false)
	addr := fakeAddr("127.0.0.1:9")
	accessKey := "key 1"
	status := "OK"
	data := metrics.ProxyMetrics{}
	timeToCipher := time.Microsecond
	duration := time.Minute
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddClosedTCPConnection(addr, accessKey, status, data, duration)
		ssMetrics.AddTCPCipherSearch(true, timeToCipher)
	}
}

func BenchmarkProbe(b *testing.B) {
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry(), false)
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
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry(), false)
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
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry(), false)
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
	ssMetrics := newPrometheusOutlineMetrics(nil, prometheus.NewRegistry(), false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddUDPNatEntry(fakeAddr("127.0.0.1:9"), "key-0")
		ssMetrics.RemoveUDPNatEntry(fakeAddr("127.0.0.1:9"), "key-0")
	}
}
