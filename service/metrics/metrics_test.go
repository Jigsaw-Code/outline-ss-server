package metrics

import (
	"net"
	"testing"
	"time"

	geoip2 "github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMethodsDontPanic(t *testing.T) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewPedanticRegistry())
	proxyMetrics := ProxyMetrics{
		ClientProxy: 1,
		ProxyTarget: 2,
		TargetProxy: 3,
		ProxyClient: 4,
	}
	ssMetrics.SetBuildInfo("0.0.0-test")
	ssMetrics.SetNumAccessKeys(20, 2)
	ssMetrics.AddOpenTCPConnection("US")
	ssMetrics.AddClosedTCPConnection("US", "1", "OK", proxyMetrics, 10*time.Millisecond)
	ssMetrics.AddUDPPacketFromClient("US", "2", "OK", 10, 20)
	ssMetrics.AddUDPPacketFromTarget("US", "3", "OK", 10, 20)
	ssMetrics.AddUDPNatEntry()
	ssMetrics.RemoveUDPNatEntry()
	ssMetrics.AddTCPProbe("ERR_CIPHER", "eof", 443, proxyMetrics.ClientProxy)
	ssMetrics.AddTCPCipherSearch(true, 10*time.Millisecond)
	ssMetrics.AddUDPCipherSearch(true, 10*time.Millisecond)
}

func BenchmarkGetLocation(b *testing.B) {
	var ipCountryDB *geoip2.Reader
	// The test data is in a git submodule that must be initialized before running the test.
	dbPath := "../../third_party/maxmind/test-data/GeoIP2-Country-Test.mmdb"
	ipCountryDB, err := geoip2.Open(dbPath)
	if err != nil {
		b.Fatalf("Could not open geoip database at %v: %v", dbPath, err)
	}
	defer ipCountryDB.Close()

	ssMetrics := NewPrometheusShadowsocksMetrics(ipCountryDB, prometheus.NewRegistry())
	testIP := net.ParseIP("217.65.48.1")
	testAddr := &net.TCPAddr{IP: testIP, Port: 12345}
	b.ResetTimer()
	// Repeatedly check the country for the same address.  This is realistic, because
	// servers call this method for each new connection, but typically many connections
	// come from a single user in succession.
	for i := 0; i < b.N; i++ {
		ssMetrics.GetLocation(testAddr)
	}
}

func BenchmarkOpenTCP(b *testing.B) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddOpenTCPConnection("ZZ")
	}
}

func BenchmarkCloseTCP(b *testing.B) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	clientLocation := CountryCode("ZZ")
	accessKey := "key 1"
	status := "OK"
	data := ProxyMetrics{}
	timeToCipher := time.Microsecond
	duration := time.Minute
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddClosedTCPConnection(clientLocation, accessKey, status, data, duration)
		ssMetrics.AddTCPCipherSearch(true, timeToCipher)
	}
}

func BenchmarkProbe(b *testing.B) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	status := "ERR_REPLAY"
	drainResult := "other"
	port := 12345
	data := ProxyMetrics{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddTCPProbe(status, drainResult, port, data.ClientProxy)
	}
}

func BenchmarkClientUDP(b *testing.B) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	clientLocation := CountryCode("ZZ")
	accessKey := "key 1"
	status := "OK"
	size := 1000
	timeToCipher := time.Microsecond
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddUDPPacketFromClient(clientLocation, accessKey, status, size, size)
		ssMetrics.AddUDPCipherSearch(true, timeToCipher)
	}
}

func BenchmarkTargetUDP(b *testing.B) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	clientLocation := CountryCode("ZZ")
	accessKey := "key 1"
	status := "OK"
	size := 1000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddUDPPacketFromTarget(clientLocation, accessKey, status, size, size)
	}
}

func BenchmarkNAT(b *testing.B) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddUDPNatEntry()
		ssMetrics.RemoveUDPNatEntry()
	}
}
