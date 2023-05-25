package metrics

import (
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
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
	ssMetrics.AddOpenTCPConnection(ipinfo.IPInfo{CountryCode: "US"})
	ssMetrics.AddClosedTCPConnection(ipinfo.IPInfo{CountryCode: "US"}, "1", "OK", proxyMetrics, 10*time.Millisecond)
	ssMetrics.AddUDPPacketFromClient(ipinfo.IPInfo{CountryCode: "US"}, "2", "OK", 10, 20)
	ssMetrics.AddUDPPacketFromTarget(ipinfo.IPInfo{CountryCode: "US"}, "3", "OK", 10, 20)
	ssMetrics.AddUDPNatEntry()
	ssMetrics.RemoveUDPNatEntry()
	ssMetrics.AddTCPProbe("ERR_CIPHER", "eof", 443, proxyMetrics.ClientProxy)
	ssMetrics.AddTCPCipherSearch(true, 10*time.Millisecond)
	ssMetrics.AddUDPCipherSearch(true, 10*time.Millisecond)
}

func BenchmarkOpenTCP(b *testing.B) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddOpenTCPConnection(ipinfo.IPInfo{CountryCode: "ZZ"})
	}
}

func BenchmarkCloseTCP(b *testing.B) {
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	clientInfo := ipinfo.IPInfo{CountryCode: "ZZ"}
	accessKey := "key 1"
	status := "OK"
	data := ProxyMetrics{}
	timeToCipher := time.Microsecond
	duration := time.Minute
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddClosedTCPConnection(clientInfo, accessKey, status, data, duration)
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
	clientInfo := ipinfo.IPInfo{CountryCode: "ZZ"}
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
	ssMetrics := NewPrometheusShadowsocksMetrics(nil, prometheus.NewRegistry())
	clientInfo := ipinfo.IPInfo{CountryCode: "ZZ"}
	accessKey := "key 1"
	status := "OK"
	size := 1000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ssMetrics.AddUDPPacketFromTarget(clientInfo, accessKey, status, size, size)
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
