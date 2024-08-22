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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// `now` is stubbable for testing.
var now = time.Now

func NewTimeToCipherVec(proto string) (prometheus.ObserverVec, error) {
	vec := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "time_to_cipher_ms",
			Help:    "Time needed to find the cipher",
			Buckets: []float64{0.1, 1, 10, 100, 1000},
		}, []string{"proto", "found_key"})
	return vec.CurryWith(map[string]string{"proto": proto})
}

type proxyCollector struct {
	// NOTE: New metrics need to be added to `newProxyCollector()`, `Describe()` and `Collect()`.
	dataBytesPerKey      *prometheus.CounterVec
	dataBytesPerLocation *prometheus.CounterVec
}

func newProxyCollector(proto string) (*proxyCollector, error) {
	dataBytesPerKey, err := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "data_bytes",
			Help: "Bytes transferred by the proxy, per access key",
		}, []string{"proto", "dir", "access_key"}).CurryWith(map[string]string{"proto": proto})
	if err != nil {
		return nil, err
	}
	dataBytesPerLocation, err := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "data_bytes_per_location",
			Help: "Bytes transferred by the proxy, per location",
		}, []string{"proto", "dir", "location", "asn"}).CurryWith(map[string]string{"proto": proto})
	if err != nil {
		return nil, err
	}
	return &proxyCollector{
		dataBytesPerKey:      dataBytesPerKey,
		dataBytesPerLocation: dataBytesPerLocation,
	}, nil
}

func (c *proxyCollector) Describe(ch chan<- *prometheus.Desc) {
	c.dataBytesPerKey.Describe(ch)
	c.dataBytesPerLocation.Describe(ch)
}

func (c *proxyCollector) Collect(ch chan<- prometheus.Metric) {
	c.dataBytesPerKey.Collect(ch)
	c.dataBytesPerLocation.Collect(ch)
}

func (c *proxyCollector) addOutbound(clientProxyBytes, proxyTargetBytes int64, accessKey string, clientInfo ipinfo.IPInfo) {
	addIfNonZero(clientProxyBytes, c.dataBytesPerKey, "c>p", accessKey)
	addIfNonZero(clientProxyBytes, c.dataBytesPerLocation, "c>p", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(proxyTargetBytes, c.dataBytesPerKey, "p>t", accessKey)
	addIfNonZero(proxyTargetBytes, c.dataBytesPerLocation, "p>t", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
}

func (c *proxyCollector) addInbound(targetProxyBytes, proxyClientBytes int64, accessKey string, clientInfo ipinfo.IPInfo) {
	addIfNonZero(targetProxyBytes, c.dataBytesPerKey, "p<t", accessKey)
	addIfNonZero(targetProxyBytes, c.dataBytesPerLocation, "p<t", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(proxyClientBytes, c.dataBytesPerKey, "c<p", accessKey)
	addIfNonZero(proxyClientBytes, c.dataBytesPerLocation, "c<p", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
}

type tcpConnMetrics struct {
	tcpCollector        *tcpCollector
	tunnelTimeCollector *tunnelTimeCollector

	localAddr  net.Addr
	clientAddr net.Addr
	clientInfo ipinfo.IPInfo
}

var _ service.TCPConnMetrics = (*tcpConnMetrics)(nil)

func newTCPConnMetrics(tcpCollector *tcpCollector, tunnelTimeCollector *tunnelTimeCollector, clientConn net.Conn, clientInfo ipinfo.IPInfo) *tcpConnMetrics {
	tcpCollector.openConnection(clientInfo)
	return &tcpConnMetrics{
		tcpCollector:        tcpCollector,
		tunnelTimeCollector: tunnelTimeCollector,
		localAddr:           clientConn.LocalAddr(),
		clientAddr:          clientConn.RemoteAddr(),
		clientInfo:          clientInfo,
	}
}

func (cm *tcpConnMetrics) AddAuthenticated(accessKey string) {
	ipKey, err := toIPKey(cm.clientAddr, accessKey)
	if err == nil {
		cm.tunnelTimeCollector.startConnection(*ipKey)
	}
}

func (cm *tcpConnMetrics) AddClosed(accessKey string, status string, data metrics.ProxyMetrics, duration time.Duration) {
	cm.tcpCollector.proxyCollector.addOutbound(data.ClientProxy, data.ProxyTarget, accessKey, cm.clientInfo)
	cm.tcpCollector.proxyCollector.addInbound(data.TargetProxy, data.ProxyClient, accessKey, cm.clientInfo)
	cm.tcpCollector.closeConnection(status, duration, accessKey, cm.clientInfo)
	ipKey, err := toIPKey(cm.clientAddr, accessKey)
	if err == nil {
		cm.tunnelTimeCollector.stopConnection(*ipKey)
	}
}

func (cm *tcpConnMetrics) AddProbe(status, drainResult string, clientProxyBytes int64) {
	cm.tcpCollector.addProbe(cm.localAddr.String(), status, drainResult, clientProxyBytes)
}

type tcpCollector struct {
	proxyCollector *proxyCollector
	// NOTE: New metrics need to be added to `newTCPCollector()`, `Describe()` and `Collect()`.
	probes               *prometheus.HistogramVec
	openConnections      *prometheus.CounterVec
	closedConnections    *prometheus.CounterVec
	connectionDurationMs *prometheus.HistogramVec
	timeToCipherMs       prometheus.ObserverVec
}

var _ prometheus.Collector = (*tcpCollector)(nil)
var _ service.ShadowsocksConnMetrics = (*tcpCollector)(nil)

func newTCPCollector() (*tcpCollector, error) {
	namespace := "tcp"
	proxyCollector, err := newProxyCollector(namespace)
	if err != nil {
		return nil, err
	}
	timeToCipherVec, err := NewTimeToCipherVec(namespace)
	if err != nil {
		return nil, err
	}
	return &tcpCollector{
		proxyCollector: proxyCollector,
		timeToCipherMs: timeToCipherVec,
		probes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "probes",
			Buckets:   []float64{0, 49, 50, 51, 73, 91},
			Help:      "Histogram of number of bytes from client to proxy, for detecting possible probes",
		}, []string{"port", "status", "error"}),
		openConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "connections_opened",
			Help:      "Count of open TCP connections",
		}, []string{"location", "asn"}),
		closedConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "connections_closed",
			Help:      "Count of closed TCP connections",
		}, []string{"location", "asn", "status", "access_key"}),
		connectionDurationMs: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "connection_duration_ms",
				Help:      "TCP connection duration distributions.",
				Buckets: []float64{
					100,
					float64(time.Second.Milliseconds()),
					float64(time.Minute.Milliseconds()),
					float64(time.Hour.Milliseconds()),
					float64(24 * time.Hour.Milliseconds()),     // Day
					float64(7 * 24 * time.Hour.Milliseconds()), // Week
				},
			}, []string{"status"}),
	}, nil
}

func (c *tcpCollector) Describe(ch chan<- *prometheus.Desc) {
	c.proxyCollector.Describe(ch)
	c.timeToCipherMs.Describe(ch)
	c.probes.Describe(ch)
	c.openConnections.Describe(ch)
	c.closedConnections.Describe(ch)
	c.connectionDurationMs.Describe(ch)
}

func (c *tcpCollector) Collect(ch chan<- prometheus.Metric) {
	c.proxyCollector.Collect(ch)
	c.timeToCipherMs.Collect(ch)
	c.probes.Collect(ch)
	c.openConnections.Collect(ch)
	c.closedConnections.Collect(ch)
	c.connectionDurationMs.Collect(ch)
}

func (c *tcpCollector) openConnection(clientInfo ipinfo.IPInfo) {
	c.openConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN)).Inc()
}

func (c *tcpCollector) closeConnection(status string, duration time.Duration, accessKey string, clientInfo ipinfo.IPInfo) {
	c.closedConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN), status, accessKey).Inc()
	c.connectionDurationMs.WithLabelValues(status).Observe(duration.Seconds() * 1000)
}

func (c *tcpCollector) addProbe(listenerId, status, drainResult string, clientProxyBytes int64) {
	c.probes.WithLabelValues(listenerId, status, drainResult).Observe(float64(clientProxyBytes))
}

func (c *tcpCollector) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	foundStr := "false"
	if accessKeyFound {
		foundStr = "true"
	}
	c.timeToCipherMs.WithLabelValues(foundStr).Observe(timeToCipher.Seconds() * 1000)
}

type udpConnMetrics struct {
	udpCollector        *udpCollector
	tunnelTimeCollector *tunnelTimeCollector

	clientAddr net.Addr
	clientInfo ipinfo.IPInfo
	accessKey  string
}

var _ service.UDPConnMetrics = (*udpConnMetrics)(nil)

func newUDPConnMetrics(udpCollector *udpCollector, tunnelTimeCollector *tunnelTimeCollector, accessKey string, clientAddr net.Addr, clientInfo ipinfo.IPInfo) *udpConnMetrics {
	udpCollector.addNatEntry()
	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		tunnelTimeCollector.startConnection(*ipKey)
	}
	return &udpConnMetrics{
		udpCollector:        udpCollector,
		tunnelTimeCollector: tunnelTimeCollector,
		accessKey:           accessKey,
		clientAddr:          clientAddr,
		clientInfo:          clientInfo,
	}
}

func (cm *udpConnMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int) {
	cm.udpCollector.addPacketFromClient(status, int64(clientProxyBytes), int64(proxyTargetBytes), cm.accessKey, cm.clientInfo)
}

func (cm *udpConnMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int) {
	cm.udpCollector.addPacketFromTarget(status, int64(targetProxyBytes), int64(proxyClientBytes), cm.accessKey, cm.clientInfo)
}

func (cm *udpConnMetrics) RemoveNatEntry() {
	cm.udpCollector.removeNatEntry()

	ipKey, err := toIPKey(cm.clientAddr, cm.accessKey)
	if err == nil {
		cm.tunnelTimeCollector.stopConnection(*ipKey)
	}
}

type udpCollector struct {
	proxyCollector *proxyCollector
	// NOTE: New metrics need to be added to `newUDPCollector()`, `Describe()` and `Collect()`.
	packetsFromClientPerLocation *prometheus.CounterVec
	addedNatEntries              prometheus.Counter
	removedNatEntries            prometheus.Counter
	timeToCipherMs               prometheus.ObserverVec
}

var _ prometheus.Collector = (*udpCollector)(nil)
var _ service.ShadowsocksConnMetrics = (*tcpCollector)(nil)

func newUDPCollector() (*udpCollector, error) {
	namespace := "udp"
	proxyCollector, err := newProxyCollector(namespace)
	if err != nil {
		return nil, err
	}
	timeToCipherVec, err := NewTimeToCipherVec(namespace)
	if err != nil {
		return nil, err
	}
	return &udpCollector{
		proxyCollector: proxyCollector,
		timeToCipherMs: timeToCipherVec,
		packetsFromClientPerLocation: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "packets_from_client_per_location",
				Help:      "Packets received from the client, per location and status",
			}, []string{"location", "asn", "status"}),
		addedNatEntries: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "nat_entries_added",
				Help:      "Entries added to the UDP NAT table",
			}),
		removedNatEntries: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "nat_entries_removed",
				Help:      "Entries removed from the UDP NAT table",
			}),
	}, nil
}

func (c *udpCollector) Describe(ch chan<- *prometheus.Desc) {
	c.proxyCollector.Describe(ch)
	c.timeToCipherMs.Describe(ch)
	c.packetsFromClientPerLocation.Describe(ch)
	c.addedNatEntries.Describe(ch)
	c.removedNatEntries.Describe(ch)
}

func (c *udpCollector) Collect(ch chan<- prometheus.Metric) {
	c.proxyCollector.Collect(ch)
	c.timeToCipherMs.Collect(ch)
	c.packetsFromClientPerLocation.Collect(ch)
	c.addedNatEntries.Collect(ch)
	c.removedNatEntries.Collect(ch)
}

func (c *udpCollector) addNatEntry() {
	c.addedNatEntries.Inc()
}

func (c *udpCollector) removeNatEntry() {
	c.removedNatEntries.Inc()
}

func (c *udpCollector) addPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64, accessKey string, clientInfo ipinfo.IPInfo) {
	c.packetsFromClientPerLocation.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN), status).Inc()
	c.proxyCollector.addOutbound(clientProxyBytes, proxyTargetBytes, accessKey, clientInfo)
}

func (c *udpCollector) addPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64, accessKey string, clientInfo ipinfo.IPInfo) {
	c.proxyCollector.addInbound(targetProxyBytes, proxyClientBytes, accessKey, clientInfo)
}

func (c *udpCollector) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	foundStr := "false"
	if accessKeyFound {
		foundStr = "true"
	}
	c.timeToCipherMs.WithLabelValues(foundStr).Observe(timeToCipher.Seconds() * 1000)
}

// Represents the clients that are or have been active recently. They stick
// around until they are inactive, or get reported to Prometheus, whichever
// comes last.
type activeClient struct {
	info      ipinfo.IPInfo
	connCount int // The active connection count.
	startTime time.Time
}

type IPKey struct {
	ip        netip.Addr
	accessKey string
}

type tunnelTimeCollector struct {
	ip2info       ipinfo.IPInfoMap
	mu            sync.Mutex // Protects the activeClients map.
	activeClients map[IPKey]*activeClient

	// NOTE: New metrics need to be added to `newTunnelTimeCollector()`, `Describe()` and `Collect()`.
	tunnelTimePerKey      *prometheus.CounterVec
	tunnelTimePerLocation *prometheus.CounterVec
}

var _ prometheus.Collector = (*tunnelTimeCollector)(nil)

func newTunnelTimeCollector(ip2info ipinfo.IPInfoMap) *tunnelTimeCollector {
	namespace := "tunnel_time"
	return &tunnelTimeCollector{
		ip2info:       ip2info,
		activeClients: make(map[IPKey]*activeClient),

		tunnelTimePerKey: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "seconds",
			Help:      "Tunnel time, per access key.",
		}, []string{"access_key"}),
		tunnelTimePerLocation: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "seconds_per_location",
			Help:      "Tunnel time, per location.",
		}, []string{"location", "asn"}),
	}
}

func (c *tunnelTimeCollector) Describe(ch chan<- *prometheus.Desc) {
	c.tunnelTimePerKey.Describe(ch)
	c.tunnelTimePerLocation.Describe(ch)
}

func (c *tunnelTimeCollector) Collect(ch chan<- prometheus.Metric) {
	tNow := now()
	c.mu.Lock()
	for ipKey, client := range c.activeClients {
		c.reportTunnelTime(ipKey, client, tNow)
	}
	c.mu.Unlock()
	c.tunnelTimePerKey.Collect(ch)
	c.tunnelTimePerLocation.Collect(ch)
}

// Calculates and reports the tunnel time for a given active client.
func (c *tunnelTimeCollector) reportTunnelTime(ipKey IPKey, client *activeClient, tNow time.Time) {
	tunnelTime := tNow.Sub(client.startTime)
	slog.LogAttrs(nil, slog.LevelDebug, "Reporting tunnel time.", slog.String("key", ipKey.accessKey), slog.Duration("duration", tunnelTime))
	c.tunnelTimePerKey.WithLabelValues(ipKey.accessKey).Add(tunnelTime.Seconds())
	c.tunnelTimePerLocation.WithLabelValues(client.info.CountryCode.String(), asnLabel(client.info.ASN)).Add(tunnelTime.Seconds())
	// Reset the start time now that the tunnel time has been reported.
	client.startTime = tNow
}

// Registers a new active connection for a client [net.Addr] and access key.
func (c *tunnelTimeCollector) startConnection(ipKey IPKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	client, exists := c.activeClients[ipKey]
	if !exists {
		clientInfo, _ := ipinfo.GetIPInfoFromIP(c.ip2info, net.IP(ipKey.ip.AsSlice()))
		client = &activeClient{info: clientInfo, startTime: now()}
		c.activeClients[ipKey] = client
	}
	client.connCount++
}

// Removes an active connection for a client [net.Addr] and access key.
func (c *tunnelTimeCollector) stopConnection(ipKey IPKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	client, exists := c.activeClients[ipKey]
	if !exists {
		slog.Warn("Failed to find active client.")
		return
	}
	client.connCount--
	if client.connCount <= 0 {
		c.reportTunnelTime(ipKey, client, now())
		delete(c.activeClients, ipKey)
	}
}

type outlineMetricsCollector struct {
	ip2info ipinfo.IPInfoMap

	tcpCollector        *tcpCollector
	udpCollector        *udpCollector
	tunnelTimeCollector *tunnelTimeCollector

	// NOTE: New metrics need to be added to `newPrometheusOutlineMetrics()`, `Describe()` and `Collect()`.
	buildInfo  *prometheus.GaugeVec
	accessKeys prometheus.Gauge
	ports      prometheus.Gauge
	// TODO: Add time to first byte.
}

var _ prometheus.Collector = (*outlineMetricsCollector)(nil)
var _ service.UDPMetrics = (*outlineMetricsCollector)(nil)

// newPrometheusOutlineMetrics constructs a Prometheus metrics collector that uses
// `ip2info` to convert IP addresses to countries. `ip2info` may be nil.
func newPrometheusOutlineMetrics(ip2info ipinfo.IPInfoMap) (*outlineMetricsCollector, error) {
	tcpCollector, err := newTCPCollector()
	if err != nil {
		return nil, err
	}
	udpCollector, err := newUDPCollector()
	if err != nil {
		return nil, err
	}
	tunnelTimeCollector := newTunnelTimeCollector(ip2info)

	return &outlineMetricsCollector{
		ip2info: ip2info,

		tcpCollector:        tcpCollector,
		udpCollector:        udpCollector,
		tunnelTimeCollector: tunnelTimeCollector,

		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "build_info",
			Help: "Information on the outline-ss-server build",
		}, []string{"version"}),
		accessKeys: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "keys",
			Help: "Count of access keys",
		}),
		ports: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ports",
			Help: "Count of open Shadowsocks ports",
		}),
	}, nil
}

func (m *outlineMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	m.tcpCollector.Describe(ch)
	m.udpCollector.Describe(ch)
	m.tunnelTimeCollector.Describe(ch)
	m.buildInfo.Describe(ch)
	m.accessKeys.Describe(ch)
	m.ports.Describe(ch)
}

func (m *outlineMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	m.tcpCollector.Collect(ch)
	m.udpCollector.Collect(ch)
	m.tunnelTimeCollector.Collect(ch)
	m.buildInfo.Collect(ch)
	m.accessKeys.Collect(ch)
	m.ports.Collect(ch)
}

func (m *outlineMetricsCollector) getIPInfoFromAddr(addr net.Addr) ipinfo.IPInfo {
	ipInfo, err := ipinfo.GetIPInfoFromAddr(m.ip2info, addr)
	if err != nil {
		slog.LogAttrs(nil, slog.LevelWarn, "Failed client info lookup.", slog.Any("err", err))
		return ipInfo
	}
	if slog.Default().Enabled(nil, slog.LevelDebug) {
		slog.LogAttrs(nil, slog.LevelDebug, "Got info for IP.", slog.String("IP", addr.String()), slog.Any("info", ipInfo))
	}
	return ipInfo
}

func (m *outlineMetricsCollector) SetBuildInfo(version string) {
	m.buildInfo.WithLabelValues(version).Set(1)
}

func (m *outlineMetricsCollector) SetNumAccessKeys(numKeys int, ports int) {
	m.accessKeys.Set(float64(numKeys))
	m.ports.Set(float64(ports))
}

func (m *outlineMetricsCollector) AddOpenTCPConnection(clientConn net.Conn) *tcpConnMetrics {
	clientAddr := clientConn.RemoteAddr()
	clientInfo := m.getIPInfoFromAddr(clientAddr)
	return newTCPConnMetrics(m.tcpCollector, m.tunnelTimeCollector, clientConn, clientInfo)
}

func (m *outlineMetricsCollector) AddUDPNatEntry(clientAddr net.Addr, accessKey string) service.UDPConnMetrics {
	clientInfo := m.getIPInfoFromAddr(clientAddr)
	return newUDPConnMetrics(m.udpCollector, m.tunnelTimeCollector, accessKey, clientAddr, clientInfo)
}

// addIfNonZero helps avoid the creation of series that are always zero.
func addIfNonZero(value int64, counterVec *prometheus.CounterVec, lvs ...string) {
	if value > 0 {
		counterVec.WithLabelValues(lvs...).Add(float64(value))
	}
}

func asnLabel(asn int) string {
	if asn == 0 {
		return ""
	}
	return fmt.Sprint(asn)
}

// Converts a [net.Addr] to an [IPKey].
func toIPKey(addr net.Addr, accessKey string) (*IPKey, error) {
	hostname, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create IPKey: %w", err)
	}
	ip, err := netip.ParseAddr(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPKey: %w", err)
	}
	return &IPKey{ip, accessKey}, nil
}
