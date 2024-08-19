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
	"context"
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

type tcpCollector struct {
	probes               *prometheus.HistogramVec
	openConnections      *prometheus.CounterVec
	closedConnections    *prometheus.CounterVec
	connectionDurationMs *prometheus.HistogramVec
}

var _ prometheus.Collector = (*tcpCollector)(nil)

func newTcpCollector() *tcpCollector {
	namespace := "tcp"
	return &tcpCollector{
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
	}
}

func (c *tcpCollector) Describe(ch chan<- *prometheus.Desc) {
	c.probes.Describe(ch)
	c.openConnections.Describe(ch)
	c.closedConnections.Describe(ch)
	c.connectionDurationMs.Describe(ch)
}

func (c *tcpCollector) Collect(ch chan<- prometheus.Metric) {
	c.probes.Collect(ch)
	c.openConnections.Collect(ch)
	c.closedConnections.Collect(ch)
	c.connectionDurationMs.Collect(ch)
}

func (c *tcpCollector) openConnection(clientInfo ipinfo.IPInfo) {
	c.openConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN)).Inc()
}

func (c *tcpCollector) closeConnection(clientInfo ipinfo.IPInfo, status, accessKey string, duration time.Duration) {
	c.closedConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN), status, accessKey).Inc()
	c.connectionDurationMs.WithLabelValues(status).Observe(duration.Seconds() * 1000)
}

func (c *tcpCollector) addProbe(listenerId, status, drainResult string, clientProxyBytes int64) {
	c.probes.WithLabelValues(listenerId, status, drainResult).Observe(float64(clientProxyBytes))
}

type udpCollector struct {
	packetsFromClientPerLocation *prometheus.CounterVec
	addedNatEntries              prometheus.Counter
	removedNatEntries            prometheus.Counter
}

var _ prometheus.Collector = (*udpCollector)(nil)

func newUdpCollector() *udpCollector {
	namespace := "udp"
	return &udpCollector{
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
	}
}

func (c *udpCollector) Describe(ch chan<- *prometheus.Desc) {
	c.packetsFromClientPerLocation.Describe(ch)
	c.addedNatEntries.Describe(ch)
	c.removedNatEntries.Describe(ch)
}

func (c *udpCollector) Collect(ch chan<- prometheus.Metric) {
	c.packetsFromClientPerLocation.Collect(ch)
	c.addedNatEntries.Collect(ch)
	c.removedNatEntries.Collect(ch)
}

func (c *udpCollector) addPacketFromClient(clientInfo ipinfo.IPInfo, status string) {
	c.packetsFromClientPerLocation.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN), status).Inc()
}

func (c *udpCollector) addNatEntry() {
	c.addedNatEntries.Inc()
}

func (c *udpCollector) removeNatEntry() {
	c.removedNatEntries.Inc()
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
	slog.Debug("Reporting tunnel time.", "key", ipKey.accessKey, "duration", tunnelTime)
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
	ip2info     ipinfo.IPInfoMap
	ipInfoCache *LRUCache[net.Addr, ipinfo.IPInfo]

	*tcpCollector
	*udpCollector
	*tunnelTimeCollector

	buildInfo            *prometheus.GaugeVec
	accessKeys           prometheus.Gauge
	ports                prometheus.Gauge
	dataBytes            *prometheus.CounterVec
	dataBytesPerLocation *prometheus.CounterVec
	timeToCipherMs       *prometheus.HistogramVec
	// TODO: Add time to first byte.
}

var _ prometheus.Collector = (*outlineMetricsCollector)(nil)
var _ service.TCPMetrics = (*outlineMetricsCollector)(nil)
var _ service.UDPMetrics = (*outlineMetricsCollector)(nil)

// newPrometheusOutlineMetrics constructs a Prometheus metrics collector that uses
// `ip2info` to convert IP addresses to countries. `ip2info` may be nil.
func newPrometheusOutlineMetrics(ip2info ipinfo.IPInfoMap) *outlineMetricsCollector {
	tcpCollector := newTcpCollector()
	udpCollector := newUdpCollector()
	tunnelTimeCollector := newTunnelTimeCollector(ip2info)

	return &outlineMetricsCollector{
		ip2info:     ip2info,
		ipInfoCache: NewLRUCache[net.Addr, ipinfo.IPInfo](10000, 60*time.Second, 30*time.Second),

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
		dataBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "data_bytes",
				Help: "Bytes transferred by the proxy, per access key",
			}, []string{"dir", "proto", "access_key"}),
		dataBytesPerLocation: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "data_bytes_per_location",
				Help: "Bytes transferred by the proxy, per location",
			}, []string{"dir", "proto", "location", "asn"}),
		timeToCipherMs: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "time_to_cipher_ms",
				Help:    "Time needed to find the cipher",
				Buckets: []float64{0.1, 1, 10, 100, 1000},
			}, []string{"proto", "found_key"}),
	}
}

func (m *outlineMetricsCollector) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.tcpCollector,
		m.udpCollector,
		m.tunnelTimeCollector,

		m.buildInfo,
		m.accessKeys,
		m.ports,
		m.dataBytes,
		m.dataBytesPerLocation,
		m.timeToCipherMs,
	}
}

func (m *outlineMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, collector := range m.collectors() {
		collector.Describe(ch)
	}
}

func (m *outlineMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	for _, collector := range m.collectors() {
		collector.Collect(ch)
	}
}

func (m *outlineMetricsCollector) getIPInfoFromAddr(addr net.Addr) ipinfo.IPInfo {
	ipInfo, exists := m.ipInfoCache.Get(addr)
	if !exists {
		ipInfo, err := ipinfo.GetIPInfoFromAddr(m.ip2info, addr)
		if err != nil {
			slog.Warn("Failed client info lookup.", "err", err)
			return ipInfo
		}
		m.ipInfoCache.Set(addr, ipInfo)
	}
	if slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		slog.Debug("Got IP info for address.", "address", addr, "info", ipInfo)
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

func (m *outlineMetricsCollector) AddOpenTCPConnection(clientAddr net.Addr) {
	clientInfo := m.getIPInfoFromAddr(clientAddr)
	m.tcpCollector.openConnection(clientInfo)
}

func (m *outlineMetricsCollector) AddAuthenticatedTCPConnection(clientAddr net.Addr, accessKey string) {
	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		m.tunnelTimeCollector.startConnection(*ipKey)
	}
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

func (m *outlineMetricsCollector) AddClosedTCPConnection(clientAddr net.Addr, accessKey, status string, data metrics.ProxyMetrics, duration time.Duration) {
	clientInfo := m.getIPInfoFromAddr(clientAddr)
	m.tcpCollector.closeConnection(clientInfo, status, accessKey, duration)
	addIfNonZero(data.ClientProxy, m.dataBytes, "c>p", "tcp", accessKey)
	addIfNonZero(data.ClientProxy, m.dataBytesPerLocation, "c>p", "tcp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(data.ProxyTarget, m.dataBytes, "p>t", "tcp", accessKey)
	addIfNonZero(data.ProxyTarget, m.dataBytesPerLocation, "p>t", "tcp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(data.TargetProxy, m.dataBytes, "p<t", "tcp", accessKey)
	addIfNonZero(data.TargetProxy, m.dataBytesPerLocation, "p<t", "tcp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(data.ProxyClient, m.dataBytes, "c<p", "tcp", accessKey)
	addIfNonZero(data.ProxyClient, m.dataBytesPerLocation, "c<p", "tcp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))

	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		m.tunnelTimeCollector.stopConnection(*ipKey)
	}
}

func (m *outlineMetricsCollector) AddUDPPacketFromClient(clientAddr net.Addr, accessKey, status string, clientProxyBytes, proxyTargetBytes int) {
	clientInfo := m.getIPInfoFromAddr(clientAddr)
	m.udpCollector.addPacketFromClient(clientInfo, status)
	addIfNonZero(int64(clientProxyBytes), m.dataBytes, "c>p", "udp", accessKey)
	addIfNonZero(int64(clientProxyBytes), m.dataBytesPerLocation, "c>p", "udp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(int64(proxyTargetBytes), m.dataBytes, "p>t", "udp", accessKey)
	addIfNonZero(int64(proxyTargetBytes), m.dataBytesPerLocation, "p>t", "udp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
}

func (m *outlineMetricsCollector) AddUDPPacketFromTarget(clientAddr net.Addr, accessKey, status string, targetProxyBytes, proxyClientBytes int) {
	clientInfo := m.getIPInfoFromAddr(clientAddr)
	addIfNonZero(int64(targetProxyBytes), m.dataBytes, "p<t", "udp", accessKey)
	addIfNonZero(int64(targetProxyBytes), m.dataBytesPerLocation, "p<t", "udp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(int64(proxyClientBytes), m.dataBytes, "c<p", "udp", accessKey)
	addIfNonZero(int64(proxyClientBytes), m.dataBytesPerLocation, "c<p", "udp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
}

func (m *outlineMetricsCollector) AddUDPNatEntry(clientAddr net.Addr, accessKey string) {
	m.udpCollector.addNatEntry()

	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		m.tunnelTimeCollector.startConnection(*ipKey)
	}
}

func (m *outlineMetricsCollector) RemoveUDPNatEntry(clientAddr net.Addr, accessKey string) {
	m.udpCollector.removeNatEntry()

	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		m.tunnelTimeCollector.stopConnection(*ipKey)
	}
}

func (m *outlineMetricsCollector) AddTCPProbe(status, drainResult, listenerId string, clientProxyBytes int64) {
	m.tcpCollector.addProbe(listenerId, status, drainResult, clientProxyBytes)
}

func (m *outlineMetricsCollector) AddTCPCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	foundStr := "false"
	if accessKeyFound {
		foundStr = "true"
	}
	m.timeToCipherMs.WithLabelValues("tcp", foundStr).Observe(timeToCipher.Seconds() * 1000)
}

func (m *outlineMetricsCollector) AddUDPCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	foundStr := "false"
	if accessKeyFound {
		foundStr = "true"
	}
	m.timeToCipherMs.WithLabelValues("udp", foundStr).Observe(timeToCipher.Seconds() * 1000)
}
