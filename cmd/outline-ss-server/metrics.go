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
		}, []string{"proto", "dir", "location", "asn", "asorg"}).CurryWith(map[string]string{"proto": proto})
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

func (c *proxyCollector) addClientTarget(clientProxyBytes, proxyTargetBytes int64, accessKey string, clientInfo ipinfo.IPInfo) {
	addIfNonZero(clientProxyBytes, c.dataBytesPerKey, "c>p", accessKey)
	addIfNonZero(clientProxyBytes, c.dataBytesPerLocation, "c>p", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN.Number), clientInfo.ASN.Organization)
	addIfNonZero(proxyTargetBytes, c.dataBytesPerKey, "p>t", accessKey)
	addIfNonZero(proxyTargetBytes, c.dataBytesPerLocation, "p>t", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN.Number), clientInfo.ASN.Organization)
}

func (c *proxyCollector) addTargetClient(targetProxyBytes, proxyClientBytes int64, accessKey string, clientInfo ipinfo.IPInfo) {
	addIfNonZero(targetProxyBytes, c.dataBytesPerKey, "p<t", accessKey)
	addIfNonZero(targetProxyBytes, c.dataBytesPerLocation, "p<t", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN.Number), clientInfo.ASN.Organization)
	addIfNonZero(proxyClientBytes, c.dataBytesPerKey, "c<p", accessKey)
	addIfNonZero(proxyClientBytes, c.dataBytesPerLocation, "c<p", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN.Number), clientInfo.ASN.Organization)
}

type tcpConnMetrics struct {
	tcpServiceMetrics *tcpServiceMetrics
	tunnelTimeMetrics *tunnelTimeMetrics

	localAddr  net.Addr
	clientAddr net.Addr
	clientInfo ipinfo.IPInfo
	accessKey  string
}

var _ service.TCPConnMetrics = (*tcpConnMetrics)(nil)

func newTCPConnMetrics(tcpServiceMetrics *tcpServiceMetrics, tunnelTimeMetrics *tunnelTimeMetrics, clientConn net.Conn, clientInfo ipinfo.IPInfo) *tcpConnMetrics {
	tcpServiceMetrics.openConnection(clientInfo)
	return &tcpConnMetrics{
		tcpServiceMetrics: tcpServiceMetrics,
		tunnelTimeMetrics: tunnelTimeMetrics,
		localAddr:         clientConn.LocalAddr(),
		clientAddr:        clientConn.RemoteAddr(),
		clientInfo:        clientInfo,
	}
}

func (cm *tcpConnMetrics) AddAuthenticated(accessKey string) {
	cm.accessKey = accessKey
	ipKey, err := toIPKey(cm.clientAddr, accessKey)
	if err == nil {
		cm.tunnelTimeMetrics.startConnection(*ipKey)
	}
}

func (cm *tcpConnMetrics) AddClosed(status string, data metrics.ProxyMetrics, duration time.Duration) {
	cm.tcpServiceMetrics.proxyCollector.addClientTarget(data.ClientProxy, data.ProxyTarget, cm.accessKey, cm.clientInfo)
	cm.tcpServiceMetrics.proxyCollector.addTargetClient(data.TargetProxy, data.ProxyClient, cm.accessKey, cm.clientInfo)
	cm.tcpServiceMetrics.closeConnection(status, duration, cm.accessKey, cm.clientInfo)
	// We only track authenticated TCP connections, so ignore unauthenticated closed connections
	// when calculating tunneltime. See https://github.com/Jigsaw-Code/outline-server/issues/1590.
	if cm.accessKey != "" {
		ipKey, err := toIPKey(cm.clientAddr, cm.accessKey)
		if err == nil {
			cm.tunnelTimeMetrics.stopConnection(*ipKey)
		}
	}
}

func (cm *tcpConnMetrics) AddProbe(status, drainResult string, clientProxyBytes int64) {
	cm.tcpServiceMetrics.addProbe(cm.localAddr.String(), status, drainResult, clientProxyBytes)
}

type tcpServiceMetrics struct {
	proxyCollector *proxyCollector
	// NOTE: New metrics need to be added to `newTCPCollector()`, `Describe()` and `Collect()`.
	probes               *prometheus.HistogramVec
	openConnections      *prometheus.CounterVec
	closedConnections    *prometheus.CounterVec
	connectionDurationMs *prometheus.HistogramVec
	timeToCipherMs       prometheus.ObserverVec
}

var _ prometheus.Collector = (*tcpServiceMetrics)(nil)
var _ service.ShadowsocksConnMetrics = (*tcpServiceMetrics)(nil)

func newTCPCollector() (*tcpServiceMetrics, error) {
	namespace := "tcp"
	proxyCollector, err := newProxyCollector(namespace)
	if err != nil {
		return nil, err
	}
	timeToCipherVec, err := NewTimeToCipherVec(namespace)
	if err != nil {
		return nil, err
	}
	return &tcpServiceMetrics{
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
		}, []string{"location", "asn", "asorg"}),
		closedConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "connections_closed",
			Help:      "Count of closed TCP connections",
		}, []string{"location", "asn", "asorg", "status", "access_key"}),
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

func (c *tcpServiceMetrics) Describe(ch chan<- *prometheus.Desc) {
	c.proxyCollector.Describe(ch)
	c.timeToCipherMs.Describe(ch)
	c.probes.Describe(ch)
	c.openConnections.Describe(ch)
	c.closedConnections.Describe(ch)
	c.connectionDurationMs.Describe(ch)
}

func (c *tcpServiceMetrics) Collect(ch chan<- prometheus.Metric) {
	c.proxyCollector.Collect(ch)
	c.timeToCipherMs.Collect(ch)
	c.probes.Collect(ch)
	c.openConnections.Collect(ch)
	c.closedConnections.Collect(ch)
	c.connectionDurationMs.Collect(ch)
}

func (c *tcpServiceMetrics) openConnection(clientInfo ipinfo.IPInfo) {
	c.openConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN.Number), clientInfo.ASN.Organization).Inc()
}

func (c *tcpServiceMetrics) closeConnection(status string, duration time.Duration, accessKey string, clientInfo ipinfo.IPInfo) {
	c.closedConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN.Number), clientInfo.ASN.Organization, status, accessKey).Inc()
	c.connectionDurationMs.WithLabelValues(status).Observe(duration.Seconds() * 1000)
}

func (c *tcpServiceMetrics) addProbe(listenerId, status, drainResult string, clientProxyBytes int64) {
	c.probes.WithLabelValues(listenerId, status, drainResult).Observe(float64(clientProxyBytes))
}

func (c *tcpServiceMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	foundStr := "false"
	if accessKeyFound {
		foundStr = "true"
	}
	c.timeToCipherMs.WithLabelValues(foundStr).Observe(timeToCipher.Seconds() * 1000)
}

type udpConnMetrics struct {
	udpServiceMetrics *udpServiceMetrics
	tunnelTimeMetrics *tunnelTimeMetrics

	clientAddr net.Addr
	clientInfo ipinfo.IPInfo
	accessKey  string
}

var _ service.UDPConnMetrics = (*udpConnMetrics)(nil)

func newUDPConnMetrics(udpServiceMetrics *udpServiceMetrics, tunnelTimeMetrics *tunnelTimeMetrics, accessKey string, clientAddr net.Addr, clientInfo ipinfo.IPInfo) *udpConnMetrics {
	udpServiceMetrics.addNatEntry()
	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		tunnelTimeMetrics.startConnection(*ipKey)
	}
	return &udpConnMetrics{
		udpServiceMetrics: udpServiceMetrics,
		tunnelTimeMetrics: tunnelTimeMetrics,
		accessKey:         accessKey,
		clientAddr:        clientAddr,
		clientInfo:        clientInfo,
	}
}

func (cm *udpConnMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
	cm.udpServiceMetrics.addPacketFromClient(status, clientProxyBytes, proxyTargetBytes, cm.accessKey, cm.clientInfo)
}

func (cm *udpConnMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
	cm.udpServiceMetrics.addPacketFromTarget(status, targetProxyBytes, proxyClientBytes, cm.accessKey, cm.clientInfo)
}

func (cm *udpConnMetrics) RemoveNatEntry() {
	cm.udpServiceMetrics.removeNatEntry()

	ipKey, err := toIPKey(cm.clientAddr, cm.accessKey)
	if err == nil {
		cm.tunnelTimeMetrics.stopConnection(*ipKey)
	}
}

type udpServiceMetrics struct {
	proxyCollector *proxyCollector
	// NOTE: New metrics need to be added to `newUDPCollector()`, `Describe()` and `Collect()`.
	packetsFromClientPerLocation *prometheus.CounterVec
	addedNatEntries              prometheus.Counter
	removedNatEntries            prometheus.Counter
	timeToCipherMs               prometheus.ObserverVec
}

var _ prometheus.Collector = (*udpServiceMetrics)(nil)
var _ service.ShadowsocksConnMetrics = (*tcpServiceMetrics)(nil)

func newUDPCollector() (*udpServiceMetrics, error) {
	namespace := "udp"
	proxyCollector, err := newProxyCollector(namespace)
	if err != nil {
		return nil, err
	}
	timeToCipherVec, err := NewTimeToCipherVec(namespace)
	if err != nil {
		return nil, err
	}
	return &udpServiceMetrics{
		proxyCollector: proxyCollector,
		timeToCipherMs: timeToCipherVec,
		packetsFromClientPerLocation: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "packets_from_client_per_location",
				Help:      "Packets received from the client, per location and status",
			}, []string{"location", "asn", "asorg", "status"}),
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

func (c *udpServiceMetrics) Describe(ch chan<- *prometheus.Desc) {
	c.proxyCollector.Describe(ch)
	c.timeToCipherMs.Describe(ch)
	c.packetsFromClientPerLocation.Describe(ch)
	c.addedNatEntries.Describe(ch)
	c.removedNatEntries.Describe(ch)
}

func (c *udpServiceMetrics) Collect(ch chan<- prometheus.Metric) {
	c.proxyCollector.Collect(ch)
	c.timeToCipherMs.Collect(ch)
	c.packetsFromClientPerLocation.Collect(ch)
	c.addedNatEntries.Collect(ch)
	c.removedNatEntries.Collect(ch)
}

func (c *udpServiceMetrics) addNatEntry() {
	c.addedNatEntries.Inc()
}

func (c *udpServiceMetrics) removeNatEntry() {
	c.removedNatEntries.Inc()
}

func (c *udpServiceMetrics) addPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64, accessKey string, clientInfo ipinfo.IPInfo) {
	c.packetsFromClientPerLocation.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN.Number), clientInfo.ASN.Organization, status).Inc()
	c.proxyCollector.addClientTarget(clientProxyBytes, proxyTargetBytes, accessKey, clientInfo)
}

func (c *udpServiceMetrics) addPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64, accessKey string, clientInfo ipinfo.IPInfo) {
	c.proxyCollector.addTargetClient(targetProxyBytes, proxyClientBytes, accessKey, clientInfo)
}

func (c *udpServiceMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
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

type tunnelTimeMetrics struct {
	ip2info       ipinfo.IPInfoMap
	mu            sync.Mutex // Protects the activeClients map.
	activeClients map[IPKey]*activeClient

	// NOTE: New metrics need to be added to `newTunnelTimeMetrics()`, `Describe()` and `Collect()`.
	tunnelTimePerKey      *prometheus.CounterVec
	tunnelTimePerLocation *prometheus.CounterVec
}

var _ prometheus.Collector = (*tunnelTimeMetrics)(nil)

func newTunnelTimeMetrics(ip2info ipinfo.IPInfoMap) *tunnelTimeMetrics {
	namespace := "tunnel_time"
	return &tunnelTimeMetrics{
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
		}, []string{"location", "asn", "asorg"}),
	}
}

func (c *tunnelTimeMetrics) Describe(ch chan<- *prometheus.Desc) {
	c.tunnelTimePerKey.Describe(ch)
	c.tunnelTimePerLocation.Describe(ch)
}

func (c *tunnelTimeMetrics) Collect(ch chan<- prometheus.Metric) {
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
func (c *tunnelTimeMetrics) reportTunnelTime(ipKey IPKey, client *activeClient, tNow time.Time) {
	tunnelTime := tNow.Sub(client.startTime)
	slog.LogAttrs(nil, slog.LevelDebug, "Reporting tunnel time.", slog.String("key", ipKey.accessKey), slog.Duration("duration", tunnelTime))
	c.tunnelTimePerKey.WithLabelValues(ipKey.accessKey).Add(tunnelTime.Seconds())
	c.tunnelTimePerLocation.WithLabelValues(client.info.CountryCode.String(), asnLabel(client.info.ASN.Number), client.info.ASN.Organization).Add(tunnelTime.Seconds())
	// Reset the start time now that the tunnel time has been reported.
	client.startTime = tNow
}

// Registers a new active connection for a client [net.Addr] and access key.
func (c *tunnelTimeMetrics) startConnection(ipKey IPKey) {
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
func (c *tunnelTimeMetrics) stopConnection(ipKey IPKey) {
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

type outlineMetrics struct {
	ip2info ipinfo.IPInfoMap

	tcpServiceMetrics *tcpServiceMetrics
	udpServiceMetrics *udpServiceMetrics
	tunnelTimeMetrics *tunnelTimeMetrics

	// NOTE: New metrics need to be added to `newPrometheusOutlineMetrics()`, `Describe()` and `Collect()`.
	buildInfo  *prometheus.GaugeVec
	accessKeys prometheus.Gauge
	ports      prometheus.Gauge
	// TODO: Add time to first byte.
}

var _ prometheus.Collector = (*outlineMetrics)(nil)
var _ service.UDPMetrics = (*outlineMetrics)(nil)

// newPrometheusOutlineMetrics constructs a Prometheus metrics collector that uses
// `ip2info` to convert IP addresses to countries. `ip2info` may be nil.
func newPrometheusOutlineMetrics(ip2info ipinfo.IPInfoMap) (*outlineMetrics, error) {
	tcpServiceMetrics, err := newTCPCollector()
	if err != nil {
		return nil, err
	}
	udpServiceMetrics, err := newUDPCollector()
	if err != nil {
		return nil, err
	}
	tunnelTimeMetrics := newTunnelTimeMetrics(ip2info)

	return &outlineMetrics{
		ip2info: ip2info,

		tcpServiceMetrics: tcpServiceMetrics,
		udpServiceMetrics: udpServiceMetrics,
		tunnelTimeMetrics: tunnelTimeMetrics,

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

func (m *outlineMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.tcpServiceMetrics.Describe(ch)
	m.udpServiceMetrics.Describe(ch)
	m.tunnelTimeMetrics.Describe(ch)
	m.buildInfo.Describe(ch)
	m.accessKeys.Describe(ch)
	m.ports.Describe(ch)
}

func (m *outlineMetrics) Collect(ch chan<- prometheus.Metric) {
	m.tcpServiceMetrics.Collect(ch)
	m.udpServiceMetrics.Collect(ch)
	m.tunnelTimeMetrics.Collect(ch)
	m.buildInfo.Collect(ch)
	m.accessKeys.Collect(ch)
	m.ports.Collect(ch)
}

func (m *outlineMetrics) getIPInfoFromAddr(addr net.Addr) ipinfo.IPInfo {
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

func (m *outlineMetrics) SetBuildInfo(version string) {
	m.buildInfo.WithLabelValues(version).Set(1)
}

func (m *outlineMetrics) SetNumAccessKeys(numKeys int, ports int) {
	m.accessKeys.Set(float64(numKeys))
	m.ports.Set(float64(ports))
}

func (m *outlineMetrics) AddOpenTCPConnection(clientConn net.Conn) *tcpConnMetrics {
	clientAddr := clientConn.RemoteAddr()
	clientInfo := m.getIPInfoFromAddr(clientAddr)
	return newTCPConnMetrics(m.tcpServiceMetrics, m.tunnelTimeMetrics, clientConn, clientInfo)
}

func (m *outlineMetrics) AddUDPNatEntry(clientAddr net.Addr, accessKey string) service.UDPConnMetrics {
	clientInfo := m.getIPInfoFromAddr(clientAddr)
	return newUDPConnMetrics(m.udpServiceMetrics, m.tunnelTimeMetrics, accessKey, clientAddr, clientInfo)
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
