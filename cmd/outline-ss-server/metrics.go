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
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// How often to report the active IP key TunnelTime.
const tunnelTimeTrackerReportingInterval = 5 * time.Second

// Now is stubbable for testing.
var Now = time.Now

type outlineMetrics struct {
	ipinfo.IPInfoMap
	tunnelTimeTracker

	buildInfo            *prometheus.GaugeVec
	accessKeys           prometheus.Gauge
	ports                prometheus.Gauge
	dataBytes            *prometheus.CounterVec
	dataBytesPerLocation *prometheus.CounterVec
	timeToCipherMs       *prometheus.HistogramVec
	// TODO: Add time to first byte.

	TunnelTimePerKey      *prometheus.CounterVec
	TunnelTimePerLocation *prometheus.CounterVec

	tcpProbes               *prometheus.HistogramVec
	tcpOpenConnections      *prometheus.CounterVec
	tcpClosedConnections    *prometheus.CounterVec
	tcpConnectionDurationMs *prometheus.HistogramVec

	udpPacketsFromClientPerLocation *prometheus.CounterVec
	udpAddedNatEntries              prometheus.Counter
	udpRemovedNatEntries            prometheus.Counter
}

var _ service.TCPMetrics = (*outlineMetrics)(nil)
var _ service.UDPMetrics = (*outlineMetrics)(nil)

// Converts a [net.Addr] to an [IPKey].
func toIPKey(addr net.Addr, accessKey string) (*IPKey, error) {
	hostname, _, _ := net.SplitHostPort(addr.String())
	ip, err := netip.ParseAddr(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to convert IP address: %w", err)
	}
	return &IPKey{ip, accessKey}, nil
}

type ReportTunnelTimeFunc func(IPKey, ipinfo.IPInfo, time.Duration)

type activeClient struct {
	mu              sync.Mutex
	IPKey           IPKey
	clientInfo      ipinfo.IPInfo
	connectionCount int
	startTime       time.Time
}

type IPKey struct {
	ip        netip.Addr
	accessKey string
}

type tunnelTimeTracker struct {
	ipinfo.IPInfoMap
	mu               sync.Mutex
	activeClients    map[IPKey]*activeClient
	reportTunnelTime ReportTunnelTimeFunc
}

// Reports time connected for all active clients, called at a regular interval.
func (t *tunnelTimeTracker) reportAll(now time.Time) {
	if len(t.activeClients) == 0 {
		logger.Debugf("No active clients. No TunnelTime activity to report.")
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.activeClients {
		t.reportDuration(c, now)
	}
}

// Reports time connected for a given active client.
func (t *tunnelTimeTracker) reportDuration(c *activeClient, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	connDuration := now.Sub(c.startTime)
	logger.Debugf("Reporting activity for key `%v`, duration: %v", c.IPKey.accessKey, connDuration)
	t.reportTunnelTime(c.IPKey, c.clientInfo, connDuration)
	// Reset the start time now that it's been reported.
	c.startTime = Now()
}

// Registers a new active connection for a client [net.Addr] and access key.
func (t *tunnelTimeTracker) startConnection(ipKey IPKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, exists := t.activeClients[ipKey]
	if !exists {
		clientInfo, _ := ipinfo.GetIPInfoFromIP(t.IPInfoMap, net.IP(ipKey.ip.AsSlice()))
		c = &activeClient{
			IPKey:      ipKey,
			clientInfo: clientInfo,
			startTime:  Now(),
		}
	}
	c.connectionCount++
	t.activeClients[ipKey] = c
}

// Removes an active connection for a client [net.Addr] and access key.
func (t *tunnelTimeTracker) stopConnection(ipKey IPKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, exists := t.activeClients[ipKey]
	if !exists {
		logger.Warningf("Failed to find active client")
		return
	}
	c.mu.Lock()
	c.connectionCount--
	c.mu.Unlock()
	if c.connectionCount <= 0 {
		t.reportDuration(c, Now())
		delete(t.activeClients, ipKey)
		return
	}
}

func newTunnelTimeTracker(ip2info ipinfo.IPInfoMap, report ReportTunnelTimeFunc) *tunnelTimeTracker {
	tracker := &tunnelTimeTracker{
		IPInfoMap:        ip2info,
		activeClients:    make(map[IPKey]*activeClient),
		reportTunnelTime: report,
	}
	ticker := time.NewTicker(tunnelTimeTrackerReportingInterval)
	go func() {
		for t := range ticker.C {
			tracker.reportAll(t)
		}
	}()
	return tracker
}

// newPrometheusOutlineMetrics constructs a metrics object that uses
// `ip2info` to convert IP addresses to countries, and reports all
// metrics to Prometheus via `registerer`. `ip2info` may be nil, but
// `registerer` must not be.
func newPrometheusOutlineMetrics(ip2info ipinfo.IPInfoMap, registerer prometheus.Registerer) *outlineMetrics {
	m := &outlineMetrics{
		IPInfoMap: ip2info,
		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "shadowsocks",
			Name:      "build_info",
			Help:      "Information on the outline-ss-server build",
		}, []string{"version"}),
		accessKeys: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shadowsocks",
			Name:      "keys",
			Help:      "Count of access keys",
		}),
		ports: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "shadowsocks",
			Name:      "ports",
			Help:      "Count of open Shadowsocks ports",
		}),
		tcpProbes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "shadowsocks",
			Name:      "tcp_probes",
			Buckets:   []float64{0, 49, 50, 51, 73, 91},
			Help:      "Histogram of number of bytes from client to proxy, for detecting possible probes",
		}, []string{"port", "status", "error"}),
		tcpOpenConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Subsystem: "tcp",
			Name:      "connections_opened",
			Help:      "Count of open TCP connections",
		}, []string{"location", "asn"}),
		tcpClosedConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Subsystem: "tcp",
			Name:      "connections_closed",
			Help:      "Count of closed TCP connections",
		}, []string{"location", "asn", "status", "access_key"}),
		tcpConnectionDurationMs: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "shadowsocks",
				Subsystem: "tcp",
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
		TunnelTimePerKey: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Name:      "tunnel_time_seconds",
			Help:      "Time at least 1 connection was open for a (IP, access key) pair, per key",
		}, []string{"access_key"}),
		TunnelTimePerLocation: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Name:      "tunnel_time_seconds_per_location",
			Help:      "Time at least 1 connection was open for a (IP, access key) pair, per location",
		}, []string{"location", "asn"}),
		dataBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Name:      "data_bytes",
				Help:      "Bytes transferred by the proxy, per access key",
			}, []string{"dir", "proto", "access_key"}),
		dataBytesPerLocation: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Name:      "data_bytes_per_location",
				Help:      "Bytes transferred by the proxy, per location",
			}, []string{"dir", "proto", "location", "asn"}),
		timeToCipherMs: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "shadowsocks",
				Name:      "time_to_cipher_ms",
				Help:      "Time needed to find the cipher",
				Buckets:   []float64{0.1, 1, 10, 100, 1000},
			}, []string{"proto", "found_key"}),
		udpPacketsFromClientPerLocation: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "packets_from_client_per_location",
				Help:      "Packets received from the client, per location and status",
			}, []string{"location", "asn", "status"}),
		udpAddedNatEntries: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "nat_entries_added",
				Help:      "Entries added to the UDP NAT table",
			}),
		udpRemovedNatEntries: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "shadowsocks",
				Subsystem: "udp",
				Name:      "nat_entries_removed",
				Help:      "Entries removed from the UDP NAT table",
			}),
	}
	m.tunnelTimeTracker = *newTunnelTimeTracker(ip2info, m.addTunnelTime)

	// TODO: Is it possible to pass where to register the collectors?
	registerer.MustRegister(m.buildInfo, m.accessKeys, m.ports, m.tcpProbes, m.tcpOpenConnections, m.tcpClosedConnections, m.tcpConnectionDurationMs,
		m.dataBytes, m.dataBytesPerLocation, m.timeToCipherMs, m.udpPacketsFromClientPerLocation, m.udpAddedNatEntries, m.udpRemovedNatEntries,
		m.TunnelTimePerKey, m.TunnelTimePerLocation)
	return m
}

func (m *outlineMetrics) SetBuildInfo(version string) {
	m.buildInfo.WithLabelValues(version).Set(1)
}

func (m *outlineMetrics) SetNumAccessKeys(numKeys int, ports int) {
	m.accessKeys.Set(float64(numKeys))
	m.ports.Set(float64(ports))
}

func (m *outlineMetrics) AddOpenTCPConnection(clientInfo ipinfo.IPInfo) {
	m.tcpOpenConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN)).Inc()
}

// Reports total time connected (i.e. TunnelTime), by access key and by country.
func (m *outlineMetrics) addTunnelTime(ipKey IPKey, clientInfo ipinfo.IPInfo, duration time.Duration) {
	m.TunnelTimePerKey.WithLabelValues(ipKey.accessKey).Add(duration.Seconds())
	m.TunnelTimePerLocation.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN)).Add(duration.Seconds())
}

func (m *outlineMetrics) AddAuthenticatedTCPConnection(clientAddr net.Addr, accessKey string) {
	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		m.tunnelTimeTracker.startConnection(*ipKey)
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

func (m *outlineMetrics) AddClosedTCPConnection(clientInfo ipinfo.IPInfo, clientAddr net.Addr, accessKey, status string, data metrics.ProxyMetrics, duration time.Duration) {
	m.tcpClosedConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN), status, accessKey).Inc()
	m.tcpConnectionDurationMs.WithLabelValues(status).Observe(duration.Seconds() * 1000)
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
		m.tunnelTimeTracker.stopConnection(*ipKey)
	}
}

func (m *outlineMetrics) AddUDPPacketFromClient(clientInfo ipinfo.IPInfo, accessKey, status string, clientProxyBytes, proxyTargetBytes int) {
	m.udpPacketsFromClientPerLocation.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN), status).Inc()
	addIfNonZero(int64(clientProxyBytes), m.dataBytes, "c>p", "udp", accessKey)
	addIfNonZero(int64(clientProxyBytes), m.dataBytesPerLocation, "c>p", "udp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(int64(proxyTargetBytes), m.dataBytes, "p>t", "udp", accessKey)
	addIfNonZero(int64(proxyTargetBytes), m.dataBytesPerLocation, "p>t", "udp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
}

func (m *outlineMetrics) AddUDPPacketFromTarget(clientInfo ipinfo.IPInfo, accessKey, status string, targetProxyBytes, proxyClientBytes int) {
	addIfNonZero(int64(targetProxyBytes), m.dataBytes, "p<t", "udp", accessKey)
	addIfNonZero(int64(targetProxyBytes), m.dataBytesPerLocation, "p<t", "udp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
	addIfNonZero(int64(proxyClientBytes), m.dataBytes, "c<p", "udp", accessKey)
	addIfNonZero(int64(proxyClientBytes), m.dataBytesPerLocation, "c<p", "udp", clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN))
}

func (m *outlineMetrics) AddUDPNatEntry(clientAddr net.Addr, accessKey string) {
	m.udpAddedNatEntries.Inc()

	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		m.tunnelTimeTracker.startConnection(*ipKey)
	}
}

func (m *outlineMetrics) RemoveUDPNatEntry(clientAddr net.Addr, accessKey string) {
	m.udpRemovedNatEntries.Inc()

	ipKey, err := toIPKey(clientAddr, accessKey)
	if err == nil {
		m.tunnelTimeTracker.stopConnection(*ipKey)
	}
}

func (m *outlineMetrics) AddTCPProbe(status, drainResult string, port int, clientProxyBytes int64) {
	m.tcpProbes.WithLabelValues(strconv.Itoa(port), status, drainResult).Observe(float64(clientProxyBytes))
}

func (m *outlineMetrics) AddTCPCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	foundStr := "false"
	if accessKeyFound {
		foundStr = "true"
	}
	m.timeToCipherMs.WithLabelValues("tcp", foundStr).Observe(timeToCipher.Seconds() * 1000)
}

func (m *outlineMetrics) AddUDPCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	foundStr := "false"
	if accessKeyFound {
		foundStr = "true"
	}
	m.timeToCipherMs.WithLabelValues("udp", foundStr).Observe(timeToCipher.Seconds() * 1000)
}
