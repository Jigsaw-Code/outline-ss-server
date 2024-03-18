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
	"strconv"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// How often to report the active IP key TunnelTime.
	activeIPKeyTrackerReportingInterval = 5 * time.Second
)

var since = time.Since

type outlineMetrics struct {
	ipinfo.IPInfoMap
	*activeIPKeyTracker

	buildInfo            *prometheus.GaugeVec
	accessKeys           prometheus.Gauge
	ports                prometheus.Gauge
	dataBytes            *prometheus.CounterVec
	dataBytesPerLocation *prometheus.CounterVec
	timeToCipherMs       *prometheus.HistogramVec
	// TODO: Add time to first byte.

	IPKeyTimePerKey      *prometheus.CounterVec
	IPKeyTimePerLocation *prometheus.CounterVec

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

type activeClient struct {
	IPKey           IPKey
	connectionCount int
	startTime       time.Time
}

func (c *activeClient) IsActive() bool {
	return c.connectionCount > 0
}

type IPKey struct {
	ip        string
	accessKey string
}

type activeIPKeyTracker struct {
	activeClients   map[IPKey]activeClient
	metricsCallback func(IPKey, time.Duration)
}

// Reports time connected for all active clients, called at a regular interval.
func (t *activeIPKeyTracker) reportAll() {
	if len(t.activeClients) == 0 {
		logger.Debugf("No active clients. No IPKey activity to report.")
		return
	}
	for _, c := range t.activeClients {
		t.reportDuration(c)
	}
}

// Reports time connected for a given active client.
func (t *activeIPKeyTracker) reportDuration(c activeClient) {
	connDuration := since(c.startTime)
	logger.Debugf("Reporting activity for key `%v`, duration: %v", c.IPKey.accessKey, connDuration)
	t.metricsCallback(c.IPKey, connDuration)

	// Reset the start time now that it's been reported.
	c.startTime = time.Now()
	t.activeClients[c.IPKey] = c
}

// Registers a new active connection for a client [net.Addr] and access key.
func (t *activeIPKeyTracker) startConnection(addr net.Addr, accessKey string) {
	hostname, _, _ := net.SplitHostPort(addr.String())
	ipKey := IPKey{ip: hostname, accessKey: accessKey}

	c, exists := t.activeClients[ipKey]
	if !exists {
		c = activeClient{ipKey, 0, time.Now()}
	}
	c.connectionCount++
	t.activeClients[ipKey] = c
}

// Removes an active connection for a client [net.Addr] and access key.
func (t *activeIPKeyTracker) stopConnection(addr net.Addr, accessKey string) {
	hostname, _, _ := net.SplitHostPort(addr.String())
	ipKey := IPKey{ip: hostname, accessKey: accessKey}

	c := t.activeClients[ipKey]
	c.connectionCount--
	if !c.IsActive() {
		t.reportDuration(c)
		delete(t.activeClients, ipKey)
		return
	}
	t.activeClients[ipKey] = c
}

func newActiveIPKeyTracker(callback func(IPKey, time.Duration)) *activeIPKeyTracker {
	t := &activeIPKeyTracker{activeClients: make(map[IPKey]activeClient), metricsCallback: callback}
	ticker := time.NewTicker(activeIPKeyTrackerReportingInterval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				t.reportAll()
			case <-done:
				logger.Debugf("done channel %p closed", done)
				ticker.Stop()
				return
			}
		}
	}()
	return t
}

// newPrometheusOutlineMetrics constructs a metrics object that uses
// `ip2info` to convert IP addresses to countries, and reports all
// metrics to Prometheus via `registerer`. `ip2info` may be nil, but
// `registerer` must not be.
func newPrometheusOutlineMetrics(ip2info ipinfo.IPInfoMap, registerer prometheus.Registerer, enableIPKeyConnectivity bool) *outlineMetrics {
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
		IPKeyTimePerKey: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Name:      "ip_key_connectivity_seconds",
			Help:      "Time at least 1 connection was open for a (IP, access key) pair, per key",
		}, []string{"access_key"}),
		IPKeyTimePerLocation: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "shadowsocks",
			Name:      "ip_key_connectivity_seconds_per_location",
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
	if enableIPKeyConnectivity {
		m.activeIPKeyTracker = newActiveIPKeyTracker(m.reportIPKeyActivity)
	}
	logger.Debugf("tracker: %v", m.activeIPKeyTracker)

	// TODO: Is it possible to pass where to register the collectors?
	registerer.MustRegister(m.buildInfo, m.accessKeys, m.ports, m.tcpProbes, m.tcpOpenConnections, m.tcpClosedConnections, m.tcpConnectionDurationMs,
		m.dataBytes, m.dataBytesPerLocation, m.timeToCipherMs, m.udpPacketsFromClientPerLocation, m.udpAddedNatEntries, m.udpRemovedNatEntries,
		m.IPKeyTimePerKey, m.IPKeyTimePerLocation)
	return m
}

func (m *outlineMetrics) SetBuildInfo(version string) {
	m.buildInfo.WithLabelValues(version).Set(1)
}

func (m *outlineMetrics) SetNumAccessKeys(numKeys int, ports int) {
	m.accessKeys.Set(float64(numKeys))
	m.ports.Set(float64(ports))
}

func (m *outlineMetrics) AddOpenTCPConnection(addr net.Addr) {
	clientInfo, err := ipinfo.GetIPInfoFromAddr(m.IPInfoMap, addr)
	if err != nil {
		logger.Warningf("Failed client info lookup: %v", err)
	}
	logger.Debugf("Got info \"%#v\" for IP %v", clientInfo, addr.String())
	m.tcpOpenConnections.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN)).Inc()
}

// Reports total time connected, by access key and by country.
func (m *outlineMetrics) reportIPKeyActivity(ipKey IPKey, duration time.Duration) {
	m.IPKeyTimePerKey.WithLabelValues(ipKey.accessKey).Add(duration.Seconds())
	ip := net.ParseIP(ipKey.ip)
	clientInfo, err := ipinfo.GetIPInfoFromIP(m.IPInfoMap, ip)
	if err != nil {
		logger.Warningf("Failed client info lookup: %v", err)
	}
	m.IPKeyTimePerLocation.WithLabelValues(clientInfo.CountryCode.String(), asnLabel(clientInfo.ASN)).Add(duration.Seconds())
}

func (m *outlineMetrics) AddAuthenticatedTCPConnection(addr net.Addr, accessKey string) {
	if m.activeIPKeyTracker != nil {
		m.activeIPKeyTracker.startConnection(addr, accessKey)
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

func (m *outlineMetrics) AddClosedTCPConnection(addr net.Addr, accessKey, status string, data metrics.ProxyMetrics, duration time.Duration) {
	clientInfo, err := ipinfo.GetIPInfoFromAddr(m.IPInfoMap, addr)
	if err != nil {
		logger.Warningf("Failed client info lookup: %v", err)
	}
	logger.Debugf("Got info \"%#v\" for IP %v", clientInfo, addr.String())
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

	if m.activeIPKeyTracker != nil {
		m.activeIPKeyTracker.stopConnection(addr, accessKey)
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

func (m *outlineMetrics) AddUDPNatEntry(addr net.Addr, accessKey string) {
	m.udpAddedNatEntries.Inc()

	if m.activeIPKeyTracker != nil {
		m.activeIPKeyTracker.startConnection(addr, accessKey)
	}
}

func (m *outlineMetrics) RemoveUDPNatEntry(addr net.Addr, accessKey string) {
	m.udpRemovedNatEntries.Inc()

	if m.activeIPKeyTracker != nil {
		m.activeIPKeyTracker.stopConnection(addr, accessKey)
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
