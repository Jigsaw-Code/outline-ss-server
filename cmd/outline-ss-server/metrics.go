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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// `now` is stubbable for testing.
var now = time.Now

type serverMetrics struct {
	// NOTE: New metrics need to be added to `newPrometheusServerMetrics()`, `Describe()` and `Collect()`.
	buildInfo  *prometheus.GaugeVec
	accessKeys prometheus.Gauge
	ports      prometheus.Gauge
}

var _ prometheus.Collector = (*serverMetrics)(nil)

// newPrometheusServerMetrics constructs a Prometheus metrics collector for server
// related metrics.
func newPrometheusServerMetrics() *serverMetrics {
	return &serverMetrics{
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
			Help: "Count of open ports",
		}),
	}
}

func (m *serverMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.buildInfo.Describe(ch)
	m.accessKeys.Describe(ch)
	m.ports.Describe(ch)
}

func (m *serverMetrics) Collect(ch chan<- prometheus.Metric) {
	m.buildInfo.Collect(ch)
	m.accessKeys.Collect(ch)
	m.ports.Collect(ch)
}

func (m *serverMetrics) SetVersion(version string) {
	m.buildInfo.WithLabelValues(version).Set(1)
}

func (m *serverMetrics) SetNumAccessKeys(numKeys int, ports int) {
	m.accessKeys.Set(float64(numKeys))
	m.ports.Set(float64(ports))
}
