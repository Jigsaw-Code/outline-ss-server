// Copyright 2024 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package caddy provides an app and handler for Caddy Server (https://caddyserver.com/)
// allowing it to turn any handler into one supporting the Vulcain protocol.

package caddy

import (
	"errors"
	"log/slog"

	outline_prometheus "github.com/Jigsaw-Code/outline-ss-server/prometheus"
	outline "github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
)

const outlineModuleName = "outline"

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  outlineModuleName,
		New: func() caddy.Module { return new(OutlineApp) },
	})
}

type ShadowsocksConfig struct {
	ReplayHistory int `json:"replay_history,omitempty"`
}

type OutlineApp struct {
	ShadowsocksConfig *ShadowsocksConfig `json:"shadowsocks,omitempty"`

	ReplayCache outline.ReplayCache
	logger      *slog.Logger
	Metrics     outline.ServiceMetrics
	buildInfo   *prometheus.GaugeVec
}

var (
	_ caddy.App         = (*OutlineApp)(nil)
	_ caddy.Provisioner = (*OutlineApp)(nil)
)

func (OutlineApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: outlineModuleName}
}

// Provision sets up Outline.
func (app *OutlineApp) Provision(ctx caddy.Context) error {
	app.logger = ctx.Slogger()

	app.logger.Info("provisioning app instance")

	if app.ShadowsocksConfig != nil {
		// TODO: Persist replay cache across config reloads.
		app.ReplayCache = outline.NewReplayCache(app.ShadowsocksConfig.ReplayHistory)
	}

	if err := app.defineMetrics(); err != nil {
		app.logger.Error("failed to define Prometheus metrics", "err", err)
	}
	// TODO: Set version at build time.
	app.buildInfo.WithLabelValues("dev").Set(1)
	// TODO: Add replacement metrics for `shadowsocks_keys` and `shadowsocks_ports`.

	return nil
}

func (app *OutlineApp) defineMetrics() error {
	r := prometheus.WrapRegistererWithPrefix("outline_", prometheus.DefaultRegisterer)

	var err error
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "build_info",
		Help: "Information on the outline-ss-server build",
	}, []string{"version"})
	app.buildInfo, err = registerCollector(r, buildInfo)
	if err != nil {
		return err
	}

	// TODO: Allow the configuration of ip2info.
	metrics, err := outline_prometheus.NewServiceMetrics(nil)
	if err != nil {
		return err
	}
	app.Metrics, err = registerCollector(r, metrics)
	if err != nil {
		return err
	}
	return nil
}

func registerCollector[T prometheus.Collector](registerer prometheus.Registerer, coll T) (T, error) {
	if err := registerer.Register(coll); err != nil {
		are := &prometheus.AlreadyRegisteredError{}
		if !errors.As(err, are) {
			// This collector has been registered before. This is expected during a config reload.
			coll = are.ExistingCollector.(T)
		} else {
			// Something else went wrong.
			return coll, err
		}
	}
	return coll, nil
}

// Start starts the App.
func (app *OutlineApp) Start() error {
	app.logger.Debug("started app instance")
	return nil
}

// Stop stops the App.
func (app *OutlineApp) Stop() error {
	app.logger.Debug("stopped app instance")
	return nil
}
