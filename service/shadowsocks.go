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

package service

import (
	"log/slog"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
)

const (
	// 59 seconds is most common timeout for servers that do not respond to invalid requests
	tcpReadTimeout time.Duration = 59 * time.Second
)

// ShadowsocksConnMetrics is used to report Shadowsocks related metrics on connections.
type ShadowsocksConnMetrics interface {
	AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration)
}

type ServiceMetrics interface {
	AddOpenUDPAssociation(conn net.Conn) UDPAssociationMetrics
	AddOpenTCPConnection(conn net.Conn) TCPConnMetrics
	AddTCPCipherSearch(accessKeyFound bool, timeToCipher time.Duration)
	AddUDPCipherSearch(accessKeyFound bool, timeToCipher time.Duration)
}

// Option is a Shadowsocks service constructor option.
type Option func(s *ssService)

type ssService struct {
	logger            *slog.Logger
	ciphers           CipherList
	metrics           ServiceMetrics
	targetIPValidator onet.TargetIPValidator
	replayCache       *ReplayCache

	streamDialer transport.StreamDialer
}

// NewShadowsocksHandlers creates new Shadowsocks stream and packet handlers.
func NewShadowsocksHandlers(opts ...Option) (StreamHandler, PacketHandler) {
	s := &ssService{
		logger: noopLogger(),
	}

	for _, opt := range opts {
		opt(s)
	}

	// TODO: Register initial data metrics at zero.
	sh := NewStreamHandler(
		NewShadowsocksStreamAuthenticator(s.ciphers, s.replayCache, &ssConnMetrics{s.metrics.AddTCPCipherSearch}, s.logger),
		tcpReadTimeout,
	)
	if s.streamDialer != nil {
		sh.SetTargetDialer(s.streamDialer)
	}
	sh.SetLogger(s.logger)

	ph := NewPacketHandler(s.ciphers, &ssConnMetrics{s.metrics.AddUDPCipherSearch})
	ph.SetLogger(s.logger)

	return sh, ph
}

// WithLogger can be used to provide a custom log target. If not provided,
// the service uses a noop logger (i.e., no logging).
func WithLogger(l *slog.Logger) Option {
	return func(s *ssService) {
		s.logger = l
	}
}

// WithCiphers option function.
func WithCiphers(ciphers CipherList) Option {
	return func(s *ssService) {
		s.ciphers = ciphers
	}
}

func WithMetrics(metrics ServiceMetrics) Option {
	return func(s *ssService) {
		s.metrics = metrics
	}
}

// WithReplayCache option function.
func WithReplayCache(replayCache *ReplayCache) Option {
	return func(s *ssService) {
		s.replayCache = replayCache
	}
}

// WithStreamDialer option function.
func WithStreamDialer(dialer transport.StreamDialer) Option {
	return func(s *ssService) {
		s.streamDialer = dialer
	}
}

type ssConnMetrics struct {
	metricFunc func(accessKeyFound bool, timeToCipher time.Duration)
}

var _ ShadowsocksConnMetrics = (*ssConnMetrics)(nil)

func (cm *ssConnMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	if cm.metricFunc != nil {
		cm.metricFunc(accessKeyFound, timeToCipher)
	}
}

// NoOpShadowsocksConnMetrics is a [ShadowsocksConnMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpShadowsocksConnMetrics struct{}

var _ ShadowsocksConnMetrics = (*NoOpShadowsocksConnMetrics)(nil)

func (m *NoOpShadowsocksConnMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
}
