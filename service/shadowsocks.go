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
	"context"
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
	AddOpenUDPAssociation(conn net.Conn) UDPAssocationMetrics
	AddOpenTCPConnection(conn net.Conn) TCPConnMetrics
	AddCipherSearch(proto string, accessKeyFound bool, timeToCipher time.Duration)
}

type Service interface {
	HandleStream(ctx context.Context, conn transport.StreamConn)
	NewConnAssociation(conn net.Conn) (ConnAssociation, error)
	NewPacketAssociation(conn net.Conn) (PacketAssociation, error)
}

// Option is a Shadowsocks service constructor option.
type Option func(s *ssService)

type ssService struct {
	logger            *slog.Logger
	metrics           ServiceMetrics
	ciphers           CipherList
	targetIPValidator onet.TargetIPValidator
	replayCache       *ReplayCache

	streamDialer   transport.StreamDialer
	sh             StreamHandler
	packetListener transport.PacketListener
	ph             PacketHandler
}

// NewShadowsocksService creates a new Shadowsocks service.
func NewShadowsocksService(opts ...Option) (Service, error) {
	s := &ssService{}

	for _, opt := range opts {
		opt(s)
	}

	// If no logger is provided via options, use a noop logger.
	if s.logger == nil {
		s.logger = noopLogger()
	}

	// TODO: Register initial data metrics at zero.
	s.sh = NewStreamHandler(
		NewShadowsocksStreamAuthenticator(s.ciphers, s.replayCache, &ssConnMetrics{ServiceMetrics: s.metrics, proto: "tcp"}, s.logger),
		tcpReadTimeout,
	)
	if s.streamDialer != nil {
		s.sh.SetTargetDialer(s.streamDialer)
	}
	s.sh.SetLogger(s.logger)

	s.ph = NewPacketHandler(s.ciphers, &ssConnMetrics{ServiceMetrics: s.metrics, proto: "udp"})
	if s.packetListener != nil {
		s.ph.SetTargetPacketListener(s.packetListener)
	}
	s.ph.SetLogger(s.logger)

	return s, nil
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

// WithMetrics option function.
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

// WithPacketListener option function.
func WithPacketListener(listener transport.PacketListener) Option {
	return func(s *ssService) {
		s.packetListener = listener
	}
}

// HandleStream handles a Shadowsocks stream-based connection.
func (s *ssService) HandleStream(ctx context.Context, conn transport.StreamConn) {
	var metrics TCPConnMetrics
	if s.metrics != nil {
		metrics = s.metrics.AddOpenTCPConnection(conn)
	}
	s.sh.Handle(ctx, conn, metrics)
}

// NewConnAssociation creates a new Shadowsocks packet-based association that
// handles incoming packets. Used by Caddy.
func (s *ssService) NewConnAssociation(conn net.Conn) (ConnAssociation, error) {
	var metrics UDPAssocationMetrics
	if s.metrics != nil {
		metrics = s.metrics.AddOpenUDPAssociation(conn)
	}
	return s.ph.NewConnAssociation(conn, metrics)
}

// NewPacketAssociation creates a new Shadowsocks packet-based association.
// Used by outline-ss-server.
func (s *ssService) NewPacketAssociation(conn net.Conn) (PacketAssociation, error) {
	var metrics UDPAssocationMetrics
	if s.metrics != nil {
		metrics = s.metrics.AddOpenUDPAssociation(conn)
	}
	return s.ph.NewPacketAssociation(conn, metrics)
}

type ssConnMetrics struct {
	ServiceMetrics
	proto string
}

var _ ShadowsocksConnMetrics = (*ssConnMetrics)(nil)

func (cm *ssConnMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	if cm.ServiceMetrics != nil {
		cm.ServiceMetrics.AddCipherSearch(cm.proto, accessKeyFound, timeToCipher)
	}
}

// NoOpShadowsocksConnMetrics is a [ShadowsocksConnMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpShadowsocksConnMetrics struct{}

var _ ShadowsocksConnMetrics = (*NoOpShadowsocksConnMetrics)(nil)

func (m *NoOpShadowsocksConnMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
}
