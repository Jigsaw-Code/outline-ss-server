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
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
)

const (
	// 59 seconds is most common timeout for servers that do not respond to invalid requests
	tcpReadTimeout time.Duration = 59 * time.Second

	// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
	defaultNatTimeout time.Duration = 5 * time.Minute
)

// ShadowsocksConnMetrics is used to report Shadowsocks related metrics on connections.
type ShadowsocksConnMetrics interface {
	AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration)
}

type ServiceMetrics interface {
	UDPMetrics
	AddOpenTCPConnection(conn net.Conn) TCPConnMetrics
	AddCipherSearch(proto string, accessKeyFound bool, timeToCipher time.Duration)
}

type Service interface {
	HandleStream(ctx context.Context, conn transport.StreamConn)
	HandlePacket(conn net.PacketConn)
}

// Option is a Shadowsocks service constructor option.
type Option func(s *ssService)

type ssService struct {
	logger      Logger
	m           ServiceMetrics
	ciphers     CipherList
	natTimeout  time.Duration
	replayCache *ReplayCache

	sh StreamHandler
	ph PacketHandler
}

func NewShadowsocksService(opts ...Option) (Service, error) {
	s := &ssService{}

	for _, opt := range opts {
		opt(s)
	}

	if s.natTimeout == 0 {
		s.natTimeout = defaultNatTimeout
	}

	// TODO: Register initial data metrics at zero.
	s.sh = NewStreamHandler(
		NewShadowsocksStreamAuthenticator(s.ciphers, s.replayCache, &ssConnMetrics{ServiceMetrics: s.m, proto: "tcp"}, s.logger),
		tcpReadTimeout,
	)
	s.ph = NewPacketHandler(s.natTimeout, s.ciphers, s.m, &ssConnMetrics{ServiceMetrics: s.m, proto: "udp"})
	if s.logger != nil {
		s.sh.SetLogger(s.logger)
		s.ph.SetLogger(s.logger)
	}

	return s, nil
}

// WithLogger can be used to provide a custom log target.
func WithLogger(l Logger) Option {
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
		s.m = metrics
	}
}

// WithReplayCache option function.
func WithReplayCache(replayCache *ReplayCache) Option {
	return func(s *ssService) {
		s.replayCache = replayCache
	}
}

// WithNatTimeout option function.
func WithNatTimeout(natTimeout time.Duration) Option {
	return func(s *ssService) {
		s.natTimeout = natTimeout
	}
}

// HandleStream handles a Shadowsocks stream-based connection.
func (s *ssService) HandleStream(ctx context.Context, conn transport.StreamConn) {
	connMetrics := s.m.AddOpenTCPConnection(conn)
	s.sh.Handle(ctx, conn, connMetrics)
}

// HandlePacket handles a Shadowsocks packet connection.
func (s *ssService) HandlePacket(conn net.PacketConn) {
	s.ph.Handle(conn)
}

type ssConnMetrics struct {
	ServiceMetrics
	proto string
}

var _ ShadowsocksConnMetrics = (*ssConnMetrics)(nil)

func (cm *ssConnMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	cm.ServiceMetrics.AddCipherSearch(cm.proto, accessKeyFound, timeToCipher)
}
