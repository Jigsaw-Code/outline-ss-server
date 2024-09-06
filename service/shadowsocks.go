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
	"container/list"
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
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

// Option user's option.
type Option func(s *ssService) error

type ssService struct {
	m           ServiceMetrics
	ciphers     CipherList
	natTimeout  time.Duration
	replayCache *ReplayCache

	sh StreamHandler
	ph PacketHandler
}

func NewService(opts ...Option) (Service, error) {
	s := &ssService{}

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, fmt.Errorf("failed to create new service: %v", err)
		}
	}

	if s.natTimeout == 0 {
		s.natTimeout = defaultNatTimeout
	}
	return s, nil
}

// WithConfig option function.
func WithConfig(config ServiceConfig) Option {
	return func(s *ssService) error {
		ciphers, err := newCipherListFromConfig(config)
		if err != nil {
			return fmt.Errorf("failed to create cipher list from config: %v", err)
		}
		s.ciphers = ciphers

		s.natTimeout = time.Duration(config.NatTimeoutSec) * time.Second

		return nil
	}
}

// WithCiphers option function.
func WithCiphers(ciphers CipherList) Option {
	return func(s *ssService) error {
		s.ciphers = ciphers
		return nil
	}
}

// WithMetrics option function.
func WithMetrics(metrics ServiceMetrics) Option {
	return func(s *ssService) error {
		s.m = metrics
		return nil
	}
}

// WithReplayCache option function.
func WithReplayCache(replayCache *ReplayCache) Option {
	return func(s *ssService) error {
		s.replayCache = replayCache
		return nil
	}
}

// WithNatTimeout option function.
func WithNatTimeout(natTimeout time.Duration) Option {
	return func(s *ssService) error {
		s.natTimeout = natTimeout
		return nil
	}
}

// HandleStream handles a Shadowsocks stream-based connection.
func (s *ssService) HandleStream(ctx context.Context, conn transport.StreamConn) {
	if s.sh == nil {
		authFunc := NewShadowsocksStreamAuthenticator(s.ciphers, s.replayCache, &ssConnMetrics{ServiceMetrics: s.m, proto: "tcp"})
		// TODO: Register initial data metrics at zero.
		s.sh = NewStreamHandler(authFunc, tcpReadTimeout)
	}
	connMetrics := s.m.AddOpenTCPConnection(conn)
	s.sh.Handle(ctx, conn, connMetrics)
}

// HandlePacket handles a Shadowsocks packet connection.
func (s *ssService) HandlePacket(conn net.PacketConn) {
	if s.ph == nil {
		s.ph = NewPacketHandler(s.natTimeout, s.ciphers, s.m, &ssConnMetrics{ServiceMetrics: s.m, proto: "udp"})
	}
	s.ph.Handle(conn)
}

func newCipherListFromConfig(config ServiceConfig) (CipherList, error) {
	type cipherKey struct {
		cipher string
		secret string
	}
	cipherList := list.New()
	existingCiphers := make(map[cipherKey]bool)
	for _, keyConfig := range config.Keys {
		key := cipherKey{keyConfig.Cipher, keyConfig.Secret}
		if _, exists := existingCiphers[key]; exists {
			slog.Debug("Encryption key already exists. Skipping.", "ID", keyConfig.ID)
			continue
		}
		cryptoKey, err := shadowsocks.NewEncryptionKey(keyConfig.Cipher, keyConfig.Secret)
		if err != nil {
			return nil, fmt.Errorf("failed to create encyption key for key %v: %w", keyConfig.ID, err)
		}
		entry := MakeCipherEntry(keyConfig.ID, cryptoKey, keyConfig.Secret)
		cipherList.PushBack(&entry)
		existingCiphers[key] = true
	}
	ciphers := NewCipherList()
	ciphers.Update(cipherList)

	return ciphers, nil
}

type ssConnMetrics struct {
	ServiceMetrics
	proto string
}

var _ ShadowsocksConnMetrics = (*ssConnMetrics)(nil)

func (cm *ssConnMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
	cm.ServiceMetrics.AddCipherSearch(cm.proto, accessKeyFound, timeToCipher)
}
