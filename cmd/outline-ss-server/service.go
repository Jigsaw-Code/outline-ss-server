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

package main

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/service"
)

// The implementations of listeners for different network types are not
// interchangeable. The type of listener depends on the network type.
// TODO(sbruens): Create a custom `Listener` type so we can share serving logic,
// dispatching to the handlers based on connection type instead of on the
// listener type.
type Listener = any

type Service struct {
	lnManager   ListenerManager
	natTimeout  time.Duration
	m           *outlineMetrics
	replayCache *service.ReplayCache
	listeners   []Listener
	ciphers     *list.List // Values are *List of *service.CipherEntry.
}

func (s *Service) Serve(lnKey string, listener Listener, cipherList service.CipherList) error {
	switch ln := listener.(type) {
	case net.Listener:
		authFunc := service.NewShadowsocksStreamAuthenticator(cipherList, s.replayCache, s.m)
		// TODO: Register initial data metrics at zero.
		tcpHandler := service.NewTCPHandler(lnKey, authFunc, s.m, tcpReadTimeout)
		accept := func() (transport.StreamConn, error) {
			c, err := ln.Accept()
			if err == nil {
				return c.(transport.StreamConn), err
			}
			return nil, err
		}
		go service.StreamServe(accept, tcpHandler.Handle)
	case net.PacketConn:
		packetHandler := service.NewPacketHandler(s.natTimeout, cipherList, s.m)
		go packetHandler.Handle(ln)
	default:
		return fmt.Errorf("unknown listener type: %v", ln)
	}
	return nil
}

func (s *Service) Stop() error {
	for _, listener := range s.listeners {
		switch ln := listener.(type) {
		case net.Listener:
			if err := ln.Close(); err != nil {
				//lint:ignore ST1005 Shadowsocks is capitalized.
				return fmt.Errorf("Shadowsocks %s service on address %s failed to stop: %w", ln.Addr().Network(), ln.Addr().String(), err)
			}
		case net.PacketConn:
			if err := ln.Close(); err != nil {
				//lint:ignore ST1005 Shadowsocks is capitalized.
				return fmt.Errorf("Shadowsocks %s service on address %s failed to stop: %w", ln.LocalAddr().Network(), ln.LocalAddr().String(), err)
			}
		default:
			return fmt.Errorf("unknown listener type: %v", ln)
		}
	}
	return nil
}

// AddListener adds a new listener to the service.
func (s *Service) AddListener(network string, addr string) error {
	// Create new listeners based on the configured network addresses.
	cipherList := service.NewCipherList()
	cipherList.Update(s.ciphers)

	listener, err := s.lnManager.Listen(context.TODO(), network, addr, net.ListenConfig{KeepAlive: 0})
	if err != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks %s service failed to start on address %s: %w", network, addr, err)
	}
	s.listeners = append(s.listeners, listener)
	logger.Infof("Shadowsocks %s service listening on %s", network, addr)
	lnKey := network + "/" + addr
	if err = s.Serve(lnKey, listener, cipherList); err != nil {
		return fmt.Errorf("failed to serve on %s listener on address %s: %w", network, addr, err)
	}
	return nil
}

func (s *Service) NumListeners() int {
	return len(s.listeners)
}

func (s *Service) AddCipher(entry *service.CipherEntry) {
	s.ciphers.PushBack(entry)
}

func (s *Service) NumCiphers() int {
	return s.ciphers.Len()
}

// NewService creates a new Service based on a config
func NewService(config ServiceConfig, lnManager ListenerManager, natTimeout time.Duration, m *outlineMetrics, replayCache *service.ReplayCache) (*Service, error) {
	s := Service{
		lnManager:   lnManager,
		natTimeout:  natTimeout,
		m:           m,
		replayCache: replayCache,
		ciphers:     list.New(),
	}

	type cipherKey struct {
		cipher string
		secret string
	}
	existingCiphers := make(map[cipherKey]bool)
	for _, keyConfig := range config.Keys {
		key := cipherKey{keyConfig.Cipher, keyConfig.Secret}
		if _, exists := existingCiphers[key]; exists {
			logger.Debugf("encryption key already exists for ID=`%v`. Skipping.", keyConfig.ID)
			continue
		}
		cryptoKey, err := shadowsocks.NewEncryptionKey(keyConfig.Cipher, keyConfig.Secret)
		if err != nil {
			return nil, fmt.Errorf("failed to create encyption key for key %v: %w", keyConfig.ID, err)
		}
		entry := service.MakeCipherEntry(keyConfig.ID, cryptoKey, keyConfig.Secret)
		s.AddCipher(&entry)
		existingCiphers[key] = true
	}

	for _, listener := range config.Listeners {
		network := string(listener.Type)
		if err := s.AddListener(network, listener.Address); err != nil {
			return nil, err
		}
	}

	return &s, nil
}
