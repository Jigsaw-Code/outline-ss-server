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

package outlinecaddy

import (
	"container/list"
	"fmt"
	"log/slog"
	"net"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	outline "github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

const ssModuleName = "layer4.handlers.shadowsocks"

// Max UDP buffer size for the server code.
const serverUDPBufferSize = 64 * 1024

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  ssModuleName,
		New: func() caddy.Module { return new(ShadowsocksHandler) },
	})
}

type KeyConfig struct {
	ID     string
	Cipher string
	Secret string
}

// ShadowsocksHandler implements a Caddy plugin for Shadowsocks connections.
type ShadowsocksHandler struct {
	Keys []KeyConfig `json:"keys,omitempty"`

	service outline.Service
	buffer  []byte
	logger  *slog.Logger
}

var (
	_ caddy.Provisioner  = (*ShadowsocksHandler)(nil)
	_ layer4.NextHandler = (*ShadowsocksHandler)(nil)
)

func (*ShadowsocksHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: ssModuleName}
}

// Provision implements caddy.Provisioner.
func (h *ShadowsocksHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Slogger()

	if len(h.Keys) == 0 {
		h.logger.Warn("no keys configured")
	}
	type cipherKey struct {
		cipher string
		secret string
	}
	cipherList := list.New()
	existingCiphers := make(map[cipherKey]bool)
	for _, cfg := range h.Keys {
		key := cipherKey{cfg.Cipher, cfg.Secret}
		if _, exists := existingCiphers[key]; exists {
			h.logger.Debug("Encryption key already exists. Skipping.", slog.String("id", cfg.ID))
			continue
		}
		cryptoKey, err := shadowsocks.NewEncryptionKey(cfg.Cipher, cfg.Secret)
		if err != nil {
			return fmt.Errorf("failed to create encyption key for key %v: %w", cfg.ID, err)
		}
		entry := outline.MakeCipherEntry(cfg.ID, cryptoKey, cfg.Secret)
		cipherList.PushBack(&entry)
		existingCiphers[key] = true
	}
	ciphers := outline.NewCipherList()
	ciphers.Update(cipherList)

	replayCache, ok := ctx.Value(replayCacheCtxKey).(outline.ReplayCache)
	if !ok {
		h.logger.Warn("Handler configured outside Outline app; replay cache not available.")
	}
	metrics, ok := ctx.Value(metricsCtxKey).(outline.ServiceMetrics)
	if !ok {
		h.logger.Warn("Handler configured outside Outline app; metrics not available.")
	}

	service, err := outline.NewShadowsocksService(
		outline.WithLogger(h.logger),
		outline.WithCiphers(ciphers),
		outline.WithMetrics(metrics),
		outline.WithReplayCache(&replayCache),
	)
	if err != nil {
		return err
	}
	h.service = service
	h.buffer = make([]byte, serverUDPBufferSize)
	return nil
}

// Handle implements layer4.NextHandler.
func (h *ShadowsocksHandler) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	switch conn := cx.Conn.(type) {
	case transport.StreamConn:
		h.service.HandleStream(cx.Context, &l4StreamConn{Connection: cx, wrappedStreamConn: conn})
	case net.Conn:
		n, err := cx.Read(h.buffer)
		if err != nil {
			return err
		}
		pkt := h.buffer[:n]
		h.service.HandlePacket(cx, pkt)
	default:
		return fmt.Errorf("failed to handle unknown connection type: %T", conn)
	}
	return nil
}

type l4StreamConn struct {
	*layer4.Connection
	wrappedStreamConn transport.StreamConn
}

var _ transport.StreamConn = (*l4StreamConn)(nil)

func (c l4StreamConn) CloseRead() error {
	return c.wrappedStreamConn.CloseRead()
}

func (c l4StreamConn) CloseWrite() error {
	return c.wrappedStreamConn.CloseWrite()
}
