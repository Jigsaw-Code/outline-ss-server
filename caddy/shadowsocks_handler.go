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

package caddy

import (
	"container/list"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"

	outline "github.com/Jigsaw-Code/outline-ss-server/service"
)

const ssModuleName = "layer4.handlers.shadowsocks"

// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
const defaultNatTimeout time.Duration = 5 * time.Minute

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

type ShadowsocksHandler struct {
	Keys []KeyConfig `json:"keys,omitempty"`

	streamHandler outline.StreamHandler
	associationHandler outline.AssociationHandler
	metrics       outline.ServiceMetrics
	logger        *slog.Logger
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

	mod, err := ctx.AppIfConfigured(outlineModuleName)
	if err != nil {
		return fmt.Errorf("outline app configure error: %w", err)
	}
	app, ok := mod.(*OutlineApp)
	if !ok {
		return fmt.Errorf("module `%s` is of type `%T`, expected `OutlineApp`", outlineModuleName, app)
	}
	h.metrics = app.Metrics

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

	h.streamHandler, h.associationHandler = outline.NewShadowsocksHandlers(
		outline.WithLogger(h.logger),
		outline.WithCiphers(ciphers),
		outline.WithMetrics(h.metrics),
		outline.WithReplayCache(&app.ReplayCache),
	)
	return nil
}

// Handle implements layer4.NextHandler.
func (h *ShadowsocksHandler) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	switch conn := cx.Conn.(type) {
	case transport.StreamConn:
		h.streamHandler.HandleStream(cx.Context, conn, h.metrics.AddOpenTCPConnection(conn))
	case net.Conn:
		h.associationHandler.HandleAssociation(cx.Context, conn, h.metrics.AddOpenUDPAssociation(conn))
	default:
		return fmt.Errorf("failed to handle unknown connection type: %t", conn)
	}
	return nil
}
