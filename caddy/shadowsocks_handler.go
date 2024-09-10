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

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	outline "github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&ShadowsocksHandler{})
}

type KeyConfig struct {
	ID     string
	Cipher string
	Secret string
}

type ShadowsocksHandler struct {
	Keys          []KeyConfig `json:"keys,omitempty"`

	service outline.Service
	logger  *slog.Logger
}

func (*ShadowsocksHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.shadowsocks",
		New: func() caddy.Module { return new(ShadowsocksHandler) },
	}
}

// Provision implements caddy.Provisioner.
func (h *ShadowsocksHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Slogger()

	ctx.App(moduleName)
	if _, err := ctx.AppIfConfigured(moduleName); err != nil {
		return fmt.Errorf("outline app configure error: %w", err)
	}
	mod, err := ctx.App(moduleName)
	if err != nil {
		return err
	}
	app, ok := mod.(*OutlineApp)
	if !ok {
		return fmt.Errorf("module `%s` is not an OutlineApp", moduleName)
	}

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
			h.logger.Debug("Encryption key already exists. Skipping.", zap.String("id", cfg.ID))
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

	service, err := outline.NewShadowsocksService(
		outline.WithLogger(h.logger),
		outline.WithCiphers(ciphers),
		outline.WithMetrics(app.Metrics),
		outline.WithReplayCache(&app.ReplayCache),
	)
	if err != nil {
		return err
	}
	h.service = service
	return nil
}

// Handle implements layer4.NextHandler.
func (h *ShadowsocksHandler) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	switch conn := cx.Conn.(type) {
	case transport.StreamConn:
		h.service.HandleStream(cx.Context, conn)
	case net.PacketConn:
		h.service.HandlePacket(conn)
	default:
		return fmt.Errorf("failed to handle unknown connection type: %t", conn)
	}
	return nil
}

var (
	_ caddy.Provisioner  = (*ShadowsocksHandler)(nil)
	_ layer4.NextHandler = (*ShadowsocksHandler)(nil)
)
