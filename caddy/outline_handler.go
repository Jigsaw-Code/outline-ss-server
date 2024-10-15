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
	"errors"
	"fmt"
	"log/slog"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

const outlineHandlerModuleName = "layer4.handlers.outline"

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  outlineHandlerModuleName,
		New: func() caddy.Module { return new(OutlineHandler) },
	})
}

// OutlineHandler implements a Caddy layer4 plugin for Outline connections.
type OutlineHandler struct {
	ConnectionHandler string `json:"connection_handler,omitempty"`
	compiledHandler   layer4.NextHandler

	logger *slog.Logger
}

var (
	_ caddy.Provisioner  = (*OutlineHandler)(nil)
	_ caddy.Validator    = (*OutlineHandler)(nil)
	_ layer4.NextHandler = (*OutlineHandler)(nil)
)

func (*OutlineHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: outlineHandlerModuleName}
}

// Provision implements caddy.Provisioner.
func (h *OutlineHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Slogger()

	mod, err := ctx.AppIfConfigured(outlineModuleName)
	if err != nil {
		return fmt.Errorf("outline app configure error: %w", err)
	}
	app, ok := mod.(*OutlineApp)
	if !ok {
		return fmt.Errorf("module `%s` is of type `%T`, expected `OutlineApp`", outlineModuleName, app)
	}
	for _, compiledHandler := range app.Handlers {
		if compiledHandler.Name == h.ConnectionHandler {
			h.compiledHandler = compiledHandler
			break
		}
	}
	if h.compiledHandler == nil {
		return fmt.Errorf("no connection handler configured for `%s`", h.ConnectionHandler)
	}

	return nil
}

// Validate implements caddy.Validator.
func (h *OutlineHandler) Validate() error {
	if h.ConnectionHandler == "" {
		return errors.New("must specify `connection_handler`")
	}
	return nil
}

// Handle implements layer4.NextHandler.
func (h *OutlineHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	return h.compiledHandler.Handle(cx, next)
}
