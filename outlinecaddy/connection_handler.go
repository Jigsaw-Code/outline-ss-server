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
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

// ConnectionHandler represents a named, reusable connection handler.
//
// These handlers are configured within the Outline app and can be shared
// across different applications. A ConnectionHandler compiles and wraps a layer4
// handler, allowing it to be referenced and reused by name. This enables sharing
// configurations and services between different protocol stacks.
//
// For example, you might have a Shadowsocks handler (TCP or UDP) in the layer4
// app and a Shadowsocks-over-WebSockets handler in the HTTP app. Using
// ConnectionHandler, you can wrap a single Shadowsocks handler and reference
// it by name in both the layer4 and HTTP app configurations, ensuring they
// share the same Shadowsocks service configuration.
type ConnectionHandler struct {
	// Name of the connection handler. This is used to reference the handler
	//  within the Outline app configuration.
	Name string `json:"name,omitempty"`

	// WrappedHandlerRaw is the raw JSON configuration for the wrapped
	// layer4.NextHandler. It is unmarshalled and used to create the actual
	// handler instance.
	WrappedHandlerRaw json.RawMessage `json:"handle,omitempty" caddy:"namespace=layer4.handlers inline_key=handler"`

	// compiled is the compiled instance of the wrapped layer4.NextHandler. It is
	// populated during the Provision step.
	compiled layer4.NextHandler
}

var (
	_ caddy.Provisioner  = (*ConnectionHandler)(nil)
	_ layer4.NextHandler = (*ConnectionHandler)(nil)
)

// Provision sets up the connection handler.
func (ch *ConnectionHandler) Provision(ctx caddy.Context) error {
	mod, err := ctx.LoadModule(ch, "WrappedHandlerRaw")
	if err != nil {
		return err
	}
	compiled, ok := mod.(layer4.NextHandler)
	if !ok {
		return fmt.Errorf("module is of type `%T`, expected `layer4.NextHandler`", compiled)
	}
	ch.compiled = compiled
	return nil
}

func (ch *ConnectionHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	return ch.compiled.Handle(cx, next)
}

type ConnectionHandlers []*ConnectionHandler

// Provision sets up all the connection handlers.
func (ch ConnectionHandlers) Provision(ctx caddy.Context) error {
	for i, h := range ch {
		err := h.Provision(ctx)
		if err != nil {
			return fmt.Errorf("connection handler %d: %v", i, err)
		}
	}
	return nil
}
