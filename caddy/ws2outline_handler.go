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
	"net"
	"net/http"
	"strconv"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"golang.org/x/net/websocket"
)

const wsModuleName = "http.handlers.ws2outline"

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  wsModuleName,
		New: func() caddy.Module { return new(WebSocketHandler) },
	})
}

type ConnectionType string

const (
	connectionTypeStream ConnectionType = "stream"
	connectionTypePacket ConnectionType = "packet"
)

// WebSocketHandler implements a middleware Caddy web handler that proxies
// WebSockets Outline connections.
type WebSocketHandler struct {
	// The type of connection.
	Type              ConnectionType `json:"type,omitempty"`
	ConnectionHandler string         `json:"connection_handler,omitempty"`
	compiledHandler   layer4.NextHandler

	logger *slog.Logger
}

var (
	_ caddy.Provisioner           = (*WebSocketHandler)(nil)
	_ caddy.Validator             = (*WebSocketHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*WebSocketHandler)(nil)
)

func (*WebSocketHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: wsModuleName}
}

// Provision implements caddy.Provisioner.
func (h *WebSocketHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Slogger()
	if h.Type == "" {
		// The default connection type if not provided is a stream.
		h.Type = connectionTypeStream
	}

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
func (h *WebSocketHandler) Validate() error {
	if h.Type != "" && h.Type != connectionTypeStream && h.Type != connectionTypePacket {
		return fmt.Errorf("unsupported `type`: %v", h.Type)
	}
	if h.ConnectionHandler == "" {
		return errors.New("must specify `connection_handler`")
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h WebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	h.logger.Debug("handling websocket connection", slog.String("path", r.URL.Path))

	var handler func(wsConn *websocket.Conn)
	switch h.Type {
	case connectionTypeStream:
		handler = func(wsConn *websocket.Conn) {
			cx := layer4.WrapConnection(&wsToStreamConn{wsConn}, []byte{}, zap.NewNop())
			defer cx.Close()

			err := h.compiledHandler.Handle(cx, nil)
			if err != nil {
				h.logger.Error("failed to upgrade", "err", err)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
		}
	case connectionTypePacket:
		// TODO: Implement.
		return errors.New("not supported yet")
	}

	websocket.Server{Handler: handler}.ServeHTTP(w, r)
	return nil
}

// wsToStreamConn converts a [websocket.Conn] to a [transport.StreamConn].
type wsToStreamConn struct {
	*websocket.Conn
}

var _ transport.StreamConn = (*wsToStreamConn)(nil)

// RemoteAddr returns the remote network address of the websocket connection.
func (c wsToStreamConn) RemoteAddr() net.Addr {
	wsAddr, ok := c.Conn.RemoteAddr().(*websocket.Addr)
	if !ok {
		return &net.TCPAddr{}
	}
	if wsAddr.URL == nil {
		return &net.TCPAddr{}
	}
	port, err := strconv.Atoi(wsAddr.URL.Port())
	if err != nil {
		return &net.TCPAddr{}
	}
	return &net.TCPAddr{
		IP:   net.ParseIP(wsAddr.URL.Hostname()),
		Port: port,
	}
}

func (c wsToStreamConn) CloseRead() error {
	return c.Close()
}

func (c wsToStreamConn) CloseWrite() error {
	return nil
}
