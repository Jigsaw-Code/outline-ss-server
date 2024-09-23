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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/websocket"
)

const wsModuleName = "http.handlers.websocket"

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  wsModuleName,
		New: func() caddy.Module { return new(WebSocketHandler) },
	})
}

// WebSocketHandler implements a middleware Caddy handler that proxies
// WebSockets connections.
type WebSocketHandler struct {
	// The address of the backend to connect to.
	Backend string `json:"backend,omitempty"`

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
	return nil
}

// Validate implements caddy.Validator.
func (h *WebSocketHandler) Validate() error {
	if h.Backend == "" {
		return errors.New("must specify `backend`")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h WebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	h.logger.Info("handling websocket connection", slog.String("path", r.URL.Path))

	backendAddr, err := caddy.ParseNetworkAddress(h.Backend)
	if err != nil {
		return fmt.Errorf("unable to parse `backend` network address: %v", err)
	}

	var handler func(wsConn *websocket.Conn)
	switch backendAddr.Network {
	case "tcp":
		streamDialer := &transport.TCPDialer{}
		endpoint := transport.StreamDialerEndpoint{Dialer: streamDialer, Address: backendAddr.JoinHostPort(0)}
		handler = func(wsConn *websocket.Conn) {
			targetConn, err := endpoint.ConnectStream(r.Context())
			if err != nil {
				h.logger.Error("failed to connect to backend", slog.Any("err", err))
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			defer targetConn.Close()

			go func() {
				io.Copy(targetConn, wsConn)
				targetConn.CloseWrite()
			}()

			io.Copy(wsConn, targetConn)
			wsConn.Close()
		}
	case "udp":
		packetDialer := &transport.UDPDialer{}
		endpoint := transport.PacketDialerEndpoint{Dialer: packetDialer, Address: backendAddr.JoinHostPort(0)}
		handler = func(wsConn *websocket.Conn) {
			targetConn, err := endpoint.ConnectPacket(r.Context())
			if err != nil {
				h.logger.Error("failed to connect to backend", slog.Any("err", err))
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			// Expire connection after 5 minutes of idle time, as per
			// https://datatracker.ietf.org/doc/html/rfc4787#section-4.3
			targetConn = &natConn{targetConn, 5 * time.Minute}

			go func() {
				io.Copy(targetConn, wsConn)
				targetConn.Close()
			}()

			io.Copy(wsConn, targetConn)
			wsConn.Close()
		}
	default:
		return fmt.Errorf("unsupported `backend` network: %v", backendAddr.Network)
	}

	websocket.Server{Handler: handler}.ServeHTTP(w, r)
	return nil
}

type natConn struct {
	net.Conn
	mappingTimeout time.Duration
}

// Consider ReadFrom/WriteTo
func (c *natConn) Write(b []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.mappingTimeout))
	return c.Conn.Write(b)
}
