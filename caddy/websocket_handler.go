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
	"bufio"
	"bytes"
	"errors"
	_ "errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/caddyserver/caddy/v2"
	"github.com/gorilla/websocket"
	"github.com/mholt/caddy-l4/layer4"
)

const wsModuleName = "layer4.handlers.websocket"

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  wsModuleName,
		New: func() caddy.Module { return new(WebSocketHandler) },
	})
}

// WebSocketHandler implements a Caddy plugin for WebSocket connections.
type WebSocketHandler struct {
	logger *slog.Logger
	u      websocket.Upgrader
}

var (
	_ caddy.Provisioner  = (*WebSocketHandler)(nil)
	_ layer4.NextHandler = (*WebSocketHandler)(nil)
)

func (*WebSocketHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: wsModuleName}
}

// Provision implements caddy.Provisioner.
func (h *WebSocketHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Slogger()
	return nil
}

// Handle implements layer4.NextHandler.
func (h *WebSocketHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	req, err := http.ReadRequest(bufio.NewReader(cx))
	if err != nil {
		return err
	}

	// Upgrade the TCP connection to a WebSocket connection
	rw := &responseWriter{cx, req.Header}
	wsConn, err := h.u.Upgrade(rw, req, nil)
	if err != nil {
		return fmt.Errorf("error upgrading connection:", err)
	}

	h.logger.Debug("connection established", "URL", req.URL)
	return next.Handle(cx.Wrap(&wsConnWrapper{Conn: wsConn}))
}

// wsConnWrapper converts a [websocket.Conn] to a [transport.StreamConn].
type wsConnWrapper struct {
	*websocket.Conn
	readBuf bytes.Buffer // Buffer for storing incomplete frames
}

var _ net.Conn = (*wsConnWrapper)(nil)
var _ transport.StreamConn = (*wsConnWrapper)(nil)

func (c *wsConnWrapper) Read(b []byte) (n int, err error) {
	for c.readBuf.Len() < len(b) {
		messageType, reader, err := c.Conn.NextReader()
		if err != nil {
			return 0, err
		}
		if messageType != websocket.TextMessage {
			return 0, errors.New("must be text message")
		}
		_, err = io.Copy(&c.readBuf, reader)
		if err != nil {
			return 0, err
		}
	}
	return c.readBuf.Read(b)
}

func (c *wsConnWrapper) Write(b []byte) (n int, err error) {
	err = c.WriteMessage(websocket.TextMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConnWrapper) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *wsConnWrapper) CloseRead() error {
	return nil
}

func (c *wsConnWrapper) CloseWrite() error {
	return c.Close()
}

type responseWriter struct {
	conn   net.Conn
	header http.Header
}

var _ http.ResponseWriter = (*responseWriter)(nil)

func (rw *responseWriter) Header() http.Header {
	return http.Header{}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.conn.Write(b)
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	rw.conn.Write([]byte(statusLine))
	rw.header.Write(rw.conn)
	rw.conn.Write([]byte("\r\n"))
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return rw.conn, bufio.NewReadWriter(bufio.NewReader(rw.conn), bufio.NewWriter(rw.conn)), nil
}
