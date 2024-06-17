// Copyright 2024 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"bufio"
	"fmt"
	"net"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	proxyproto "github.com/pires/go-proxyproto"
)

type DirectListener struct {
	net.Listener
}

func (l *DirectListener) Accept() (IClientStreamConn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c.(*net.TCPConn).SetKeepAlive(true)
	return &clientStreamConn{StreamConn: c.(transport.StreamConn)}, nil
}

// ProxyListener wraps a [net.Listener] and fetches the source of the connection from the PROXY
// protocol header string. See https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt.
type ProxyListener struct {
	net.Listener
}

// Accept waits for and returns the next incoming connection.
func (l *ProxyListener) Accept() (IClientStreamConn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn := c.(transport.StreamConn)
	r := bufio.NewReader(conn)
	h, err := proxyproto.Read(r)
	if err == proxyproto.ErrNoProxyProtocol {
		logger.Warningf("Received connection from %v without proxy header.", conn.RemoteAddr())
		return &clientStreamConn{StreamConn: conn}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error parsing proxy header: %v", err)
	}

	conn.(*net.TCPConn).SetKeepAlive(true)
	clientConn := transport.WrapConn(conn, r, conn)
	return &clientStreamConn{clientConn, h.SourceAddr}, nil
}
