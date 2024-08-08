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

package service

import (
	"bufio"
	"errors"
	"fmt"

	"github.com/pires/go-proxyproto"
)

// ProxyStreamListener wraps a [StreamListener] and fetches the source of the connection from the PROXY
// protocol header string. See https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt.
type ProxyStreamListener struct {
	StreamListener
}

// AcceptStream waits for the next incoming connection, parses the client IP from the PROXY protocol
// header, and adds it to the connection.
func (l *ProxyStreamListener) AcceptStream() (ClientStreamConn, error) {
	conn, err := l.StreamListener.AcceptStream()
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(conn)
	header, err := proxyproto.Read(r)
	if errors.Is(err, proxyproto.ErrNoProxyProtocol) {
		logger.Warningf("Received connection from %v without proxy header.", conn.RemoteAddr())
		return conn, nil
	}
	if header == nil || err != nil {
		return nil, fmt.Errorf("error parsing proxy header: %v", err)
	}
	if header.Command.IsLocal() {
		return conn, nil
	}
	return &clientStreamConn{StreamConn: conn, clientAddr: header.SourceAddr}, nil
}
