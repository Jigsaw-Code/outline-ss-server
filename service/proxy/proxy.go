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

package proxy

import (
	"io"
	"net/http"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func ParseShadowsocks(reader io.Reader) (string, error) {
	tgtAddr, err := socks.ReadAddr(reader)
	if err != nil {
		return "", err
	}
	return tgtAddr.String(), nil
}

func ParseSocks(rw io.ReadWriter) (string, error) {
	tgtAddr, err := socks.Handshake(rw)
	if err != nil {
		return "", err
	}

	return tgtAddr.String(), nil
}

func ParseHTTP(conn onet.BufferedConn) (string, error) {
	req, err := http.ReadRequest(conn.R)
	if err != nil {
		return "", err
	}

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n" +
		"Proxy-agent: Outline-Proxy\r\n" +
		"\r\n"))
	target := req.RequestURI
	return target, nil
}
