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

package net

import (
	"bufio"
	"net"
)

// BufConn wraps an original [net.Conn] and a [bufio.Reader] to allow reads
// without losing bytes in the buffer.
type BufConn struct {
	*bufio.Reader
	net.Conn
}

func NewBufConn(conn net.Conn) BufConn {
	return BufConn{Reader: bufio.NewReader(conn), Conn: conn}
}

func (c BufConn) Peek(n int) ([]byte, error) {
	return c.Reader.Peek(n)
}

func (c BufConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}
