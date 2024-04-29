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

type BufferedConn struct {
	R *bufio.Reader
	net.Conn
}

func NewBufferedConn(c net.Conn) BufferedConn {
	return BufferedConn{bufio.NewReader(c), c}
}

func (b BufferedConn) Peek(n int) ([]byte, error) {
	return b.R.Peek(n)
}

func (b BufferedConn) Read(p []byte) (int, error) {
	return b.R.Read(p)
}
