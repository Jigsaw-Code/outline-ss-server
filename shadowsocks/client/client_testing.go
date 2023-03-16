// Copyright 2023 Jigsaw Operations LLC
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

package client

import (
	"bytes"
	"io"
	"testing"

	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
)

const (
	testTargetAddr = "test.local:1111"
)

// Writes `payload` to `conn` and reads it into `buf`, which we take as a parameter to avoid
// reallocations in benchmarks and memory profiles. Fails the test if the read payload does not match.
func expectEchoPayload(conn io.ReadWriter, payload, buf []byte, t testing.TB) {
	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Failed to write payload: %v", err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read payload: %v", err)
	}
	if !bytes.Equal(payload, buf[:n]) {
		t.Fatalf("Expected output '%v'. Got '%v'", payload, buf[:n])
	}
}

func makeTestCipher(tb testing.TB) *shadowsocks.Cipher {
	cipher, err := shadowsocks.NewCipher(shadowsocks.TestCipher, "testPassword")
	if err != nil {
		tb.Fatalf("Failed to create cipher: %v", err)
	}
	return cipher
}
