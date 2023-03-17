// Copyright 2020 Jigsaw Operations LLC
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

package shadowsocks

import (
	"testing"
)

func assertCipher(t *testing.T, name string, saltSize, tagSize int) {
	cipher, err := NewCipher(name, "")
	if err != nil {
		t.Fatal(err)
	}
	if cipher.SaltSize() != saltSize || cipher.TagSize() != tagSize {
		t.Fatalf("Bad spec for %v", name)
	}
}

func TestSizes(t *testing.T) {
	// Values from https://shadowsocks.org/en/spec/AEAD-Ciphers.html
	assertCipher(t, "chacha20-ietf-poly1305", 32, 16)
	assertCipher(t, "aes-256-gcm", 32, 16)
	assertCipher(t, "aes-192-gcm", 24, 16)
	assertCipher(t, "aes-128-gcm", 16, 16)
}

func TestUnsupportedCipher(t *testing.T) {
	_, err := NewCipher("aes-256-cfb", "")
	if err == nil {
		t.Errorf("Should get an error for unsupported cipher")
	}
}

func TestMaxNonceSize(t *testing.T) {
	for _, aeadName := range SupportedCipherNames() {
		cipher, err := NewCipher(aeadName, "")
		if err != nil {
			t.Errorf("Failed to create Cipher %v: %v", aeadName, err)
		}
		aead, err := cipher.NewAEAD(make([]byte, cipher.SaltSize()))
		if err != nil {
			t.Errorf("Failed to create AEAD %v: %v", aeadName, err)
		}
		if aead.NonceSize() > len(zeroNonce) {
			t.Errorf("Cipher %v has nonce size %v > zeroNonce (%v)", aeadName, aead.NonceSize(), len(zeroNonce))
		}
	}
}
