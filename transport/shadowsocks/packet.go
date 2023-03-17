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
	"errors"
	"io"
)

// ErrShortPacket is identical to shadowaead.ErrShortPacket
var ErrShortPacket = errors.New("short packet")

// Pack encrypts a Shadowsocks-UDP packet and returns a slice containing the encrypted packet.
// dst must be big enough to hold the encrypted packet.
// If plaintext and dst overlap but are not aligned for in-place encryption, this
// function will panic.
func Pack(dst, plaintext []byte, cipher *Cipher) ([]byte, error) {
	saltSize := cipher.SaltSize()
	if len(dst) < saltSize {
		return nil, io.ErrShortBuffer
	}
	salt := dst[:saltSize]
	if err := RandomSaltGenerator.GetSalt(salt); err != nil {
		return nil, err
	}

	aead, err := cipher.NewAEAD(salt)
	if err != nil {
		return nil, err
	}

	if len(dst) < saltSize+len(plaintext)+aead.Overhead() {
		return nil, io.ErrShortBuffer
	}
	return aead.Seal(salt, zeroNonce[:aead.NonceSize()], plaintext, nil), nil
}

// Unpack decrypts a Shadowsocks-UDP packet and returns a slice containing the decrypted payload or an error.
// If dst is present, it is used to store the plaintext, and must have enough capacity.
// If dst is nil, decryption proceeds in-place.
// This function is needed because shadowaead.Unpack() embeds its own replay detection,
// which we do not always want, especially on memory-constrained clients.
func Unpack(dst, pkt []byte, cipher *Cipher) ([]byte, error) {
	saltSize := cipher.SaltSize()
	if len(pkt) < saltSize {
		return nil, ErrShortPacket
	}
	salt := pkt[:saltSize]
	msg := pkt[saltSize:]
	if dst == nil {
		dst = msg
	}
	return DecryptOnce(cipher, salt, dst[:0], msg)
}
