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
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
)

// bytesForKeyFinding is the number of bytes to read for finding the AccessKey.
// Is must satisfy provided >= bytesForKeyFinding >= required for every cipher in the list.
// provided = saltSize + 2 + 2 * cipher.TagSize, the minimum number of bytes we will see in a valid connection
// required = saltSize + 2 + cipher.TagSize, the number of bytes needed to authenticate the connection.
const bytesForKeyFinding = 50

func findAccessKey(clientReader io.Reader, clientIP netip.Addr, bufferSize int, cipherList CipherList) (*CipherEntry, io.Reader, []byte, time.Duration, error) {
	firstBytes := make([]byte, bytesForKeyFinding)
	if n, err := io.ReadFull(clientReader, firstBytes); err != nil {
		return nil, clientReader, nil, 0, fmt.Errorf("reading header failed after %d bytes: %w", n, err)
	}

	// We snapshot the list because it may be modified while we use it.
	ciphers := cipherList.SnapshotForClientIP(clientIP)

	findStartTime := time.Now()
	entry, _, elt, err := findEntry(firstBytes, bufferSize, ciphers)
	timeToCipher := time.Since(findStartTime)
	if err != nil {
		// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
		return nil, clientReader, nil, timeToCipher, err
	}

	// Move the active cipher to the front, so that the search is quicker next time.
	cipherList.MarkUsedByClientIP(elt, clientIP)
	salt := firstBytes[:entry.CryptoKey.SaltSize()]
	return entry, io.MultiReader(bytes.NewReader(firstBytes), clientReader), salt, timeToCipher, nil
}

// findAccessKeyUDP decrypts src. It tries each cipher until it finds one that
// authenticates correctly.
func findAccessKeyUDP(clientIP netip.Addr, bufferSize int, src []byte, cipherList CipherList) (*CipherEntry, []byte, error) {
	// We snapshot the list because it may be modified while we use it.
	ciphers := cipherList.SnapshotForClientIP(clientIP)

	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	chunkLenBuf := make([]byte, bufferSize)
	for ci, elt := range ciphers {
		entry := elt.Value.(*CipherEntry)
		cryptoKey := entry.CryptoKey
		buf, err := shadowsocks.Unpack(chunkLenBuf, src, cryptoKey)
		if err != nil {
			debugUDP(entry.ID, "Failed to unpack: %v", err)
			continue
		}
		debugUDP(entry.ID, "Found cipher at index %d", ci)
		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.MarkUsedByClientIP(elt, clientIP)
		return entry, buf, nil
	}
	return nil, nil, errors.New("could not find valid cipher")
}

// Implements a trial decryption search. This assumes that all ciphers are AEAD.
func findEntry(src []byte, bufferSize int, ciphers []*list.Element) (*CipherEntry, []byte, *list.Element, error) {
	// To hold the decrypted chunk length.
	chunkLenBuf := make([]byte, bufferSize)
	for ci, elt := range ciphers {
		entry := elt.Value.(*CipherEntry)
		cryptoKey := entry.CryptoKey
		buf, err := shadowsocks.Unpack(chunkLenBuf, src[:cryptoKey.SaltSize()+2+cryptoKey.TagSize()], cryptoKey)
		if err != nil {
			debugTCP(entry.ID, "Failed to decrypt length: %v", err)
			continue
		}
		debugTCP(entry.ID, "Found cipher at index %d", ci)
		return entry, buf, elt, nil
	}
	return nil, nil, nil, errors.New("could not find valid cipher")
}
