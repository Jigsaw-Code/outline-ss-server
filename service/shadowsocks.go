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
	"errors"
	"net/netip"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
)

// findAccessKey implements a trial decryption search. This assumes that all ciphers are AEAD.
func findAccessKey(clientIP netip.Addr, bufferSize int, src []byte, cipherList CipherList, logDebug DebugLoggerFunc) (*CipherEntry, []byte, time.Duration, error) {
	// We snapshot the list because it may be modified while we use it.
	ciphers := cipherList.SnapshotForClientIP(clientIP)

	unpackStart := time.Now()
	// To hold the decrypted chunk length.
	chunkLenBuf := make([]byte, bufferSize)
	for ci, elt := range ciphers {
		entry := elt.Value.(*CipherEntry)
		buf, err := shadowsocks.Unpack(chunkLenBuf, src, entry.CryptoKey)
		if err != nil {
			logDebug(entry.ID, "Failed to unpack: %v", err)
			continue
		}
		logDebug(entry.ID, "Found cipher at index %d", ci)

		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.MarkUsedByClientIP(elt, clientIP)
		return entry, buf, time.Since(unpackStart), nil
	}
	return nil, nil, time.Since(unpackStart), errors.New("could not find valid cipher")
}
