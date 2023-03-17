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

package service

import (
	"encoding/binary"
	"testing"
)

const keyID = "the key"

var counter uint32 = 0

func makeSalts(n int) [][]byte {
	salts := make([][]byte, n)
	for i := 0; i < n; i++ {
		salts[i] = make([]byte, 4)
		binary.BigEndian.PutUint32(salts[i], counter)
		counter++
		if counter == 0 {
			panic("Salt counter overflow")
		}
	}
	return salts
}

func TestReplayCache_Active(t *testing.T) {
	salts := makeSalts(2)
	cache := NewReplayCache(10)
	if !cache.Add(keyID, salts[0]) {
		t.Error("First addition to a clean cache should succeed")
	}
	if cache.Add(keyID, salts[0]) {
		t.Error("Duplicate add should fail")
	}
	if !cache.Add(keyID, salts[1]) {
		t.Error("Addition of a new vector should succeed")
	}
	if cache.Add(keyID, salts[1]) {
		t.Error("Second duplicate add should fail")
	}
}

func TestReplayCache_Archive(t *testing.T) {
	salts0 := makeSalts(10)
	salts1 := makeSalts(10)
	cache := NewReplayCache(10)
	// Add vectors to the active set until it hits the limit
	// and spills into the archive.
	for _, s := range salts0 {
		if !cache.Add(keyID, s) {
			t.Error("Addition of a new vector should succeed")
		}
	}

	for _, s := range salts0 {
		if cache.Add(keyID, s) {
			t.Error("Duplicate add should fail")
		}
	}

	// Repopulate the active set.
	for _, s := range salts1 {
		if !cache.Add(keyID, s) {
			t.Error("Addition of a new vector should succeed")
		}
	}

	// Both active and archive are full.  Adding another vector
	// should wipe the archive.
	lastStraw := makeSalts(1)[0]
	if !cache.Add(keyID, lastStraw) {
		t.Error("Addition of a new vector should succeed")
	}
	for _, s := range salts0 {
		if !cache.Add(keyID, s) {
			t.Error("First 10 vectors should have been forgotten")
		}
	}
}

// Benchmark to determine the memory usage of ReplayCache.
// Note that NewReplayCache only allocates the active set,
// so the eventual memory usage will be roughly double.
func BenchmarkReplayCache_Creation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewReplayCache(MaxCapacity)
	}
}

func BenchmarkReplayCache_Max(b *testing.B) {
	salts := makeSalts(b.N)
	// Archive replacements will be infrequent.
	cache := NewReplayCache(MaxCapacity)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(keyID, salts[i])
	}
}

func BenchmarkReplayCache_Min(b *testing.B) {
	salts := makeSalts(b.N)
	// Every addition will archive the active set.
	cache := NewReplayCache(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(keyID, salts[i])
	}
}

func BenchmarkReplayCache_Parallel(b *testing.B) {
	c := make(chan []byte, b.N)
	for _, s := range makeSalts(b.N) {
		c <- s
	}
	close(c)
	// Exercise both expansion and archiving.
	cache := NewReplayCache(100)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Add(keyID, <-c)
		}
	})
}
