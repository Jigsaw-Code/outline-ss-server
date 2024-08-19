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

package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLRUCache(t *testing.T) {
	t.Run("BasicSetGet", func(t *testing.T) {
		cache := NewLRUCache[string, int](2, time.Minute, time.Minute)

		cache.Set("a", 1)
		cache.Set("b", 2)
		a, aOk := cache.Get("a")
		b, bOk := cache.Get("b")

		require.True(t, aOk)
		require.Equal(t, 1, a)
		require.True(t, bOk)
		require.Equal(t, 2, b)
		cache.StopCleanup()
	})

	t.Run("LRUEviction", func(t *testing.T) {
		cache := NewLRUCache[string, int](2, time.Minute, time.Minute)

		cache.Set("a", 1)
		cache.Set("b", 2)
		cache.Set("c", 3)

		_, ok := cache.Get("a")
		require.False(t, ok, "Expected `a` to have been evicted")
		v, ok := cache.Get("b")
		require.True(t, ok, "Did not expect `b` to have been evicted")
		require.Equal(t, 2, v)
		v, ok = cache.Get("c")
		require.True(t, ok, "Did not expect `c` to have been evicted")
		require.Equal(t, 3, v)
		cache.StopCleanup()
	})

	t.Run("Expiration", func(t *testing.T) {
		cache := NewLRUCache[string, int](2, 500*time.Millisecond, time.Minute)
		cache.Set("a", 1)

		time.Sleep(600 * time.Millisecond)

		_, ok := cache.Get("a")
		require.False(t, ok, "Expected `a` to have been evicted")
		cache.StopCleanup()
	})

	t.Run("Cleanup", func(t *testing.T) {
		cache := NewLRUCache[string, int](2, 500*time.Millisecond, 200*time.Millisecond)
		cache.Set("a", 1)

		time.Sleep(600 * time.Millisecond)

		require.Len(t, cache.items, 0, "Expected `a` to have been evicted in cleanup")
		cache.StopCleanup()
	})
}
