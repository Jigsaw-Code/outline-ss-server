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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExpiringMap(t *testing.T) {
	t.Run("BasicSetGet", func(t *testing.T) {
		em := NewExpiringMap[string, int](2 * time.Second)
		em.Set("key1", 10)
		val, ok := em.Get("key1")
		require.True(t, ok)
		require.Equal(t, 10, val)

		time.Sleep(3 * time.Second)

		_, ok = em.Get("key1")
		require.False(t, ok)
	})

	t.Run("Expiration", func(t *testing.T) {
		em := NewExpiringMap[string, int](2 * time.Second)
		em.Set("a", 1)

		time.Sleep(3 * time.Second)

		_, ok := em.Get("a")
		require.False(t, ok, "Expected `a` to have been evicted")
		em.StopCleanup()
	})

	t.Run("Concurrency", func(t *testing.T) {
		em := NewExpiringMap[int, string](2 * time.Second)
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				em.Set(i, fmt.Sprintf("value%d", i))

				time.Sleep(time.Duration(i) * time.Millisecond)

				val, ok := em.Get(i)
				require.True(t, ok)
				require.Equal(t, fmt.Sprintf("value%d", i), val)
			}(i)
		}
		wg.Wait()
	})
}

func BenchmarkExpiringMap(b *testing.B) {
	b.Run("Set", func(b *testing.B) {
		em := NewExpiringMap[int64, int64](10 * time.Second)
		for i := 0; i < b.N; i++ {
			em.Set(int64(i), int64(i))
		}
	})

	b.Run("Get", func(b *testing.B) {
		em := NewExpiringMap[int64, int64](10 * time.Second)
		for i := 0; i < b.N; i++ {
			em.Set(int64(i), int64(i))
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			em.Get(int64(i))
		}
	})
}
