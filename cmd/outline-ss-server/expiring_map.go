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
	"sync"
	"sync/atomic"
	"time"
)

// ExpiringMap is a thread-safe, generic map that automatically removes
// key-value pairs after a specified duration of inactivity.
// It employs reference counting to ensure safe concurrent access and prevent
// premature deletion during cleanup.
type ExpiringMap[K comparable, V any] struct {
	data       map[K]*item[V]
	mu         sync.RWMutex
	expiryTime time.Duration
	done       chan struct{}
}

type item[V any] struct {
	value      V
	lastAccess time.Time
	refCount   int32
}

func NewExpiringMap[K comparable, V any](expiryTime time.Duration) *ExpiringMap[K, V] {
	em := &ExpiringMap[K, V]{
		data:       make(map[K]*item[V]),
		expiryTime: expiryTime,
		done:       make(chan struct{}),
	}
	go em.cleanupLoop()
	return em
}

func (em *ExpiringMap[K, V]) Set(key K, value V) {
	em.mu.Lock()
	defer em.mu.Unlock()

	em.data[key] = &item[V]{
		value:      value,
		lastAccess: time.Now(),
		refCount:   0,
	}
}

func (em *ExpiringMap[K, V]) Get(key K) (V, bool) {
	em.mu.RLock()
	item, ok := em.data[key]
	if !ok {
		em.mu.RUnlock()
		var zeroValue V
		return zeroValue, false
	}

	atomic.AddInt32(&item.refCount, 1)
	em.mu.RUnlock()

	em.mu.Lock()
	defer em.mu.Unlock()

	atomic.AddInt32(&item.refCount, -1)

	item.lastAccess = time.Now()
	return item.value, true
}

func (em *ExpiringMap[K, V]) cleanup() {
	em.mu.Lock()
	defer em.mu.Unlock()

	for key, item := range em.data {
		if time.Since(item.lastAccess) > em.expiryTime && atomic.LoadInt32(&item.refCount) == 0 {
			delete(em.data, key)
		}
	}
}

func (em *ExpiringMap[K, V]) cleanupLoop() {
	ticker := time.NewTicker(em.expiryTime / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			em.cleanup()
		case <-em.done:
			return
		}
	}
}

func (em *ExpiringMap[K, V]) StopCleanup() {
	close(em.done)
}
