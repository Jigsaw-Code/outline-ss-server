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
	"container/list"
	"sync"
	"time"
)

type LRUCache[K comparable, V any] struct {
	capacity int
	duration time.Duration
	items    map[K]*list.Element
	lru      *list.List
	mu       sync.RWMutex
	done     chan struct{}
}

type entry[K comparable, V any] struct {
	key        K
	value      V
	lastAccess time.Time
}

func NewLRUCache[K comparable, V any](capacity int, duration time.Duration, cleanupInterval time.Duration) *LRUCache[K, V] {
	c := &LRUCache[K, V]{
		capacity: capacity,
		duration: duration,
		items:    make(map[K]*list.Element),
		lru:      list.New(),
		done:     make(chan struct{}),
	}
	go c.cleanup(cleanupInterval)
	return c
}

func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	elem, ok := c.items[key]
	if !ok {
		c.mu.RUnlock()
		var zero V
		return zero, false
	}
	ent := elem.Value.(*entry[K, V])
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(ent.lastAccess) > c.duration {
		c.lru.Remove(elem)
		delete(c.items, key)
		var zero V
		return zero, false
	}

	c.lru.MoveToFront(elem)
	ent.lastAccess = time.Now()
	return ent.value, true
}

func (c *LRUCache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.lru.MoveToFront(elem)
		ent := elem.Value.(*entry[K, V])
		ent.value = value
		ent.lastAccess = time.Now()
		return
	}

	ent := &entry[K, V]{key, value, time.Now()}
	elem := c.lru.PushFront(ent)
	c.items[key] = elem

	if c.lru.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *LRUCache[K, V]) removeOldest() {
	elem := c.lru.Back()
	if elem != nil {
		c.lru.Remove(elem)
		ent := elem.Value.(*entry[K, V])
		delete(c.items, ent.key)
	}
}

func (c *LRUCache[K, V]) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			for elem := c.lru.Back(); elem != nil; elem = c.lru.Back() {
				ent := elem.Value.(*entry[K, V])
				if time.Since(ent.lastAccess) > c.duration {
					c.lru.Remove(elem)
					delete(c.items, ent.key)
				} else {
					break
				}
			}
			c.mu.Unlock()
		case <-c.done:
			return
		}
	}
}

func (c *LRUCache[K, V]) StopCleanup() {
	close(c.done)
}
