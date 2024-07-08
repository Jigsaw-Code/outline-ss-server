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
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type sharedListener struct {
	listener   net.Listener
	manager    ListenerManager
	key        string
	closed     atomic.Int32
	usage      *atomic.Int32
	deadline   *bool
	deadlineMu *sync.Mutex
}

// Accept accepts connections until Close() is called.
func (sl *sharedListener) Accept() (net.Conn, error) {
	if sl.closed.Load() == 1 {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  sl.listener.Addr().Network(),
			Addr: sl.listener.Addr(),
			Err:  net.ErrClosed,
		}
	}

	conn, err := sl.listener.Accept()
	if err == nil {
		return conn, nil
	}

	sl.deadlineMu.Lock()
	if *sl.deadline {
		switch ln := sl.listener.(type) {
		case *net.TCPListener:
			ln.SetDeadline(time.Time{})
		}
		*sl.deadline = false
	}
	sl.deadlineMu.Unlock()

	if sl.closed.Load() == 1 {
		// In `Close()` we set a deadline in the past to force currently-blocked
		// listeners to close without having to close the underlying socket. To
		// avoid callers from retrying, we avoid returning timeout errors and
		// instead make sure we return a fake "closed" error.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, &net.OpError{
				Op:   "accept",
				Net:  sl.listener.Addr().Network(),
				Addr: sl.listener.Addr(),
				Err:  net.ErrClosed,
			}
		}
	}

	return nil, err
}

// Close stops accepting new connections without closing the underlying socket.
// Only when the last user closes it, we actually close it.
func (sl *sharedListener) Close() error {
	if sl.closed.CompareAndSwap(0, 1) {
		// NOTE: In order to cancel current calls to Accept(), we set a deadline in
		// the past, as we cannot actually close the listener.
		sl.deadlineMu.Lock()
		if !*sl.deadline {
			switch ln := sl.listener.(type) {
			case *net.TCPListener:
				ln.SetDeadline(time.Now().Add(-1 * time.Minute))
			}
			*sl.deadline = true
		}
		sl.deadlineMu.Unlock()

		// See if we need to actually close the underlying listener.
		if sl.usage.Add(-1) == 0 {
			sl.manager.Delete(sl.key)
			err := sl.listener.Close()
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func (sl *sharedListener) Addr() net.Addr {
	return sl.listener.Addr()
}

type sharedPacketConn struct {
	net.PacketConn
	manager ListenerManager
	key     string
	closed  atomic.Int32
	usage   *atomic.Int32
}

func (spc *sharedPacketConn) Close() error {
	if spc.closed.CompareAndSwap(0, 1) {
		// See if we need to actually close the underlying listener.
		if spc.usage.Add(-1) == 0 {
			spc.manager.Delete(spc.key)
			err := spc.PacketConn.Close()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type globalListener struct {
	ln         net.Listener
	pc         net.PacketConn
	usage      atomic.Int32
	deadline   bool
	deadlineMu sync.Mutex
}

// ListenerManager holds and manages the state of shared listeners.
type ListenerManager interface {
	Listen(ctx context.Context, network string, addr string, config net.ListenConfig) (any, error)
	Delete(key string)
}

type listenerManager struct {
	listeners   map[string]*globalListener
	listenersMu sync.Mutex
}

func NewListenerManager() ListenerManager {
	return &listenerManager{
		listeners: make(map[string]*globalListener),
	}
}

// Listen creates a new listener for a given network and address.
//
// Listeners can overlap one another, because during config changes the new
// config is started before the old config is destroyed. This is done by using
// reusable listener wrappers, which do not actually close the underlying socket
// until all uses of the shared listener have been closed.
func (m *listenerManager) Listen(ctx context.Context, network string, addr string, config net.ListenConfig) (any, error) {
	lnKey := listenerKey(network, addr)

	switch network {

	case "tcp":
		m.listenersMu.Lock()
		defer m.listenersMu.Unlock()

		if lnGlobal, ok := m.listeners[lnKey]; ok {
			lnGlobal.usage.Add(1)
			return &sharedListener{
				listener:   lnGlobal.ln,
				manager:    m,
				key:        lnKey,
				usage:      &lnGlobal.usage,
				deadline:   &lnGlobal.deadline,
				deadlineMu: &lnGlobal.deadlineMu,
			}, nil
		}

		ln, err := config.Listen(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		lnGlobal := &globalListener{ln: ln}
		lnGlobal.usage.Store(1)
		m.listeners[lnKey] = lnGlobal

		return &sharedListener{
			listener:   ln,
			manager:    m,
			key:        lnKey,
			usage:      &lnGlobal.usage,
			deadline:   &lnGlobal.deadline,
			deadlineMu: &lnGlobal.deadlineMu,
		}, nil

	case "udp":
		m.listenersMu.Lock()
		defer m.listenersMu.Unlock()

		if lnGlobal, ok := m.listeners[lnKey]; ok {
			lnGlobal.usage.Add(1)
			return &sharedPacketConn{
				PacketConn: lnGlobal.pc,
				manager:    m,
				key:        lnKey,
				usage:      &lnGlobal.usage,
			}, nil
		}

		pc, err := config.ListenPacket(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		lnGlobal := &globalListener{pc: pc}
		lnGlobal.usage.Store(1)
		m.listeners[lnKey] = lnGlobal

		return &sharedPacketConn{
			PacketConn: pc,
			manager:    m,
			key:        lnKey,
			usage:      &lnGlobal.usage,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported network: %s", network)

	}
}

func (m *listenerManager) Delete(key string) {
	m.listenersMu.Lock()
	delete(m.listeners, key)
	m.listenersMu.Unlock()
}

func listenerKey(network string, addr string) string {
	return network + "/" + addr
}
