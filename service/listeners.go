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
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Jigsaw-Code/outline-sdk/transport"
)

type Handler interface {
	NumCiphers() int
	AddCipher(entry *CipherEntry)
	Handle(ctx context.Context, conn any)
}

type acceptResponse struct {
	conn net.Conn
	err  error
}

type SharedListener interface {
	SetHandler(handler Handler)
}

type sharedListener struct {
	listener  net.Listener
	closed    atomic.Int32
	usage     *atomic.Int32
	acceptCh  chan acceptResponse
	closeCh   chan struct{}
	closeFunc func()
}

func (sl *sharedListener) SetHandler(handler Handler) {
	accept := func() (transport.StreamConn, error) {
		c, err := sl.Accept()
		if err == nil {
			return c.(transport.StreamConn), err
		}
		return nil, err
	}
	handle := func(ctx context.Context, conn transport.StreamConn) {
		handler.Handle(ctx, conn)
	}
	go StreamServe(accept, handle)
}

// Accept accepts connections until Close() is called.
func (sl *sharedListener) Accept() (net.Conn, error) {
	if sl.closed.Load() == 1 {
		return nil, net.ErrClosed
	}
	select {
	case acceptResponse := <-sl.acceptCh:
		if acceptResponse.err != nil {
			return nil, acceptResponse.err
		}
		return acceptResponse.conn, nil
	case <-sl.closeCh:
		return nil, net.ErrClosed
	}
}

// Close stops accepting new connections without closing the underlying socket.
// Only when the last user closes it, we actually close it.
func (sl *sharedListener) Close() error {
	if sl.closed.CompareAndSwap(0, 1) {
		close(sl.closeCh)

		// See if we need to actually close the underlying listener.
		if sl.usage.Add(-1) == 0 {
			sl.closeFunc()
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
	closed    atomic.Int32
	usage     *atomic.Int32
	closeFunc func()
}

func (spc *sharedPacketConn) Close() error {
	if spc.closed.CompareAndSwap(0, 1) {
		// See if we need to actually close the underlying listener.
		if spc.usage.Add(-1) == 0 {
			spc.closeFunc()
			err := spc.PacketConn.Close()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (spc *sharedPacketConn) SetHandler(handler Handler) {
	go handler.Handle(context.TODO(), spc.PacketConn)
}

type globalListener struct {
	ln       net.Listener
	pc       net.PacketConn
	usage    atomic.Int32
	acceptCh chan acceptResponse
}

type ListenerSet interface {
	Listen(ctx context.Context, network string, addr string, config net.ListenConfig) (SharedListener, error)
	Close() error
	Len() int
}

type listenerSet struct {
	manager   ListenerManager
	listeners map[string]*SharedListener
}

func (ls *listenerSet) Listen(ctx context.Context, network string, addr string, config net.ListenConfig) (SharedListener, error) {
	lnKey := listenerKey(network, addr)
	if _, exists := ls.listeners[lnKey]; exists {
		return nil, fmt.Errorf("listener %s already exists", lnKey)
	}
	ln, err := ls.manager.Listen(ctx, network, addr, config)
	if err != nil {
		return nil, err
	}
	ls.listeners[lnKey] = &ln
	return ln, nil
}

func (ls *listenerSet) Close() error {
	for _, listener := range ls.listeners {
		switch ln := (*listener).(type) {
		case net.Listener:
			if err := ln.Close(); err != nil {
				return fmt.Errorf("%s listener on address %s failed to stop: %w", ln.Addr().Network(), ln.Addr().String(), err)
			}
		case net.PacketConn:
			if err := ln.Close(); err != nil {
				return fmt.Errorf("%s listener on address %s failed to stop: %w", ln.LocalAddr().Network(), ln.LocalAddr().String(), err)
			}
		default:
			return fmt.Errorf("unknown listener type: %v", ln)
		}
	}
	return nil
}

func (ls *listenerSet) Len() int {
	return len(ls.listeners)
}

// ListenerManager holds and manages the state of shared listeners.
type ListenerManager interface {
	NewListenerSet() ListenerSet
	Listen(ctx context.Context, network string, addr string, config net.ListenConfig) (SharedListener, error)
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

func (m *listenerManager) NewListenerSet() ListenerSet {
	return &listenerSet{
		manager:   m,
		listeners: make(map[string]*SharedListener),
	}
}

// Listen creates a new listener for a given network and address.
//
// Listeners can overlap one another, because during config changes the new
// config is started before the old config is destroyed. This is done by using
// reusable listener wrappers, which do not actually close the underlying socket
// until all uses of the shared listener have been closed.
func (m *listenerManager) Listen(ctx context.Context, network string, addr string, config net.ListenConfig) (SharedListener, error) {
	lnKey := listenerKey(network, addr)

	switch network {

	case "tcp":
		m.listenersMu.Lock()
		defer m.listenersMu.Unlock()

		if lnGlobal, ok := m.listeners[lnKey]; ok {
			lnGlobal.usage.Add(1)
			return &sharedListener{
				listener: lnGlobal.ln,
				usage:    &lnGlobal.usage,
				acceptCh: lnGlobal.acceptCh,
				closeCh:  make(chan struct{}),
				closeFunc: func() {
					m.delete(lnKey)
				},
			}, nil
		}

		ln, err := config.Listen(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		lnGlobal := &globalListener{ln: ln, acceptCh: make(chan acceptResponse)}
		go func() {
			for {
				conn, err := lnGlobal.ln.Accept()
				lnGlobal.acceptCh <- acceptResponse{conn, err}
			}
		}()
		lnGlobal.usage.Store(1)
		m.listeners[lnKey] = lnGlobal

		return &sharedListener{
			listener: ln,
			usage:    &lnGlobal.usage,
			acceptCh: lnGlobal.acceptCh,
			closeCh:  make(chan struct{}),
			closeFunc: func() {
				m.delete(lnKey)
			},
		}, nil

	case "udp":
		m.listenersMu.Lock()
		defer m.listenersMu.Unlock()

		if lnGlobal, ok := m.listeners[lnKey]; ok {
			lnGlobal.usage.Add(1)
			return &sharedPacketConn{
				PacketConn: lnGlobal.pc,
				usage:      &lnGlobal.usage,
				closeFunc: func() {
					m.delete(lnKey)
				},
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
			usage:      &lnGlobal.usage,
			closeFunc: func() {
				m.delete(lnKey)
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported network: %s", network)

	}
}

func (m *listenerManager) delete(key string) {
	m.listenersMu.Lock()
	delete(m.listeners, key)
	m.listenersMu.Unlock()
}

func listenerKey(network string, addr string) string {
	return network + "/" + addr
}
