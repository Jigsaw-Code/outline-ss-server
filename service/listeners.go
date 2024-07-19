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
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Jigsaw-Code/outline-sdk/transport"
)

// The implementations of listeners for different network types are not
// interchangeable. The type of listener depends on the network type.
type Listener = io.Closer

type StreamListener interface {
	// Accept waits for and returns the next connection to the listener.
	AcceptStream() (transport.StreamConn, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

type acceptResponse struct {
	conn transport.StreamConn
	err  error
}

type sharedListener struct {
	listener    net.TCPListener
	closed      atomic.Int32
	usage       *atomic.Int32
	acceptCh    chan acceptResponse
	closeCh     chan struct{}
	onCloseFunc func()
}

// Accept accepts connections until Close() is called.
func (sl *sharedListener) AcceptStream() (transport.StreamConn, error) {
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
			sl.onCloseFunc()
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
	closed      atomic.Int32
	usage       *atomic.Int32
	onCloseFunc func()
}

func (spc *sharedPacketConn) Close() error {
	if spc.closed.CompareAndSwap(0, 1) {
		// See if we need to actually close the underlying listener.
		if spc.usage.Add(-1) == 0 {
			spc.onCloseFunc()
			err := spc.PacketConn.Close()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type globalListener struct {
	ln       net.TCPListener
	pc       net.PacketConn
	usage    atomic.Int32
	acceptCh chan acceptResponse
}

// ListenerSet represents a set of listeners listening on unique addresses. Trying
// to listen on the same address twice will result in an error. The set can be
// closed as a unit, which is useful if you want to bring down a group of
// listeners, such as when reloading a new config.
type ListenerSet interface {
	// ListenStream announces on a given TCP network address.
	ListenStream(addr string) (StreamListener, error)
	// ListenStream announces on a given UDP network address.
	ListenPacket(addr string) (net.PacketConn, error)
	// Close closes all the listeners in the set.
	Close() error
	// Len returns the number of listeners in the set.
	Len() int
}

type listenerSet struct {
	manager   ListenerManager
	listeners map[string]Listener
}

// ListenStream announces on a given TCP network address.
func (ls *listenerSet) ListenStream(addr string) (StreamListener, error) {
	network := "tcp"
	lnKey := listenerKey(network, addr)
	if _, exists := ls.listeners[lnKey]; exists {
		return nil, fmt.Errorf("listener %s already exists", lnKey)
	}
	ln, err := ls.manager.ListenStream(network, addr)
	if err != nil {
		return nil, err
	}
	ls.listeners[lnKey] = ln
	return ln, nil
}

// ListenPacket announces on a given UDP network address.
func (ls *listenerSet) ListenPacket(addr string) (net.PacketConn, error) {
	network := "udp"
	lnKey := listenerKey(network, addr)
	if _, exists := ls.listeners[lnKey]; exists {
		return nil, fmt.Errorf("listener %s already exists", lnKey)
	}
	ln, err := ls.manager.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}
	ls.listeners[lnKey] = ln
	return ln, nil
}

// Close closes all the listeners in the set.
func (ls *listenerSet) Close() error {
	for _, listener := range ls.listeners {
		switch ln := listener.(type) {
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

// Len returns the number of listeners in the set.
func (ls *listenerSet) Len() int {
	return len(ls.listeners)
}

// ListenerManager holds and manages the state of shared listeners.
type ListenerManager interface {
	NewListenerSet() ListenerSet
	ListenStream(network string, addr string) (StreamListener, error)
	ListenPacket(network string, addr string) (net.PacketConn, error)
}

type listenerManager struct {
	listeners   map[string]*globalListener
	listenersMu sync.Mutex
}

// NewListenerManager creates a new [ListenerManger].
func NewListenerManager() ListenerManager {
	return &listenerManager{
		listeners: make(map[string]*globalListener),
	}
}

func (m *listenerManager) NewListenerSet() ListenerSet {
	return &listenerSet{
		manager:   m,
		listeners: make(map[string]Listener),
	}
}

// ListenStream creates a new stream listener for a given network and address.
//
// Listeners can overlap one another, because during config changes the new
// config is started before the old config is destroyed. This is done by using
// reusable listener wrappers, which do not actually close the underlying socket
// until all uses of the shared listener have been closed.
func (m *listenerManager) ListenStream(network string, addr string) (StreamListener, error) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()

	lnKey := listenerKey(network, addr)
	if lnGlobal, ok := m.listeners[lnKey]; ok {
		lnGlobal.usage.Add(1)
		return &sharedListener{
			listener: lnGlobal.ln,
			usage:    &lnGlobal.usage,
			acceptCh: lnGlobal.acceptCh,
			closeCh:  make(chan struct{}),
			onCloseFunc: func() {
				m.delete(lnKey)
			},
		}, nil
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP(network, tcpAddr)
	if err != nil {
		return nil, err
	}

	lnGlobal := &globalListener{ln: *ln, acceptCh: make(chan acceptResponse)}
	go func() {
		for {
			conn, err := lnGlobal.ln.AcceptTCP()
			lnGlobal.acceptCh <- acceptResponse{conn, err}
		}
	}()
	lnGlobal.usage.Store(1)
	m.listeners[lnKey] = lnGlobal

	return &sharedListener{
		listener: lnGlobal.ln,
		usage:    &lnGlobal.usage,
		acceptCh: lnGlobal.acceptCh,
		closeCh:  make(chan struct{}),
		onCloseFunc: func() {
			m.delete(lnKey)
		},
	}, nil
}

// ListenPacket creates a new packet listener for a given network and address.
//
// See notes on [ListenStream].
func (m *listenerManager) ListenPacket(network string, addr string) (net.PacketConn, error) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()

	lnKey := listenerKey(network, addr)
	if lnGlobal, ok := m.listeners[lnKey]; ok {
		lnGlobal.usage.Add(1)
		return &sharedPacketConn{
			PacketConn: lnGlobal.pc,
			usage:      &lnGlobal.usage,
			onCloseFunc: func() {
				m.delete(lnKey)
			},
		}, nil
	}

	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}

	lnGlobal := &globalListener{pc: pc}
	lnGlobal.usage.Store(1)
	m.listeners[lnKey] = lnGlobal

	return &sharedPacketConn{
		PacketConn: pc,
		usage:      &lnGlobal.usage,
		onCloseFunc: func() {
			m.delete(lnKey)
		},
	}, nil
}

func (m *listenerManager) delete(key string) {
	m.listenersMu.Lock()
	delete(m.listeners, key)
	m.listenersMu.Unlock()
}

func listenerKey(network string, addr string) string {
	return network + "/" + addr
}
