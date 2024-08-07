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

// StreamListener is a network listener for stream-oriented protocols that
// accepts [transport.StreamConn] connections.
type StreamListener interface {
	// Accept waits for and returns the next connection to the listener.
	AcceptStream() (transport.StreamConn, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors. This
	// stops the current listener from accepting new connections without closing
	// the underlying socket. Only when the last user of the underlying socket
	// closes it, do we actually close it.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

type TCPListener struct {
	ln *net.TCPListener
}

var _ StreamListener = (*TCPListener)(nil)

func (t *TCPListener) AcceptStream() (transport.StreamConn, error) {
	return t.ln.AcceptTCP()
}

func (t *TCPListener) Close() error {
	return t.ln.Close()
}

func (t *TCPListener) Addr() net.Addr {
	return t.ln.Addr()
}

type acceptResponse struct {
	conn transport.StreamConn
	err  error
}

type OnCloseFunc func() error

type virtualStreamListener struct {
	mu          sync.Mutex // Mutex to protect access to the channels
	addr        net.Addr
	acceptCh    <-chan acceptResponse
	closeCh     chan struct{}
	closed      bool
	onCloseFunc OnCloseFunc
}

var _ StreamListener = (*virtualStreamListener)(nil)

func (sl *virtualStreamListener) AcceptStream() (transport.StreamConn, error) {
	sl.mu.Lock()
	acceptCh := sl.acceptCh
	sl.mu.Unlock()

	select {
	case acceptResponse, ok := <-acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return acceptResponse.conn, acceptResponse.err
	case <-sl.closeCh:
		return nil, net.ErrClosed
	}
}

func (sl *virtualStreamListener) Close() error {
	sl.mu.Lock()
	if sl.closed {
		sl.mu.Unlock()
		return nil
	}
	sl.closed = true
	sl.acceptCh = nil
	close(sl.closeCh)
	sl.mu.Unlock()

	if sl.onCloseFunc != nil {
		return sl.onCloseFunc()
	}
	return nil
}

func (sl *virtualStreamListener) Addr() net.Addr {
	return sl.addr
}

type virtualPacketConn struct {
	net.PacketConn
	onCloseFunc OnCloseFunc
}

func (spc *virtualPacketConn) Close() error {
	if spc.onCloseFunc != nil {
		return spc.onCloseFunc()
	}
	return nil
}

// MultiListener manages shared listeners.
type MultiListener[T Listener] interface {
	// Acquire creates a new listener from the shared listener. Listeners can overlap
	// one another (e.g. during config changes the new config is started before the
	// old config is destroyed), which is done by creating virtual listeners that wrap
	// the shared listener. These virtual listeners do not actually close the
	// underlying socket until all uses of the shared listener have been closed.
	Acquire() (T, error)
}

type multiStreamListener struct {
	mu          sync.Mutex
	addr        string
	ln          RefCount[StreamListener]
	acceptCh    chan acceptResponse
	onCloseFunc OnCloseFunc
}

// NewMultiStreamListener creates a new stream-based [MultiListener].
func NewMultiStreamListener(addr string, onCloseFunc OnCloseFunc) MultiListener[StreamListener] {
	return &multiStreamListener{
		addr:        addr,
		onCloseFunc: onCloseFunc,
	}
}

func (m *multiStreamListener) Acquire() (StreamListener, error) {
	refCount, err := func() (RefCount[StreamListener], error) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if m.ln == nil {
			tcpAddr, err := net.ResolveTCPAddr("tcp", m.addr)
			if err != nil {
				return nil, err
			}
			ln, err := net.ListenTCP("tcp", tcpAddr)
			if err != nil {
				return nil, err
			}
			sl := &TCPListener{ln}
			m.ln = NewRefCount[StreamListener](sl, m.onCloseFunc)
			m.acceptCh = make(chan acceptResponse)
			go func() {
				for {
					conn, err := sl.AcceptStream()
					if errors.Is(err, net.ErrClosed) {
						close(m.acceptCh)
						return
					}
					m.acceptCh <- acceptResponse{conn, err}
				}
			}()
		}
		return m.ln, nil
	}()
	if err != nil {
		return nil, err
	}

	sl := refCount.Acquire()
	return &virtualStreamListener{
		addr:        sl.Addr(),
		acceptCh:    m.acceptCh,
		closeCh:     make(chan struct{}),
		onCloseFunc: refCount.Close,
	}, nil
}

type multiPacketListener struct {
	mu          sync.Mutex
	addr        string
	pc          RefCount[net.PacketConn]
	onCloseFunc OnCloseFunc
}

// NewMultiPacketListener creates a new packet-based [MultiListener].
func NewMultiPacketListener(addr string, onCloseFunc OnCloseFunc) MultiListener[net.PacketConn] {
	return &multiPacketListener{
		addr:        addr,
		onCloseFunc: onCloseFunc,
	}
}

func (m *multiPacketListener) Acquire() (net.PacketConn, error) {
	refCount, err := func() (RefCount[net.PacketConn], error) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if m.pc == nil {
			pc, err := net.ListenPacket("udp", m.addr)
			if err != nil {
				return nil, err
			}
			m.pc = NewRefCount(pc, m.onCloseFunc)
		}
		return m.pc, nil
	}()
	if err != nil {
		return nil, err
	}

	pc := refCount.Acquire()
	return &virtualPacketConn{
		PacketConn:  pc,
		onCloseFunc: refCount.Close,
	}, nil
}

// ListenerManager holds the state of shared listeners.
type ListenerManager interface {
	// ListenStream creates a new stream listener for a given address.
	ListenStream(addr string) (StreamListener, error)

	// ListenPacket creates a new packet listener for a given address.
	ListenPacket(addr string) (net.PacketConn, error)
}

type listenerManager struct {
	streamListeners map[string]MultiListener[StreamListener]
	packetListeners map[string]MultiListener[net.PacketConn]
	mu              sync.Mutex
}

// NewListenerManager creates a new [ListenerManger].
func NewListenerManager() ListenerManager {
	return &listenerManager{
		streamListeners: make(map[string]MultiListener[StreamListener]),
		packetListeners: make(map[string]MultiListener[net.PacketConn]),
	}
}

func (m *listenerManager) ListenStream(addr string) (StreamListener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	streamLn, exists := m.streamListeners[addr]
	if !exists {
		streamLn = NewMultiStreamListener(
			addr,
			func() error {
				m.mu.Lock()
				delete(m.streamListeners, addr)
				m.mu.Unlock()
				return nil
			},
		)
		m.streamListeners[addr] = streamLn
	}
	ln, err := streamLn.Acquire()
	if err != nil {
		return nil, fmt.Errorf("unable to create stream listener for %s: %v", addr, err)
	}
	return ln, nil
}

func (m *listenerManager) ListenPacket(addr string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	packetLn, exists := m.packetListeners[addr]
	if !exists {
		packetLn = NewMultiPacketListener(
			addr,
			func() error {
				m.mu.Lock()
				delete(m.packetListeners, addr)
				m.mu.Unlock()
				return nil
			},
		)
		m.packetListeners[addr] = packetLn
	}

	ln, err := packetLn.Acquire()
	if err != nil {
		return nil, fmt.Errorf("unable to create packet listener for %s: %v", addr, err)
	}
	return ln, nil
}

// RefCount is an atomic reference counter that can be used to track a shared
// [io.Closer] resource.
type RefCount[T io.Closer] interface {
	io.Closer

	// Acquire increases the ref count and returns the wrapped object.
	Acquire() T
}

type refCount[T io.Closer] struct {
	mu          sync.Mutex
	count       *atomic.Int32
	value       T
	onCloseFunc OnCloseFunc
}

func NewRefCount[T io.Closer](value T, onCloseFunc OnCloseFunc) RefCount[T] {
	r := &refCount[T]{
		count:       &atomic.Int32{},
		value:       value,
		onCloseFunc: onCloseFunc,
	}
	return r
}

func (r refCount[T]) Acquire() T {
	r.count.Add(1)
	return r.value
}

func (r refCount[T]) Close() error {
	// Lock to prevent someone from acquiring while we close the value.
	r.mu.Lock()
	defer r.mu.Unlock()

	if count := r.count.Add(-1); count == 0 {
		err := r.value.Close()
		if err != nil {
			return err
		}
		if r.onCloseFunc != nil {
			return r.onCloseFunc()
		}
		return nil
	}
	return nil
}
