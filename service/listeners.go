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
	addr        net.Addr
	acceptCh    <-chan acceptResponse
	closeCh     chan struct{}
	onCloseFunc OnCloseFunc
}

var _ StreamListener = (*virtualStreamListener)(nil)

func (sl *virtualStreamListener) AcceptStream() (transport.StreamConn, error) {
	select {
	case acceptResponse, ok := <-sl.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return acceptResponse.conn, acceptResponse.err
	case <-sl.closeCh:
		return nil, net.ErrClosed
	}
}

func (sl *virtualStreamListener) Close() error {
	sl.acceptCh = nil
	close(sl.closeCh)
	return sl.onCloseFunc()
}

func (sl *virtualStreamListener) Addr() net.Addr {
	return sl.addr
}

type virtualPacketConn struct {
	net.PacketConn
	onCloseFunc OnCloseFunc
}

func (spc *virtualPacketConn) Close() error {
	return spc.onCloseFunc()
}

type listenAddr struct {
	ln          Listener
	acceptCh    chan acceptResponse
	onCloseFunc OnCloseFunc
}

type canCreateStreamListener interface {
	NewStreamListener(onCloseFunc OnCloseFunc) StreamListener
}

var _ canCreateStreamListener = (*listenAddr)(nil)

// NewStreamListener creates a new [StreamListener].
func (la *listenAddr) NewStreamListener(onCloseFunc OnCloseFunc) StreamListener {
	if ln, ok := la.ln.(StreamListener); ok {
		return &virtualStreamListener{
			addr:        ln.Addr(),
			acceptCh:    la.acceptCh,
			closeCh:     make(chan struct{}),
			onCloseFunc: onCloseFunc,
		}
	}
	return nil
}

type canCreatePacketListener interface {
	NewPacketListener(onCloseFunc OnCloseFunc) net.PacketConn
}

var _ canCreatePacketListener = (*listenAddr)(nil)

// NewPacketListener creates a new [net.PacketConn].
func (cl *listenAddr) NewPacketListener(onCloseFunc OnCloseFunc) net.PacketConn {
	if ln, ok := cl.ln.(net.PacketConn); ok {
		return &virtualPacketConn{
			PacketConn:  ln,
			onCloseFunc: onCloseFunc,
		}
	}
	return nil
}

func (la *listenAddr) Close() error {
	if err := la.ln.Close(); err != nil {
		return err
	}
	return la.onCloseFunc()
}

// ListenerManager holds and manages the state of shared listeners.
type ListenerManager interface {
	// ListenStream creates a new stream listener for a given address.
	//
	// Listeners can overlap one another, because during config changes the new
	// config is started before the old config is destroyed. This is done by using
	// reusable listener wrappers, which do not actually close the underlying socket
	// until all uses of the shared listener have been closed.
	ListenStream(addr string) (StreamListener, error)

	// ListenPacket creates a new packet listener for a given address.
	//
	// See notes on [ListenStream].
	ListenPacket(addr string) (net.PacketConn, error)
}

type listenerManager struct {
	listeners   map[string]RefCount[Listener]
	listenersMu sync.Mutex
}

// NewListenerManager creates a new [ListenerManger].
func NewListenerManager() ListenerManager {
	return &listenerManager{
		listeners: make(map[string]RefCount[Listener]),
	}
}

func (m *listenerManager) newStreamListener(addr string) (Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	streamLn := &TCPListener{ln}
	lnAddr := &listenAddr{
		ln:       streamLn,
		acceptCh: make(chan acceptResponse),
		onCloseFunc: func() error {
			m.delete(listenerKey("tcp", addr))
			return nil
		},
	}
	go func() {
		for {
			conn, err := streamLn.AcceptStream()
			if errors.Is(err, net.ErrClosed) {
				close(lnAddr.acceptCh)
				return
			}
			lnAddr.acceptCh <- acceptResponse{conn, err}
		}
	}()
	return lnAddr, nil
}

func (m *listenerManager) newPacketListener(addr string) (Listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	return &listenAddr{
		ln: pc,
		onCloseFunc: func() error {
			m.delete(listenerKey("udp", addr))
			return nil
		},
	}, nil
}

func (m *listenerManager) getListener(network string, addr string) (RefCount[Listener], error) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()

	lnKey := listenerKey(network, addr)
	if lnRefCount, exists := m.listeners[lnKey]; exists {
		return lnRefCount.Acquire(), nil
	}

	var (
		ln  Listener
		err error
	)
	if network == "tcp" {
		ln, err = m.newStreamListener(addr)
	} else if network == "udp" {
		ln, err = m.newPacketListener(addr)
	} else {
		return nil, fmt.Errorf("unable to get listener for unsupported network %s", network)
	}
	if err != nil {
		return nil, err
	}
	lnRefCount := NewRefCount(ln)
	m.listeners[lnKey] = lnRefCount
	return lnRefCount, nil
}

func (m *listenerManager) ListenStream(addr string) (StreamListener, error) {
	lnRefCount, err := m.getListener("tcp", addr)
	if err != nil {
		return nil, err
	}
	if lnAddr, ok := lnRefCount.Get().(canCreateStreamListener); ok {
		return lnAddr.NewStreamListener(lnRefCount.Close), nil
	}
	return nil, fmt.Errorf("unable to create stream listener for %s", addr)
}

func (m *listenerManager) ListenPacket(addr string) (net.PacketConn, error) {
	lnRefCount, err := m.getListener("udp", addr)
	if err != nil {
		return nil, err
	}
	if lnAddr, ok := lnRefCount.Get().(canCreatePacketListener); ok {
		return lnAddr.NewPacketListener(lnRefCount.Close), nil
	}
	return nil, fmt.Errorf("unable to create packet listener for %s", addr)
}

func (m *listenerManager) delete(key string) {
	m.listenersMu.Lock()
	delete(m.listeners, key)
	m.listenersMu.Unlock()
}

func listenerKey(network string, addr string) string {
	return network + "/" + addr
}

// RefCount is an atomic reference counter that can be used to track a shared
// [io.Closer] resource.
type RefCount[T io.Closer] interface {
	io.Closer

	// Acquire increases the ref count and returns the wrapped object.
	Acquire() RefCount[T]

	Get() T
}

type refCount[T io.Closer] struct {
	count *atomic.Int32
	value T
}

func NewRefCount[T io.Closer](value T) RefCount[T] {
	res := &refCount[T]{
		count: &atomic.Int32{},
		value: value,
	}
	res.count.Store(1)
	return res
}

func (r refCount[T]) Close() error {
	if count := r.count.Add(-1); count == 0 {
		return r.value.Close()
	}

	return nil
}

func (r refCount[T]) Acquire() RefCount[T] {
	r.count.Add(1)
	return r
}

func (r refCount[T]) Get() T {
	return r.value
}
