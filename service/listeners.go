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

type sharedListener struct {
	listener    StreamListener
	acceptCh    chan acceptResponse
	closeCh     chan struct{}
	onCloseFunc func() error
}

var _ StreamListener = (*sharedListener)(nil)

// Accept accepts connections until Close() is called.
func (sl *sharedListener) AcceptStream() (transport.StreamConn, error) {
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

// Close implements [StreamListener.Close].
func (sl *sharedListener) Close() error {
	close(sl.closeCh)
	return sl.onCloseFunc()
}

// Addr returns the listener's network address.
func (sl *sharedListener) Addr() net.Addr {
	return sl.listener.Addr()
}

type sharedPacketConn struct {
	net.PacketConn
	onCloseFunc func() error
}

func (spc *sharedPacketConn) Close() error {
	return spc.onCloseFunc()
}

type listenAddr struct {
	ln          StreamListener
	pc          net.PacketConn
	acceptCh    chan acceptResponse
	onCloseFunc func() error
}

// NewStreamListener creates a new [StreamListener].
func (cl *listenAddr) NewStreamListener() StreamListener {
	return &sharedListener{
		listener:    cl.ln,
		acceptCh:    cl.acceptCh,
		closeCh:     make(chan struct{}),
		onCloseFunc: cl.Close,
	}
}

// NewPacketListener creates a new [net.PacketConn].
func (cl *listenAddr) NewPacketListener() net.PacketConn {
	return &sharedPacketConn{
		PacketConn:  cl.pc,
		onCloseFunc: cl.Close,
	}
}

func (cl *listenAddr) Close() error {
	if cl.ln != nil {
		err := cl.ln.Close()
		if err != nil {
			return err
		}
	}
	if cl.pc != nil {
		err := cl.pc.Close()
		if err != nil {
			return err
		}
	}
	return cl.onCloseFunc()
}

// ListenerManager holds and manages the state of shared listeners.
type ListenerManager interface {
	ListenStream(network string, addr string) (StreamListener, error)
	ListenPacket(network string, addr string) (net.PacketConn, error)
}

type listenerManager struct {
	listeners   map[string]RefCount[*listenAddr]
	listenersMu sync.Mutex
}

// NewListenerManager creates a new [ListenerManger].
func NewListenerManager() ListenerManager {
	return &listenerManager{
		listeners: make(map[string]RefCount[*listenAddr]),
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

	lnKey := network + "/" + addr
	if lnRefCount, ok := m.listeners[lnKey]; ok {
		lnAddr := lnRefCount.Acquire()
		return lnAddr.NewStreamListener(), nil
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP(network, tcpAddr)
	if err != nil {
		return nil, err
	}

	streamLn := &TCPListener{ln}
	lnAddr := &listenAddr{
		ln:       streamLn,
		acceptCh: make(chan acceptResponse),
		onCloseFunc: func() error {
			m.delete(lnKey)
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
	m.listeners[lnKey] = NewRefCount(lnAddr)
	return lnAddr.NewStreamListener(), nil
}

// ListenPacket creates a new packet listener for a given network and address.
//
// See notes on [ListenStream].
func (m *listenerManager) ListenPacket(network string, addr string) (net.PacketConn, error) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()

	lnKey := network + "/" + addr
	if lnRefCount, ok := m.listeners[lnKey]; ok {
		lnAddr := lnRefCount.Acquire()
		return lnAddr.NewPacketListener(), nil
	}

	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}

	lnAddr := &listenAddr{
		pc: pc,
		onCloseFunc: func() error {
			m.delete(lnKey)
			return nil
		},
	}
	m.listeners[lnKey] = NewRefCount(lnAddr)
	return lnAddr.NewPacketListener(), nil
}

func (m *listenerManager) delete(key string) {
	m.listenersMu.Lock()
	delete(m.listeners, key)
	m.listenersMu.Unlock()
}

// RefCount is an atomic reference counter that can be used to track a shared
// [io.Closer] resource.
type RefCount[T io.Closer] interface {
	io.Closer

	// Acquire increases the ref count and returns the wrapped object.
	Acquire() T
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

func (r refCount[T]) Acquire() T {
	r.count.Add(1)
	return r.value
}
