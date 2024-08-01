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
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	proxyproto "github.com/pires/go-proxyproto"
)

// The implementations of listeners for different network types are not
// interchangeable. The type of listener depends on the network type.
type Listener = io.Closer

// ClientStreamConn wraps a [transport.StreamConn] and sets the client source of the connection.
// This is useful for handling the PROXY protocol where the RemoteAddr() points to the
// server/load balancer address and we need the perceived source of the connection.
type ClientStreamConn interface {
	transport.StreamConn
	ClientAddr() net.Addr
}

type clientStreamConn struct {
	transport.StreamConn
	clientAddr net.Addr
}

func (c *clientStreamConn) ClientAddr() net.Addr {
	if c.clientAddr != nil {
		return c.clientAddr
	}
	return c.StreamConn.RemoteAddr()
}

// StreamListener is a network listener for stream-oriented protocols that
// accepts [transport.StreamConn] connections.
type StreamListener interface {
	// Accept waits for and returns the next connection to the listener.
	AcceptStream() (ClientStreamConn, error)

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

func (t *TCPListener) AcceptStream() (ClientStreamConn, error) {
	conn, err := t.ln.AcceptTCP()
	return &clientStreamConn{StreamConn: conn}, err
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
	listener    StreamListener
	acceptCh    chan acceptResponse
	closeCh     chan struct{}
	onCloseFunc OnCloseFunc
}

var _ StreamListener = (*virtualStreamListener)(nil)

func (sl *virtualStreamListener) AcceptStream() (ClientStreamConn, error) {
	select {
	case acceptResponse, ok := <-sl.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return &clientStreamConn{StreamConn: acceptResponse.conn}, acceptResponse.err
	case <-sl.closeCh:
		return nil, net.ErrClosed
	}
}

func (sl *virtualStreamListener) Close() error {
	close(sl.closeCh)
	return sl.onCloseFunc()
}

func (sl *virtualStreamListener) Addr() net.Addr {
	return sl.listener.Addr()
}

// ProxyListener wraps a [StreamListener] and fetches the source of the connection from the PROXY
// protocol header string. See https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt.
type ProxyStreamListener struct {
	StreamListener
}

// AcceptStream waits for the next incoming connection, parses the client IP from the PROXY protocol
// header, and adds it to the connection.
func (l *ProxyStreamListener) AcceptStream() (ClientStreamConn, error) {
	conn, err := l.StreamListener.AcceptStream()
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(conn)
	h, err := proxyproto.Read(r)
	if err == proxyproto.ErrNoProxyProtocol {
		logger.Warningf("Received connection from %v without proxy header.", conn.RemoteAddr())
		return conn, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error parsing proxy header: %v", err)
	}
	return &clientStreamConn{StreamConn: conn, clientAddr: h.SourceAddr}, nil
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
			listener:    ln,
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
	// ListenStream creates a new stream listener for a given network and address.
	//
	// Listeners can overlap one another, because during config changes the new
	// config is started before the old config is destroyed. This is done by using
	// reusable listener wrappers, which do not actually close the underlying socket
	// until all uses of the shared listener have been closed.
	ListenStream(network string, addr string) (StreamListener, error)

	// ListenPacket creates a new packet listener for a given network and address.
	//
	// See notes on [ListenStream].
	ListenPacket(network string, addr string) (net.PacketConn, error)
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

func (m *listenerManager) getOrCreate(key string, createFunc func() (Listener, error)) (RefCount[Listener], error) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()

	if lnRefCount, exists := m.listeners[key]; exists {
		return lnRefCount.Acquire(), nil
	}

	ln, err := createFunc()
	if err != nil {
		return nil, err
	}
	lnRefCount := NewRefCount(ln)
	m.listeners[key] = lnRefCount
	return lnRefCount, nil
}

func (m *listenerManager) ListenStream(network string, addr string) (StreamListener, error) {
	lnKey := network + "/" + addr
	lnRefCount, err := m.getOrCreate(lnKey, func() (Listener, error) {
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
		return lnAddr, nil
	})
	if err != nil {
		return nil, err
	}
	if lnAddr, ok := lnRefCount.Get().(canCreateStreamListener); ok {
		return lnAddr.NewStreamListener(lnRefCount.Close), nil
	}
	return nil, fmt.Errorf("unable to create stream listener for %s", lnKey)
}

func (m *listenerManager) ListenPacket(network string, addr string) (net.PacketConn, error) {
	lnKey := network + "/" + addr
	lnRefCount, err := m.getOrCreate(lnKey, func() (Listener, error) {
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			return nil, err
		}
		return &listenAddr{
			ln: pc,
			onCloseFunc: func() error {
				m.delete(lnKey)
				return nil
			},
		}, nil
	})
	if err != nil {
		return nil, err
	}
	if lnAddr, ok := lnRefCount.Get().(canCreatePacketListener); ok {
		return lnAddr.NewPacketListener(lnRefCount.Close), nil
	}
	return nil, fmt.Errorf("unable to create packet listener for %s", lnKey)
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
