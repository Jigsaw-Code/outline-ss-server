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
	acceptCh    *atomic.Value // closed by first Close() call
	closeCh     chan struct{}
	onCloseFunc func() error
}

// Accept accepts connections until Close() is called.
func (sl *sharedListener) AcceptStream() (transport.StreamConn, error) {
	select {
	case acceptResponse := <-sl.acceptCh.Load().(chan acceptResponse):
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
	sl.acceptCh = nil
	close(sl.closeCh)
	return sl.onCloseFunc()
}

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

type concreteListener struct {
	ln       *net.TCPListener
	pc       net.PacketConn
	usage    atomic.Int32
	acceptCh chan acceptResponse
}

func (cl *concreteListener) Close() error {
	if cl.usage.Add(-1) == 0 {
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
	}
	return nil
}

// ListenerManager holds and manages the state of shared listeners.
type ListenerManager interface {
	ListenStream(network string, addr string) (StreamListener, error)
	ListenPacket(network string, addr string) (net.PacketConn, error)
}

type listenerManager struct {
	listeners   map[string]*concreteListener
	listenersMu sync.Mutex
}

// NewListenerManager creates a new [ListenerManger].
func NewListenerManager() ListenerManager {
	return &listenerManager{
		listeners: make(map[string]*concreteListener),
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
	if lnConcrete, ok := m.listeners[lnKey]; ok {
		lnConcrete.usage.Add(1)
		sl := &sharedListener{
			listener: *lnConcrete.ln,
			closeCh:  make(chan struct{}),
			onCloseFunc: func() error {
				if err := lnConcrete.Close(); err != nil {
					return err
				}
				m.delete(lnKey)
				return nil
			},
		}
		sl.acceptCh = &atomic.Value{}
		sl.acceptCh.Store(lnConcrete.acceptCh)
		return sl, nil
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP(network, tcpAddr)
	if err != nil {
		return nil, err
	}

	lnConcrete := &concreteListener{ln: ln, acceptCh: make(chan acceptResponse)}
	go func() {
		for {
			conn, err := lnConcrete.ln.AcceptTCP()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			lnConcrete.acceptCh <- acceptResponse{conn, err}
		}
	}()
	lnConcrete.usage.Store(1)
	m.listeners[lnKey] = lnConcrete

	sl := &sharedListener{
		listener: *lnConcrete.ln,
		closeCh:  make(chan struct{}),
		onCloseFunc: func() error {
			if err := lnConcrete.Close(); err != nil {
				return err
			}
			m.delete(lnKey)
			return nil
		},
	}
	sl.acceptCh = &atomic.Value{}
	sl.acceptCh.Store(lnConcrete.acceptCh)
	return sl, nil
}

// ListenPacket creates a new packet listener for a given network and address.
//
// See notes on [ListenStream].
func (m *listenerManager) ListenPacket(network string, addr string) (net.PacketConn, error) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()

	lnKey := listenerKey(network, addr)
	if lnConcrete, ok := m.listeners[lnKey]; ok {
		lnConcrete.usage.Add(1)
		return &sharedPacketConn{
			PacketConn: lnConcrete.pc,
			onCloseFunc: func() error {
				if err := lnConcrete.Close(); err != nil {
					return err
				}
				m.delete(lnKey)
				return nil
			},
		}, nil
	}

	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}

	lnConcrete := &concreteListener{pc: pc}
	lnConcrete.usage.Store(1)
	m.listeners[lnKey] = lnConcrete

	return &sharedPacketConn{
		PacketConn: pc,
		onCloseFunc: func() error {
			if err := lnConcrete.Close(); err != nil {
				return err
			}
			m.delete(lnKey)
			return nil
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
