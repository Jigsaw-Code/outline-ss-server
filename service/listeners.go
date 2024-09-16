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

type OnCloseFunc func() error

type acceptResponse struct {
	conn transport.StreamConn
	err  error
}

type virtualStreamListener struct {
	mu          sync.Mutex // Mutex to protect access to the channels
	addr        net.Addr
	acceptCh    <-chan acceptResponse
	closeCh     chan struct{}
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
	defer sl.mu.Unlock()

	if sl.acceptCh == nil {
		return nil
	}
	sl.acceptCh = nil
	close(sl.closeCh)
	if sl.onCloseFunc != nil {
		onCloseFunc := sl.onCloseFunc
		sl.onCloseFunc = nil
		return onCloseFunc()
	}
	return nil
}

func (sl *virtualStreamListener) Addr() net.Addr {
	return sl.addr
}

type readRequest struct {
	buffer []byte
	respCh chan struct {
		n    int
		addr net.Addr
		err  error
	}
}

type virtualPacketConn struct {
	net.PacketConn
	mu      sync.Mutex // Mutex to protect access to the channels
	readCh  chan readRequest
	closeCh chan struct{}
}

func (pc *virtualPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	respCh := make(chan struct {
		n    int
		addr net.Addr
		err  error
	}, 1)

	pc.mu.Lock()
	if pc.readCh == nil {
		pc.mu.Unlock()
		return 0, nil, net.ErrClosed
	}
	pc.readCh <- readRequest{
		buffer: p,
		respCh: respCh,
	}
	pc.mu.Unlock()

	resp := <-respCh
	return resp.n, resp.addr, resp.err
}

func (pc *virtualPacketConn) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.readCh == nil {
		return nil
	}

	close(pc.closeCh)
	pc.readCh = nil
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
	ln          StreamListener
	count       uint32
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
		m.ln = &TCPListener{ln}
		m.acceptCh = make(chan acceptResponse)
		go func() {
			for {
				m.mu.Lock()
				ln := m.ln
				m.mu.Unlock()

				if ln == nil {
					return
				}
				conn, err := ln.AcceptStream()
				if errors.Is(err, net.ErrClosed) {
					close(m.acceptCh)
					return
				}
				m.acceptCh <- acceptResponse{conn, err}
			}
		}()
	}

	m.count++
	return &virtualStreamListener{
		addr:     m.ln.Addr(),
		acceptCh: m.acceptCh,
		closeCh:  make(chan struct{}),
		onCloseFunc: func() error {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.count--
			if m.count == 0 {
				m.ln.Close()
				m.ln = nil
				if m.onCloseFunc != nil {
					onCloseFunc := m.onCloseFunc
					m.onCloseFunc = nil
					return onCloseFunc()
				}
			}
			return nil
		},
	}, nil
}

type multiPacketListener struct {
	mu          sync.Mutex
	addr        string
	pc          net.PacketConn
	count       uint32
	readCh      chan readRequest
	doneCh      chan struct{}
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
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pc == nil {
		pc, err := net.ListenPacket("udp", m.addr)
		if err != nil {
			return nil, err
		}
		m.pc = pc
		m.readCh = make(chan readRequest)
		m.doneCh = make(chan struct{})
	}

	m.count++
	vpc := &virtualPacketConn{
		PacketConn: m.pc,
		readCh:     m.readCh,
		closeCh:    make(chan struct{}),
	}

	go func() {
		for {
			select {
			case req, ok := <-m.readCh:
				if !ok {
					// The read channel is closed.
					return
				}
				n, addr, err := m.pc.ReadFrom(req.buffer)
				req.respCh <- struct {
					n    int
					addr net.Addr
					err  error
				}{n, addr, err}
			case <-vpc.closeCh:
				m.mu.Lock()
				defer m.mu.Unlock()
				m.count--
				if m.count == 0 {
					close(m.doneCh)
					m.pc.Close()
					m.pc = nil
					if m.onCloseFunc != nil {
						onCloseFunc := m.onCloseFunc
						m.onCloseFunc = nil
						onCloseFunc()
					}
				}
				return
			case <-m.doneCh:
				return
			}
		}
	}()

	return vpc, nil
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
