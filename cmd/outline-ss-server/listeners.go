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
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	listeners   = make(map[string]*globalListener)
	listenersMu sync.Mutex
)

type sharedListener struct {
	net.Listener
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
			Net:  sl.Listener.Addr().Network(),
			Addr: sl.Listener.Addr(),
			Err:  fmt.Errorf("listener closed"),
		}
	}

	conn, err := sl.Listener.Accept()
	if err == nil {
		return conn, nil
	}

	sl.deadlineMu.Lock()
	if *sl.deadline {
		switch ln := sl.Listener.(type) {
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
				Net:  sl.Listener.Addr().Network(),
				Addr: sl.Listener.Addr(),
				Err:  fmt.Errorf("listener closed"),
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
			switch ln := sl.Listener.(type) {
			case *net.TCPListener:
				ln.SetDeadline(time.Now().Add(-1 * time.Minute))
			}
			*sl.deadline = true
		}
		sl.deadlineMu.Unlock()

		// See if we need to actually close the underlying listener.
		if sl.usage.Add(-1) == 0 {
			listenersMu.Lock()
			delete(listeners, sl.key)
			listenersMu.Unlock()
			err := sl.Listener.Close()
			if err != nil {
				return err
			}
		}

	}

	return nil
}

type sharedPacketConn struct {
	net.PacketConn
	key    string
	closed atomic.Int32
	usage  *atomic.Int32
}

func (spc *sharedPacketConn) Close() error {
	if spc.closed.CompareAndSwap(0, 1) {
		// See if we need to actually close the underlying listener.
		if spc.usage.Add(-1) == 0 {
			listenersMu.Lock()
			delete(listeners, spc.key)
			listenersMu.Unlock()
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

type NetworkAddr struct {
	network string
	Host    string
	Port    uint
}

// String returns a human-readable representation of the [NetworkAddr].
func (na *NetworkAddr) Network() string {
	return na.network
}

// String returns a human-readable representation of the [NetworkAddr].
func (na *NetworkAddr) String() string {
	return na.JoinHostPort()
}

// JoinHostPort is a convenience wrapper around [net.JoinHostPort].
func (na *NetworkAddr) JoinHostPort() string {
	return net.JoinHostPort(na.Host, strconv.Itoa(int(na.Port)))
}

// Key returns a representative string useful to retrieve this entity from a
// map. This is used to uniquely identify reusable listeners.
func (na *NetworkAddr) Key() string {
	return na.network + "/" + na.JoinHostPort()
}

// Listen creates a new listener for the [NetworkAddr].
//
// Listeners can overlap one another, because during config changes the new
// config is started before the old config is destroyed. This is done by using
// reusable listener wrappers, which do not actually close the underlying socket
// until all uses of the shared listener have been closed.
func (na *NetworkAddr) Listen(ctx context.Context, config net.ListenConfig) (any, error) {
	switch na.network {

	case "tcp":
		listenersMu.Lock()
		defer listenersMu.Unlock()

		if lnGlobal, ok := listeners[na.Key()]; ok {
			lnGlobal.usage.Add(1)
			return &sharedListener{
				usage:      &lnGlobal.usage,
				deadline:   &lnGlobal.deadline,
				deadlineMu: &lnGlobal.deadlineMu,
				key:        na.Key(),
				Listener:   lnGlobal.ln,
			}, nil
		}

		ln, err := config.Listen(ctx, na.network, na.JoinHostPort())
		if err != nil {
			return nil, err
		}

		lnGlobal := &globalListener{ln: ln}
		lnGlobal.usage.Store(1)
		listeners[na.Key()] = lnGlobal

		return &sharedListener{
			usage:      &lnGlobal.usage,
			deadline:   &lnGlobal.deadline,
			deadlineMu: &lnGlobal.deadlineMu,
			key:        na.Key(),
			Listener:   ln,
		}, nil

	case "udp":
		listenersMu.Lock()
		defer listenersMu.Unlock()

		if lnGlobal, ok := listeners[na.Key()]; ok {
			lnGlobal.usage.Add(1)
			return &sharedPacketConn{
				usage:      &lnGlobal.usage,
				key:        na.Key(),
				PacketConn: lnGlobal.pc,
			}, nil
		}

		pc, err := config.ListenPacket(ctx, na.network, na.JoinHostPort())
		if err != nil {
			return nil, err
		}

		lnGlobal := &globalListener{pc: pc}
		lnGlobal.usage.Store(1)
		listeners[na.Key()] = lnGlobal

		return &sharedPacketConn{
			usage:      &lnGlobal.usage,
			key:        na.Key(),
			PacketConn: pc,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported network: %s", na.network)

	}
}

// ParseNetworkAddr parses an address into a [NetworkAddr]. The input
// string is expected to be of the form "network/host:port" where any part is
// optional.
//
// Examples:
//
//	tcp/127.0.0.1:8000
//	udp/127.0.0.1:9000
func ParseNetworkAddr(addr string) (NetworkAddr, error) {
	var host, port string
	network, host, port, err := SplitNetworkAddr(addr)
	if err != nil {
		return NetworkAddr{}, err
	}
	if network == "" {
		return NetworkAddr{}, errors.New("missing network")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return NetworkAddr{}, fmt.Errorf("invalid port: %v", err)
	}
	return NetworkAddr{
		network: network,
		Host:    host,
		Port:    uint(p),
	}, nil
}

// SplitNetworkAddr splits a into its network, host, and port components.
func SplitNetworkAddr(a string) (network, host, port string, err error) {
	beforeSlash, afterSlash, slashFound := strings.Cut(a, "/")
	if slashFound {
		network = strings.ToLower(strings.TrimSpace(beforeSlash))
		a = afterSlash
	}
	host, port, err = net.SplitHostPort(a)
	return
}
