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
	"net"
	"testing"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
)

func TestDirectListenerSetsRemoteAddrAsClientAddr(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	go func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoErrorf(t, err, "Failed to dial %v: %v", listener.Addr(), err)
		conn.Write(makeTestPayload(50))
		conn.Close()
	}()

	ln := &TCPListener{listener}
	conn, err := ln.AcceptStream()
	require.NoError(t, err)
	require.Equal(t, conn.RemoteAddr(), conn.ClientAddr())
}

func TestProxyProtocolListenerParsesSourceAddressAsClientAddr(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	sourceAddr := &net.TCPAddr{
		IP:   net.ParseIP("10.1.1.1"),
		Port: 1000,
	}
	go func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoErrorf(t, err, "Failed to dial %v: %v", listener.Addr(), err)
		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        sourceAddr,
			DestinationAddr:   conn.RemoteAddr(),
		}
		header.WriteTo(conn)
		conn.Write(makeTestPayload(50))
		conn.Close()
	}()

	ln := &ProxyStreamListener{StreamListener: &TCPListener{listener}}
	conn, err := ln.AcceptStream()
	require.NoError(t, err)
	require.True(t, sourceAddr.IP.Equal(conn.ClientAddr().(*net.TCPAddr).IP))
	require.Equal(t, sourceAddr.Port, conn.ClientAddr().(*net.TCPAddr).Port)
}

func TestProxyProtocolListenerUsesRemoteAddrAsClientAddrIfLocalHeader(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	go func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoErrorf(t, err, "Failed to dial %v: %v", listener.Addr(), err)

		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.LOCAL,
			TransportProtocol: proxyproto.UNSPEC,
			SourceAddr: &net.TCPAddr{
				IP:   net.ParseIP("10.1.1.1"),
				Port: 1000,
			},
			DestinationAddr: conn.RemoteAddr(),
		}
		header.WriteTo(conn)
		conn.Write(makeTestPayload(50))
		conn.Close()
	}()

	ln := &ProxyStreamListener{StreamListener: &TCPListener{listener}}
	conn, err := ln.AcceptStream()
	require.NoError(t, err)
	require.Equal(t, conn.RemoteAddr(), conn.ClientAddr())
}

func TestListenerManagerStreamListenerEarlyClose(t *testing.T) {
	m := NewListenerManager()
	ln, err := m.ListenStream("127.0.0.1:0", false)
	require.NoError(t, err)

	ln.Close()
	_, err = ln.AcceptStream()

	require.ErrorIs(t, err, net.ErrClosed)
}

func writeTestPayload(ln StreamListener) error {
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return fmt.Errorf("Failed to dial %v: %v", ln.Addr().String(), err)
	}
	if _, err = conn.Write(makeTestPayload(50)); err != nil {
		return fmt.Errorf("Failed to write to connection: %v", err)
	}
	conn.Close()
	return nil
}

func TestListenerManagerStreamListenerNotClosedIfStillInUse(t *testing.T) {
	m := NewListenerManager()
	ln, err := m.ListenStream("127.0.0.1:0", false)
	require.NoError(t, err)
	ln2, err := m.ListenStream("127.0.0.1:0", false)
	require.NoError(t, err)
	// Close only the first listener.
	ln.Close()

	done := make(chan struct{})
	go func() {
		ln2.AcceptStream()
		done <- struct{}{}
	}()
	err = writeTestPayload(ln2)

	require.NoError(t, err)
	<-done
}

func TestListenerManagerStreamListenerCreatesListenerOnDemand(t *testing.T) {
	m := NewListenerManager()
	// Create a listener and immediately close it.
	ln, err := m.ListenStream("127.0.0.1:0", false)
	require.NoError(t, err)
	ln.Close()
	// Now create another listener on the same address.
	ln2, err := m.ListenStream("127.0.0.1:0", false)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		ln2.AcceptStream()
		done <- struct{}{}
	}()
	err = writeTestPayload(ln2)

	require.NoError(t, err)
	<-done
}

func TestListenerManagerPacketListenerEarlyClose(t *testing.T) {
	m := NewListenerManager()
	pc, err := m.ListenPacket("127.0.0.1:0", false)
	require.NoError(t, err)

	pc.Close()
	_, _, readErr := pc.ReadFrom(nil)
	_, writeErr := pc.WriteTo(nil, &net.UDPAddr{})

	require.ErrorIs(t, readErr, net.ErrClosed)
	require.ErrorIs(t, writeErr, net.ErrClosed)
}

func TestListenerManagerPacketListenerNotClosedIfStillInUse(t *testing.T) {
	m := NewListenerManager()
	pc, err := m.ListenPacket("127.0.0.1:0", false)
	require.NoError(t, err)
	pc2, err := m.ListenPacket("127.0.0.1:0", false)
	require.NoError(t, err)
	// Close only the first listener.
	pc.Close()

	done := make(chan struct{})
	go func() {
		_, _, readErr := pc2.ReadFrom(nil)
		require.NoError(t, readErr)
		done <- struct{}{}
	}()
	_, err = pc.WriteTo(nil, pc2.LocalAddr())

	require.NoError(t, err)
	<-done
}

func TestListenerManagerPacketListenerCreatesListenerOnDemand(t *testing.T) {
	m := NewListenerManager()
	// Create a listener and immediately close it.
	pc, err := m.ListenPacket("127.0.0.1:0", false)
	require.NoError(t, err)
	pc.Close()
	// Now create another listener on the same address.
	pc2, err := m.ListenPacket("127.0.0.1:0", false)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		_, _, readErr := pc2.ReadFrom(nil)
		require.NoError(t, readErr)
		done <- struct{}{}
	}()
	_, err = pc2.WriteTo(nil, pc2.LocalAddr())

	require.NoError(t, err)
	<-done
}

type testRefCount struct {
	onCloseFunc func()
}

func (t *testRefCount) Close() error {
	t.onCloseFunc()
	return nil
}

func TestRefCount(t *testing.T) {
	var objectCloseDone bool
	var onCloseFuncDone bool
	rc := NewRefCount[*testRefCount](
		&testRefCount{
			onCloseFunc: func() {
				objectCloseDone = true
			},
		},
		func() error {
			onCloseFuncDone = true
			return nil
		},
	)
	rc.Acquire()
	rc.Acquire()

	require.NoError(t, rc.Close())
	require.False(t, objectCloseDone)
	require.False(t, onCloseFuncDone)

	require.NoError(t, rc.Close())
	require.True(t, objectCloseDone)
	require.True(t, onCloseFuncDone)
}
