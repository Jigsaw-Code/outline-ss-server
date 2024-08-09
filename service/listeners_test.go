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

	"github.com/stretchr/testify/require"
)

func TestListenerManagerStreamListenerEarlyClose(t *testing.T) {
	m := NewListenerManager()
	ln, err := m.ListenStream("127.0.0.1:0")
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
	ln, err := m.ListenStream("127.0.0.1:0")
	require.NoError(t, err)
	ln2, err := m.ListenStream("127.0.0.1:0")
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
	ln, err := m.ListenStream("127.0.0.1:0")
	require.NoError(t, err)
	ln.Close()
	// Now create another listener on the same address.
	ln2, err := m.ListenStream("127.0.0.1:0")
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
	pc, err := m.ListenPacket("127.0.0.1:0")
	require.NoError(t, err)

	pc.Close()
	_, _, readErr := pc.ReadFrom(nil)
	_, writeErr := pc.WriteTo(nil, &net.UDPAddr{})

	require.ErrorIs(t, readErr, net.ErrClosed)
	require.ErrorIs(t, writeErr, net.ErrClosed)
}

func TestListenerManagerPacketListenerNotClosedIfStillInUse(t *testing.T) {
	m := NewListenerManager()
	pc, err := m.ListenPacket("127.0.0.1:0")
	require.NoError(t, err)
	pc2, err := m.ListenPacket("127.0.0.1:0")
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
	pc, err := m.ListenPacket("127.0.0.1:0")
	require.NoError(t, err)
	pc.Close()
	// Now create another listener on the same address.
	pc2, err := m.ListenPacket("127.0.0.1:0")
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
