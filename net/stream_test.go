// Copyright 2023 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package net

import (
	"context"
	"net"
	"sync"
	"testing"
	"testing/iotest"
)

func TestNewTCPEndpointIPv4(t *testing.T) {
	requestText := []byte("Request")
	responseText := []byte("Response")

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("Failed to create TCP listener: %v", err)
	}
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		defer listener.Close()
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			t.Errorf("AcceptTCP failed: %v", err)
			return
		}
		defer clientConn.Close()
		if err = iotest.TestReader(clientConn, requestText); err != nil {
			t.Errorf("Request read failed: %v", err)
			return
		}
		if err = clientConn.CloseRead(); err != nil {
			t.Errorf("CloseRead failed: %v", err)
			return
		}
		if _, err = clientConn.Write(responseText); err != nil {
			t.Errorf("Write failed: %v", err)
			return
		}
		if err = clientConn.CloseWrite(); err != nil {
			t.Errorf("CloseWrite failed: %v", err)
			return
		}
	}()

	e := TCPEndpoint{RemoteAddr: *listener.Addr().(*net.TCPAddr)}
	serverConn, err := e.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer serverConn.Close()
	serverConn.Write(requestText)
	serverConn.CloseWrite()
	if err = iotest.TestReader(serverConn, responseText); err != nil {
		t.Fatalf("Response read failed: %v", err)
	}
	serverConn.CloseRead()
	running.Wait()
}
