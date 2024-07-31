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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenerManagerStreamListenerEarlyClose(t *testing.T) {
	m := NewListenerManager()
	ln, err := m.ListenStream("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ln.Close()
	_, err = ln.AcceptStream()

	require.ErrorIs(t, err, net.ErrClosed)
}

type testRefCount struct {
	onCloseFunc func()
}

func (t *testRefCount) Close() error {
	t.onCloseFunc()
	return nil
}

func TestRefCount(t *testing.T) {
	var done bool
	rc := NewRefCount[*testRefCount](&testRefCount{
		onCloseFunc: func() {
			done = true
		},
	})
	rc.Acquire()

	require.NoError(t, rc.Close())
	require.False(t, done)

	require.NoError(t, rc.Close())
	require.True(t, done)
}
