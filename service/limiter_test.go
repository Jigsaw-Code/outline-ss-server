// Copyright 2020 Jigsaw Operations LLC
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

package service

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func makeRandBuffer(n int64) *bytes.Buffer {
	arr := make([]byte, n)
	rand.Read(arr)
	return bytes.NewBuffer(arr)
}

func TestTrafficLimiter(t *testing.T) {
	key1 := "key1"
	key2 := "key2"
	key3 := "key3"

	config := TrafficLimiterConfig{
		KeyToRateLimit: map[string]int{
			key1: 20,
			key2: 30,
			key3: 0,
		},
	}

	limiter := NewTrafficLimiter(&config)

	src1Buf := makeRandBuffer(100)
	src1 := src1Buf.Bytes()
	dst1 := &bytes.Buffer{}

	src2Buf := makeRandBuffer(100)
	src2 := src2Buf.Bytes()
	dst2 := &bytes.Buffer{}

	src3Buf := makeRandBuffer(100)
	src3 := src3Buf.Bytes()
	dst3 := &bytes.Buffer{}

	r1, w1 := limiter.WrapReaderWriter(key1, src1Buf, dst1)
	r2, w2 := limiter.WrapReaderWriter(key2, src2Buf, dst2)
	r3, w3 := limiter.WrapReaderWriter(key3, src3Buf, dst3)

	doRead := func(buf []byte, r io.Reader, n int) time.Duration {
		b := make([]byte, n)
		start := time.Now()
		_, err := io.ReadFull(r, b)
		require.NoError(t, err)
		require.Equal(t, b, buf[:len(b)])
		return time.Now().Sub(start)
	}

	period1 := doRead(src1, r1, 20)
	if period1 > 10*time.Millisecond {
		t.Errorf("read took too long")
	}

	period2 := doRead(src2, r2, 30)
	if period2 > 10*time.Millisecond {
		t.Errorf("read took too long")
	}

	period3 := doRead(src3, r3, 100)
	if period3 > 10*time.Millisecond {
		t.Errorf("read took too long")
	}

	doWrite := func(buf []byte, dst *bytes.Buffer, w io.Writer) time.Duration {
		start := time.Now()
		size := len(buf)
		_, err := w.Write(buf)
		require.NoError(t, err)
		require.Equal(t, buf, dst.Bytes()[:size])
		return time.Now().Sub(start)
	}

	// Waiting works even for payload exceeding one second burst.
	period4 := doWrite(src1[:30], dst1, w1)
	if period4 < 500*time.Millisecond {
		t.Fatalf("write took too short")
	}

	allowed := limiter.Allow(key2, 30)
	require.True(t, allowed)

	allowed = limiter.Allow(key2, 10)
	require.False(t, allowed)

	period5 := doWrite(src2[:30], dst2, w2)
	if period5 < 500*time.Millisecond {
		t.Fatalf("write took too short")
	}

	allowed = limiter.Allow(key3, 1000)
	require.True(t, allowed)

	period6 := doWrite(src3[:100], dst3, w3)
	if period6 > 10*time.Millisecond {
		t.Fatalf("write took too long")
	}
}
