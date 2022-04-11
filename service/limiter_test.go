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

func TestRateLimiter(t *testing.T) {
	key1 := "key1"
	key2 := "key2"

	var tok int64 = 1024
	config := RateLimiterConfig{
		KeyToLimits: map[string]KeyLimits{
			key1: KeyLimits {
				LargeScalePeriod: time.Minute,
				LargeScaleLimit: 10 * tok,
				SmallScalePeriod: time.Second,
				SmallScaleLimit: 2 * tok,
			},
			key2: KeyLimits{
				LargeScalePeriod: time.Minute,
				LargeScaleLimit: 10 * tok,
				SmallScalePeriod: time.Second,
				SmallScaleLimit: 3 * tok,
			},
		},
	}

	limiter := NewRateLimiter(&config)

	src1 := makeRandBuffer(20 * tok)
	src1Orig := src1.Bytes()
	dst1 := &bytes.Buffer{}

	src2 := makeRandBuffer(20 * tok)
	src2Orig := src2.Bytes()
	dst2 := &bytes.Buffer{}

	r1, w1, err1 := limiter.WrapReaderWriter(key1, src1, dst1)
	require.NoError(t, err1)
	r2, w2, err2 := limiter.WrapReaderWriter(key2, src2, dst2)
	require.NoError(t, err2)

	b := make([]byte, 50)

	start := time.Now()
	_, err := io.ReadFull(r1, b)
	require.NoError(t, err)
	require.Equal(t, b, src1Orig[:len(b)])
	if time.Now().Sub(start) > 10 * time.Millisecond {
		t.Errorf("read took too long")
	}

	start = time.Now()
	_, err = io.ReadFull(r2, b)
	require.NoError(t, err)
	require.Equal(t, b, src2Orig[:len(b)])
	if time.Now().Sub(start) > 10 * time.Millisecond {
		t.Errorf("read took too long")
	}

	start = time.Now()
	size := 2 * tok
	_, err = w1.Write(src1Orig[:size])
	require.NoError(t, err)
	require.Equal(t, src1Orig[:size], dst1.Bytes()[:size])
	if time.Now().Sub(start) < 500 * time.Millisecond {
		t.Fatalf("write took too short")
	}

	allowErr := limiter.Allow(key2, int(3 * tok))
	require.NoError(t, allowErr)

	allowErr = limiter.Allow(key2, int(1 * tok))
	require.Error(t, allowErr)

	start = time.Now()
	size = 3 * tok
	_, err = w2.Write(src2Orig[:size])
	require.NoError(t, err)
	require.Equal(t, src2Orig[:size], dst2.Bytes()[:size])
	if time.Now().Sub(start) < 500 * time.Millisecond {
		t.Fatalf("write took too short")
	}

	start = time.Now()
	size = 7 * tok
	_, err = w2.Write(src2Orig[:size])
	require.Error(t, err)
	if time.Now().Sub(start) > 10 * time.Millisecond {
		t.Fatalf("write took too long")
	}
}