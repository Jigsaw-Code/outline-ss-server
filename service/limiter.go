// Copyright 2018 Jigsaw Operations LLC
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
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"time"

	"golang.org/x/time/rate"
)

type TrafficLimits struct {
	LargeScalePeriod time.Duration
	LargeScaleLimit  int64
	SmallScalePeriod time.Duration
	SmallScaleLimit  int64
}

type TrafficLimiterConfig struct {
	// If the corresponding KeyLimits is nil, it means no limits
	KeyToLimits map[string]*TrafficLimits
}

type TrafficLimiter interface {
	WrapReaderWriter(accessKey string, reader io.Reader, writer io.Writer) (io.Reader, io.Writer)
	Allow(accessKey string, n int) error
}

func NewTrafficLimiter(config *TrafficLimiterConfig) TrafficLimiter {
	keyToLimiter := make(map[string]*perKeyLimiter, len(config.KeyToLimits))
	for accessKey, limits := range config.KeyToLimits {
		var limiter *perKeyLimiter
		if limits == nil {
			limiter = nil
		} else {
			limiter = &perKeyLimiter{
				largeScale: createLimiter(limits.LargeScalePeriod, limits.LargeScaleLimit),
				smallScale: createLimiter(limits.SmallScalePeriod, limits.SmallScaleLimit),
			}
		}
		keyToLimiter[accessKey] = limiter
	}
	return &trafficLimiter{keyToLimiter: keyToLimiter}
}

type trafficLimiter struct {
	keyToLimiter map[string]*perKeyLimiter
}

type perKeyLimiter struct {
	smallScale *rate.Limiter
	largeScale *rate.Limiter
}

// We need larger granularity, because rate.TrafficLimiter
// works with ints.
const tokenSizeBytes = 1024
const maxSizeBytes = math.MaxInt32 * tokenSizeBytes

func bytesToTokens64(n int64) int {
	// Round up to avoid attack involving small reads.
	if n >= maxSizeBytes {
		log.Panicf("%v bytes cannot be converted to tokens", n)
	}
	return (int)((n + tokenSizeBytes - 1) / tokenSizeBytes)
}

func bytesToTokens(n int) int {
	// Round up to avoid attack involving small reads.
	return (n + tokenSizeBytes - 1) / tokenSizeBytes
}

func min(a int, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func (l *perKeyLimiter) Wait(n int) error {
	tokens := bytesToTokens(n)
	if !l.largeScale.AllowN(time.Now(), tokens) {
		return fmt.Errorf("exceeds large scale limit")
	}
	waited := 0
	for waited < tokens {
		batch := min(tokens, int(l.smallScale.Burst()))
		err := l.smallScale.WaitN(context.TODO(), batch)
		if err != nil {
			return err
		}
		waited += batch
	}
	return nil
}

func (l *perKeyLimiter) Allow(n int) error {
	tokens := bytesToTokens(n)
	if !l.largeScale.AllowN(time.Now(), tokens) {
		return fmt.Errorf("exceeds large-scale limit")
	}
	if !l.smallScale.AllowN(time.Now(), tokens) {
		return fmt.Errorf("exceeds small-scale limit")
	}
	return nil
}

type limitedReader struct {
	reader  io.Reader
	limiter *perKeyLimiter
}

func (r *limitedReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	if n <= 0 {
		return n, err
	}
	waitErr := r.limiter.Wait(n)
	if waitErr != nil {
		return 0, waitErr
	}
	return n, err
}

type limitedWriter struct {
	writer  io.Writer
	limiter *perKeyLimiter
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	n, err := w.writer.Write(b)
	if n <= 0 {
		return n, err
	}
	waitErr := w.limiter.Wait(n)
	if waitErr != nil {
		return 0, waitErr
	}
	return n, err
}

func createLimiter(period time.Duration, limit int64) *rate.Limiter {
	b := bytesToTokens64(limit)
	r := rate.Every(period) * rate.Limit(b)
	return rate.NewLimiter(r, b)
}

func (l *trafficLimiter) WrapReaderWriter(accessKey string, reader io.Reader, writer io.Writer) (io.Reader, io.Writer) {
	limiter, ok := l.keyToLimiter[accessKey]
	if !ok {
		logger.Panicf("Access key %v not found", accessKey)
	}
	if limiter == nil {
		return reader, writer
	}
	return &limitedReader{reader: reader, limiter: limiter}, &limitedWriter{writer: writer, limiter: limiter}
}

func (l *trafficLimiter) Allow(accessKey string, n int) error {
	limiter, ok := l.keyToLimiter[accessKey]
	if !ok {
		logger.Panicf("Access key %v not found", accessKey)
	}
	if limiter == nil {
		return nil
	}
	return limiter.Allow(n)
}
