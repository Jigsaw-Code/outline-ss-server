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
	"io"
	"time"

	"golang.org/x/time/rate"
)

type TrafficLimiterConfig struct {
	// Rate limit in bytes per second.
	// If the corresponding limit is zero, it means no limits
	KeyToRateLimit map[string]int
}

type TrafficLimiter interface {
	WrapReaderWriter(accessKey string, reader io.Reader, writer io.Writer) (io.Reader, io.Writer)
	Allow(accessKey string, n int) bool
}

func NewTrafficLimiter(config *TrafficLimiterConfig) TrafficLimiter {
	keyToLimiter := make(map[string]*rate.Limiter, len(config.KeyToRateLimit))
	for accessKey, limit := range config.KeyToRateLimit {
		var limiter *rate.Limiter
		if limit == 0 {
			limiter = nil
		} else {
			limiter = createLimiter(limit)
		}
		keyToLimiter[accessKey] = limiter
	}
	return &trafficLimiter{keyToLimiter: keyToLimiter}
}

type trafficLimiter struct {
	keyToLimiter map[string]*rate.Limiter
}

// doWait does the waiting for any n, even exceeding the burst limit.
func doWait(l *rate.Limiter, n int) error {
	ctx := context.TODO()
	b := l.Burst()
	for b < n {
		err := l.WaitN(ctx, b)
		if err != nil {
			return err
		}
		n -= b
	}
	return l.WaitN(ctx, n)
}

type limitedReader struct {
	reader  io.Reader
	limiter *rate.Limiter
}

func (r *limitedReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	if n <= 0 {
		return n, err
	}
	waitErr := doWait(r.limiter, n)
	if waitErr != nil {
		return 0, waitErr
	}
	return n, err
}

type limitedWriter struct {
	writer  io.Writer
	limiter *rate.Limiter
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	n, err := w.writer.Write(b)
	if n <= 0 {
		return n, err
	}
	waitErr := doWait(w.limiter, n)
	if waitErr != nil {
		return 0, waitErr
	}
	return n, err
}

func createLimiter(limit int) *rate.Limiter {
	burst := limit
	theRate := rate.Every(time.Second) * rate.Limit(burst)
	return rate.NewLimiter(theRate, burst)
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

func (l *trafficLimiter) Allow(accessKey string, n int) bool {
	limiter, ok := l.keyToLimiter[accessKey]
	if !ok {
		logger.Panicf("Access key %v not found", accessKey)
	}
	if limiter == nil {
		return true
	}
	return limiter.AllowN(time.Now(), n)
}
