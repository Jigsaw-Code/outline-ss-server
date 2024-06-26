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

import logging "github.com/op/go-logging"

var logger = logging.MustGetLogger("shadowsocks")

type DebugLoggerFunc func(tag string, template string, val interface{})

// NewDebugLogger creates a wrapper for logger.Debugf during proxying.
func NewDebugLogger(protocol string) DebugLoggerFunc {
	return func(tag string, template string, val interface{}) {
		// This is an optimization to reduce unnecessary allocations due to an interaction
		// between Go's inlining/escape analysis and varargs functions like logger.Debugf.
		if logger.IsEnabledFor(logging.DEBUG) {
			logger.Debugf("%s(%s): "+template, protocol, tag, val)
		}
	}
}
