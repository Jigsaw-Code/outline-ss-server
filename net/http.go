// Copyright 2025 The Outline Authors
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

package net

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

// GetClientIPFromRequest retrieves the client's IP address from the request.
// This checks common headers that forward the client IP, falling back to the
// request's `RemoteAddr`.
func GetClientIPFromRequest(r *http.Request) (net.IP, error) {
	clientIP, err := func() (string, error) {
		// `Forwarded` (RFC 7239).
		forwardedHeader := r.Header.Get("Forwarded")
		if forwardedHeader != "" {
			parts := strings.Split(forwardedHeader, ",")
			firstPart := strings.TrimSpace(parts[0])
			subParts := strings.Split(firstPart, ";")
			for _, part := range subParts {
				normalisedPart := strings.ToLower(strings.TrimSpace(part))
				if strings.HasPrefix(normalisedPart, "for=") {
					return normalisedPart[4:], nil
				}
			}
		}

		// `X-Forwarded-For`` is potentially a list of addresses separated with ",".
		// The first item represents the original client.
		xForwardedForHeader := r.Header.Get("X-Forwarded-For")
		if xForwardedForHeader != "" {
			parts := strings.Split(xForwardedForHeader, ",")
			firstIP := strings.TrimSpace(parts[0])
			return firstIP, nil
		}

		// `X-Real-IP`.
		xRealIpHeader := r.Header.Get("X-Real-IP")
		if xRealIpHeader != "" {
			return xRealIpHeader, nil
		}

		// Fallback to the request's `RemoteAddr`, but be aware this is the last
		// proxy's IP, not the client's.
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		return ip, err
	}()
	if err != nil {
		return nil, err
	}

	parsedIP := net.ParseIP(clientIP)
	if parsedIP != nil {
		return parsedIP, nil
	}
	return nil, errors.New("no client IP found")
}
