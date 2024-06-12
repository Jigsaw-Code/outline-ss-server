// Copyright 2024 Jigsaw Operations LLC
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
	"net"
	"net/url"
)

// Resolves a URL-style listen address specification as a [net.Addr]
//
// Examples:
//
//	udp6://127.0.0.1:8000
//	unix:///tmp/foo.sock
//	tcp://127.0.0.1:9002
func ResolveAddr(addr string) (net.Addr, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "tcp", "tcp4", "tcp6":
		return net.ResolveTCPAddr(u.Scheme, u.Host)
	case "udp", "udp4", "udp6":
		return net.ResolveUDPAddr(u.Scheme, u.Host)
	case "unix", "unixgram", "unixpacket":
		var path string
		if u.Opaque != "" {
			path = u.Opaque
		} else {
			path = u.Path
		}
		return net.ResolveUnixAddr(u.Scheme, path)
	default:
		return nil, net.UnknownNetworkError(u.Scheme)
	}
}
