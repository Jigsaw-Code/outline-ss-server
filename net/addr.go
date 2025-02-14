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
	"fmt"
	"net/netip"
)

// ParseAddrPortOrIP parses a string that may contain an IP address or an IP:port combination
// and returns a [netip.AddrPort]. If only an IP is provided, the port is set to 0. It returns
// an error if the input string is not a valid IP or IP:port.
func ParseAddrPortOrIP(addrStr string) (netip.AddrPort, error) {
	addrPort, err := netip.ParseAddrPort(addrStr)
	if err == nil {
		return addrPort, nil
	}

	addr, err := netip.ParseAddr(addrStr)
	if err == nil {
		// It's just an IP, no port.
		return netip.AddrPortFrom(addr, 0), nil
	}

	return netip.AddrPort{}, fmt.Errorf("invalid address: %s", addrStr)
}
