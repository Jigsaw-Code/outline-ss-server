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
	"net/netip"
	"testing"
)

func TestParseAddrPortOrIP(t *testing.T) {
	tests := []struct {
		name         string
		addrString   string
		wantAddrPort netip.AddrPort
		wantErr      bool
	}{
		{
			name:         "Valid IP",
			addrString:   "192.168.1.1",
			wantAddrPort: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 0),
			wantErr:      false,
		},
		{
			name:         "Valid IP:Port",
			addrString:   "192.168.1.1:8080",
			wantAddrPort: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 8080),
			wantErr:      false,
		},
		{
			name:         "Valid IPv6",
			addrString:   "2001:db8::1",
			wantAddrPort: netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), 0),
			wantErr:      false,
		},
		{
			name:         "Valid IPv6:Port",
			addrString:   "[2001:db8::1]:80", // Note the brackets for IPv6
			wantAddrPort: netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), 80),
			wantErr:      false,
		},
		{
			name:         "Invalid IP",
			addrString:   "invalid-ip",
			wantAddrPort: netip.AddrPort{},
			wantErr:      true,
		},
		{
			name:         "Invalid Port",
			addrString:   "192.168.1.1:abc",
			wantAddrPort: netip.AddrPort{},
			wantErr:      true,
		},
		{
			name:         "Missing Port Colon",
			addrString:   "192.168.1.18080",
			wantAddrPort: netip.AddrPort{},
			wantErr:      true,
		},
		{
			name:         "Empty String",
			addrString:   "",
			wantAddrPort: netip.AddrPort{},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAddrPort, gotErr := ParseAddrPortOrIP(tt.addrString)
			if (gotErr != nil) != tt.wantErr {
				t.Errorf("ParseAddrPortOrIP() error = %v, wantErr %v", gotErr, tt.wantErr)
				return
			}
			if gotAddrPort != tt.wantAddrPort {
				t.Errorf("ParseAddrPortOrIP() gotAddrPort = %v, want %v", gotAddrPort, tt.wantAddrPort)
			}
		})
	}
}
