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
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetClientIPFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		wantIP     string
		wantErr    bool
	}{
		{
			name:    "X-Forwarded-For (Single IP)",
			headers: map[string]string{"X-Forwarded-For": "10.0.0.1"},
			wantIP:  "10.0.0.1",
		},
		{
			name:    "X-Forwarded-For (Multiple IPs)",
			headers: map[string]string{"X-Forwarded-For": "10.0.0.1, 172.16.0.1"},
			wantIP:  "10.0.0.1",
		},
		{
			name:    "X-Real-IP",
			headers: map[string]string{"X-Real-IP": "192.168.2.200"},
			wantIP:  "192.168.2.200",
		},
		{
			name:    "Forwarded",
			headers: map[string]string{"Forwarded": "for=192.168.3.100"},
			wantIP:  "192.168.3.100",
		},
		{
			name:       "RemoteAddr (host:port)",
			remoteAddr: "172.17.0.1:12345",
			wantIP:     "172.17.0.1",
		},
		{
			name:       "RemoteAddr (IP only)",
			remoteAddr: "172.17.0.1",
			wantErr:    true,
		},
		{
			name:    "No Headers, No RemoteAddr",
			wantErr: true,
		},
		{
			name:    "Invalid IP in header",
			headers: map[string]string{"X-Forwarded-For": "invalid-ip"},
			wantErr: true,
		},
		{
			name:       "Invalid RemoteAddr",
			remoteAddr: "invalid-ip:port",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				Header:     make(http.Header),
				RemoteAddr: tt.remoteAddr,
			}
			for h, v := range tt.headers {
				r.Header.Set(h, v)
			}

			gotIP, err := GetClientIPFromRequest(r)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}

			wantIP := net.ParseIP(tt.wantIP)
			if !gotIP.Equal(wantIP) {
				t.Errorf("err = %v, want %v", gotIP, wantIP)
			}
		})
	}
}
