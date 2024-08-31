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

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateConfigFails(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
	}{
		{
			name: "WithUnknownListenerType",
			cfg: &Config{
				Services: []ServiceConfig{
					ServiceConfig{
						Listeners: []ListenerConfig{
							ListenerConfig{Type: "foo", Address: "[::]:9000"},
						},
					},
				},
			},
		},
		{
			name: "WithInvalidListenerAddress",
			cfg: &Config{
				Services: []ServiceConfig{
					ServiceConfig{
						Listeners: []ListenerConfig{
							ListenerConfig{Type: listenerTypeTCP, Address: "tcp/[::]:9000"},
						},
					},
				},
			},
		},
		{
			name: "WithHostnameAddress",
			cfg: &Config{
				Services: []ServiceConfig{
					ServiceConfig{
						Listeners: []ListenerConfig{
							ListenerConfig{Type: listenerTypeTCP, Address: "example.com:9000"},
						},
					},
				},
			},
		},
		{
			name: "WithDuplicateListeners",
			cfg: &Config{
				Services: []ServiceConfig{
					ServiceConfig{
						Listeners: []ListenerConfig{
							ListenerConfig{Type: listenerTypeTCP, Address: "[::]:9000"},
						},
					},
					ServiceConfig{
						Listeners: []ListenerConfig{
							ListenerConfig{Type: listenerTypeTCP, Address: "[::]:9000"},
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			require.Error(t, err)
		})
	}
}
