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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadConfig(t *testing.T) {
	config, _ := ReadConfig("./config_example.yml")

	expected := Config{
		Services: []Service{
			Service{
				Listeners: []Listener{
					Listener{Type: "direct", Address: "tcp://[::]:9000"},
					Listener{Type: "direct", Address: "udp://[::]:9000"},
				},
				Keys: []Key{
					Key{"user-0", "chacha20-ietf-poly1305", "Secret0"},
					Key{"user-1", "chacha20-ietf-poly1305", "Secret1"},
				},
			},
			Service{
				Listeners: []Listener{
					Listener{Type: "direct", Address: "tcp://[::]:9001"},
					Listener{Type: "direct", Address: "udp://[::]:9001"},
				},
				Keys: []Key{
					Key{"user-2", "chacha20-ietf-poly1305", "Secret2"},
				},
			},
		},
	}
	require.Equal(t, expected, *config)
}

func TestReadConfigParsesDeprecatedFormat(t *testing.T) {
	config, _ := ReadConfig("./config_example.deprecated.yml")

	expected := Config{
		Services: []Service{
			Service{
				Listeners: []Listener{
					Listener{Type: "direct", Address: "tcp://[::]:9000"},
					Listener{Type: "direct", Address: "udp://[::]:9000"},
				},
				Keys: []Key{
					Key{"user-0", "chacha20-ietf-poly1305", "Secret0"},
					Key{"user-1", "chacha20-ietf-poly1305", "Secret1"},
				},
			},
			Service{
				Listeners: []Listener{
					Listener{Type: "direct", Address: "tcp://[::]:9001"},
					Listener{Type: "direct", Address: "udp://[::]:9001"},
				},
				Keys: []Key{
					Key{"user-2", "chacha20-ietf-poly1305", "Secret2"},
				},
			},
		},
	}
	require.Equal(t, expected, *config)
}
