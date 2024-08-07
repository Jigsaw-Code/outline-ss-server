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
	"os"
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

func TestReadConfig(t *testing.T) {
	config, err := readConfigFile("./config_example.yml")

	require.NoError(t, err)
	expected := Config{
		Services: []ServiceConfig{
			ServiceConfig{
				Listeners: []ListenerConfig{
					ListenerConfig{Type: listenerTypeTCP, Address: "[::]:9000"},
					ListenerConfig{Type: listenerTypeUDP, Address: "[::]:9000"},
				},
				Keys: []KeyConfig{
					KeyConfig{"user-0", "chacha20-ietf-poly1305", "Secret0"},
					KeyConfig{"user-1", "chacha20-ietf-poly1305", "Secret1"},
				},
			},
			ServiceConfig{
				Listeners: []ListenerConfig{
					ListenerConfig{Type: listenerTypeTCP, Address: "[::]:9001"},
					ListenerConfig{Type: listenerTypeUDP, Address: "[::]:9001"},
				},
				Keys: []KeyConfig{
					KeyConfig{"user-2", "chacha20-ietf-poly1305", "Secret2"},
				},
			},
		},
	}
	require.Equal(t, expected, *config)
}

func TestReadConfigParsesDeprecatedFormat(t *testing.T) {
	config, err := readConfigFile("./config_example.deprecated.yml")

	require.NoError(t, err)
	expected := Config{
		Keys: []LegacyKeyServiceConfig{
			LegacyKeyServiceConfig{
				KeyConfig: KeyConfig{ID: "user-0", Cipher: "chacha20-ietf-poly1305", Secret: "Secret0"},
				Port:      9000,
			},
			LegacyKeyServiceConfig{
				KeyConfig: KeyConfig{ID: "user-1", Cipher: "chacha20-ietf-poly1305", Secret: "Secret1"},
				Port:      9000,
			},
			LegacyKeyServiceConfig{
				KeyConfig: KeyConfig{ID: "user-2", Cipher: "chacha20-ietf-poly1305", Secret: "Secret2"},
				Port:      9001,
			},
		},
	}
	require.Equal(t, expected, *config)
}

func TestReadConfigFromEmptyFile(t *testing.T) {
	file, _ := os.CreateTemp("", "empty.yaml")

	config, err := readConfigFile(file.Name())

	require.NoError(t, err)
	require.ElementsMatch(t, Config{}, config)
}

func TestReadConfigFromIncorrectFormatFails(t *testing.T) {
	file, _ := os.CreateTemp("", "empty.yaml")
	file.WriteString("foo")

	config, err := readConfigFile(file.Name())

	require.Error(t, err)
	require.ElementsMatch(t, Config{}, config)
}

func readConfigFile(filename string) (*Config, error) {
	configData, _ := os.ReadFile(filename)
	return readConfig(configData)
}
