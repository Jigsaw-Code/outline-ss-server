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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Run("InvalidConfig", func(t *testing.T) {
		tests := []struct {
			name   string
			cfg    *Config
			errStr string
		}{
			{
				name: "UnknownListenerType",
				cfg: &Config{
					Services: []ServiceConfig{
						ServiceConfig{
							Listeners: []ListenerConfig{
								ListenerConfig{Type: "foo", Address: "[::]:9000"},
							},
						},
					},
				},
				errStr: "unsupported listener type",
			},
			{
				name: "InvalidListenerAddress",
				cfg: &Config{
					Services: []ServiceConfig{
						ServiceConfig{
							Listeners: []ListenerConfig{
								ListenerConfig{Type: listenerTypeTCP, Address: "tcp/[::]:9000"},
							},
						},
					},
				},
				errStr: "invalid listener address",
			},
			{
				name: "HostnameAddress",
				cfg: &Config{
					Services: []ServiceConfig{
						ServiceConfig{
							Listeners: []ListenerConfig{
								ListenerConfig{Type: listenerTypeTCP, Address: "example.com:9000"},
							},
						},
					},
				},
				errStr: "address must be IP",
			},
			{
				name: "DuplicateListeners",
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
				errStr: "already exists",
			},
			{
				name: "WebServerMissingID",
				cfg: &Config{
					Web: WebConfig{
						Servers: []WebServerConfig{
							{
								Listeners: []string{"[::]:8000"},
							},
						},
					},
					Services: []ServiceConfig{},
				},
				errStr: "web server must have an ID",
			},
			{
				name: "WebServerDuplicateID",
				cfg: &Config{
					Web: WebConfig{
						Servers: []WebServerConfig{
							{
								ID:        "foo",
								Listeners: []string{"[::]:8000"},
							},
							{
								ID:        "foo",
								Listeners: []string{"[::]:8001"},
							},
						},
					},
					Services: []ServiceConfig{},
				},
				errStr: "already exists",
			},
			{
				name: "WebServerInvalidAddress",
				cfg: &Config{
					Web: WebConfig{
						Servers: []WebServerConfig{
							{
								ID:        "foo",
								Listeners: []string{":invalid"},
							},
						},
					},
					Services: []ServiceConfig{},
				},
				errStr: "invalid listener for web server `foo`",
			},
			{
				name: "WebsocketListenerMissingWebServer",
				cfg: &Config{
					Web: WebConfig{
						Servers: []WebServerConfig{
							{
								ID:        "foo",
								Listeners: []string{"[::]:8000"},
							},
						},
					},
					Services: []ServiceConfig{
						{
							Listeners: []ListenerConfig{
								{
									Type: listenerTypeWebsocketStream,
									Path: "/tcp",
								},
							},
						},
					},
				},
				errStr: "requires a `web_server`",
			},
			{
				name: "WebsocketListenerUnknownWebServer",
				cfg: &Config{
					Web: WebConfig{
						Servers: []WebServerConfig{
							{
								ID:        "foo",
								Listeners: []string{"[::]:8000"},
							},
						},
					},
					Services: []ServiceConfig{
						{
							Listeners: []ListenerConfig{
								{
									Type:      listenerTypeWebsocketStream,
									WebServer: "unknown_server",
									Path:      "/tcp",
								},
							},
						},
					},
				},
				errStr: "unknown web server `unknown_server`",
			},
			{
				name: "WebsocketListenerMissingPath",
				cfg: &Config{
					Web: WebConfig{
						Servers: []WebServerConfig{
							{
								ID:        "foo",
								Listeners: []string{"[::]:8000"},
							},
						},
					},
					Services: []ServiceConfig{
						{
							Listeners: []ListenerConfig{
								{
									Type:      listenerTypeWebsocketStream,
									WebServer: "foo",
								},
							},
						},
					},
				},
				errStr: "requires a `path`",
			},
			{
				name: "ListenerInvalidType",
				cfg: &Config{
					Web: WebConfig{
						Servers: []WebServerConfig{
							{
								ID:        "foo",
								Listeners: []string{"[::]:8000"},
							},
						},
					},
					Services: []ServiceConfig{
						{
							Listeners: []ListenerConfig{
								{
									Type:      "invalid-type",
									WebServer: "foo",
									Path:      "/tcp",
								},
							},
						},
					},
				},
				errStr: "unsupported listener type: invalid-type",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.cfg.Validate()
				require.Error(t, err)
				if !isStrInError(err, tc.errStr) {
					t.Errorf("Config.Validate() error=`%v`, expected=`%v`", err, tc.errStr)
				}
			})
		}
	})

	t.Run("ValidConfig", func(t *testing.T) {
		config := Config{
			Web: WebConfig{
				Servers: []WebServerConfig{
					{
						ID:        "my_web_server",
						Listeners: []string{"[::]:8000"},
					},
				},
			},
			Services: []ServiceConfig{
				{
					Listeners: []ListenerConfig{
						{
							Type:      listenerTypeWebsocketStream,
							WebServer: "my_web_server",
							Path:      "/tcp",
						},
						{
							Type:      listenerTypeWebsocketPacket,
							WebServer: "my_web_server",
							Path:      "/udp",
						},
					},
					Keys: []KeyConfig{
						{
							ID:     "user-0",
							Cipher: "chacha20-ietf-poly1305",
							Secret: "Secret0",
						},
					},
				},
			},
		}
		err := config.Validate()
		require.NoError(t, err)
	})
}

func TestReadConfig(t *testing.T) {

	t.Run("ExampleFile", func(t *testing.T) {
		config, err := readConfigFile("./config_example.yml")

		require.NoError(t, err)
		expected := Config{
			Web: WebConfig{
				Servers: []WebServerConfig{
					WebServerConfig{ID: "my_web_server", Listeners: []string{"[::]:8000"}},
				},
			},
			Services: []ServiceConfig{
				ServiceConfig{
					Listeners: []ListenerConfig{
						ListenerConfig{Type: listenerTypeTCP, Address: "[::]:9000"},
						ListenerConfig{Type: listenerTypeUDP, Address: "[::]:9000"},
						ListenerConfig{Type: listenerTypeWebsocketStream, WebServer: "my_web_server", Path: "/tcp"},
						ListenerConfig{Type: listenerTypeWebsocketPacket, WebServer: "my_web_server", Path: "/udp"},
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
	})

	t.Run("ParsesDeprecatedFormat", func(t *testing.T) {
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
	})

	t.Run("FromEmptyFile", func(t *testing.T) {
		file, _ := os.CreateTemp("", "empty.yaml")

		config, err := readConfigFile(file.Name())

		require.NoError(t, err)
		require.ElementsMatch(t, Config{}, config)
	})

	t.Run("FromIncorrectFormatFails", func(t *testing.T) {
		file, _ := os.CreateTemp("", "empty.yaml")
		file.WriteString("foo")

		config, err := readConfigFile(file.Name())

		require.Error(t, err)
		require.ElementsMatch(t, Config{}, config)
	})
}

func readConfigFile(filename string) (*Config, error) {
	configData, _ := os.ReadFile(filename)
	return readConfig(configData)
}

func isStrInError(err error, str string) bool {
	return err != nil && strings.Contains(err.Error(), str)
}
