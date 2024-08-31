// Copyright 2020 Jigsaw Operations LLC
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
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestRunSSServer(t *testing.T) {
	m := service.NewPrometheusOutlineMetrics(nil, prometheus.DefaultRegisterer)
	server, err := RunSSServer("config_example.yml", m, 30*time.Second, 10000)
	if err != nil {
		t.Fatalf("RunSSServer() error = %v", err)
	}
	if err := server.Stop(); err != nil {
		t.Errorf("Error while stopping server: %v", err)
	}
}

func TestReadConfig(t *testing.T) {
	config, err := readConfigFile("./config_example.yml")

	require.NoError(t, err)
	expected := service.Config{
		Services: []service.ServiceConfig{
			service.ServiceConfig{
				Listeners: []service.ListenerConfig{
					service.ListenerConfig{Type: "tcp", Address: "[::]:9000"},
					service.ListenerConfig{Type: "udp", Address: "[::]:9000"},
				},
				Keys: []service.KeyConfig{
					service.KeyConfig{"user-0", "chacha20-ietf-poly1305", "Secret0"},
					service.KeyConfig{"user-1", "chacha20-ietf-poly1305", "Secret1"},
				},
			},
			service.ServiceConfig{
				Listeners: []service.ListenerConfig{
					service.ListenerConfig{Type: "tcp", Address: "[::]:9001"},
					service.ListenerConfig{Type: "udp", Address: "[::]:9001"},
				},
				Keys: []service.KeyConfig{
					service.KeyConfig{"user-2", "chacha20-ietf-poly1305", "Secret2"},
				},
			},
		},
	}
	require.Equal(t, expected, *config)
}

func TestReadConfigParsesDeprecatedFormat(t *testing.T) {
	config, err := readConfigFile("./config_example.deprecated.yml")

	require.NoError(t, err)
	expected := service.Config{
		Keys: []service.LegacyKeyServiceConfig{
			service.LegacyKeyServiceConfig{
				KeyConfig: service.KeyConfig{ID: "user-0", Cipher: "chacha20-ietf-poly1305", Secret: "Secret0"},
				Port:      9000,
			},
			service.LegacyKeyServiceConfig{
				KeyConfig: service.KeyConfig{ID: "user-1", Cipher: "chacha20-ietf-poly1305", Secret: "Secret1"},
				Port:      9000,
			},
			service.LegacyKeyServiceConfig{
				KeyConfig: service.KeyConfig{ID: "user-2", Cipher: "chacha20-ietf-poly1305", Secret: "Secret2"},
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
	require.ElementsMatch(t, service.Config{}, config)
}

func TestReadConfigFromIncorrectFormatFails(t *testing.T) {
	file, _ := os.CreateTemp("", "empty.yaml")
	file.WriteString("foo")

	config, err := readConfigFile(file.Name())

	require.Error(t, err)
	require.ElementsMatch(t, service.Config{}, config)
}

func readConfigFile(filename string) (*service.Config, error) {
	configData, _ := os.ReadFile(filename)
	return readConfig(configData)
}
