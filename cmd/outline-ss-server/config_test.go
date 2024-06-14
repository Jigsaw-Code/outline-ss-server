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

func TestReadConfig(t *testing.T) {
	config, err := ReadConfig("./config_example.yml")

	require.NoError(t, err)
	expected := Config{
		Services: []Service{
			Service{
				Listeners: []Listener{
					Listener{Type: listenerTypeDirect, Address: "tcp://[::]:9000"},
					Listener{Type: listenerTypeDirect, Address: "udp://[::]:9000"},
				},
				Keys: []Key{
					Key{"user-0", "chacha20-ietf-poly1305", "Secret0"},
					Key{"user-1", "chacha20-ietf-poly1305", "Secret1"},
				},
			},
			Service{
				Listeners: []Listener{
					Listener{Type: listenerTypeDirect, Address: "tcp://[::]:9001"},
					Listener{Type: listenerTypeDirect, Address: "udp://[::]:9001"},
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
	config, err := ReadConfig("./config_example.deprecated.yml")

	require.NoError(t, err)
	expected := Config{
		Keys: []LegacyKeyService{
			LegacyKeyService{
				Key:  Key{ID: "user-0", Cipher: "chacha20-ietf-poly1305", Secret: "Secret0"},
				Port: 9000,
			},
			LegacyKeyService{
				Key:  Key{ID: "user-1", Cipher: "chacha20-ietf-poly1305", Secret: "Secret1"},
				Port: 9000,
			},
			LegacyKeyService{
				Key:  Key{ID: "user-2", Cipher: "chacha20-ietf-poly1305", Secret: "Secret2"},
				Port: 9001,
			},
		},
	}
	require.Equal(t, expected, *config)
}

func TestReadConfigFromEmptyFile(t *testing.T) {
	file, _ := os.CreateTemp("", "empty.yaml")

	config, err := ReadConfig(file.Name())

	require.NoError(t, err)
	require.ElementsMatch(t, Config{}, config)
}

func TestReadConfigFromNonExistingFileFails(t *testing.T) {
	config, err := ReadConfig("./foo")

	require.Error(t, err)
	require.ElementsMatch(t, nil, config)
}

func TestReadConfigFromIncorrectFormatFails(t *testing.T) {
	file, _ := os.CreateTemp("", "empty.yaml")
	file.WriteString("foo")

	config, err := ReadConfig(file.Name())

	require.Error(t, err)
	require.ElementsMatch(t, Config{}, config)
}
