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
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type ServiceConfig struct {
	Listeners []ListenerConfig
	Keys      []KeyConfig
}

type ListenerType string

const listenerTypeDirect ListenerType = "direct"

type ListenerConfig struct {
	Type    ListenerType
	Address string
}

type KeyConfig struct {
	ID     string
	Cipher string
	Secret string
}

type LegacyKeyServiceConfig struct {
	KeyConfig `yaml:",inline"`
	Port      int
}

type Config struct {
	Services []ServiceConfig

	// Deprecated: `keys` exists for backward compatibility. Prefer to configure
	// using the newer `services` format.
	Keys []LegacyKeyServiceConfig
}

// Validate checks that the config is valid.
func (c *Config) Validate() error {
	for _, serviceConfig := range c.Services {
		for _, listenerConfig := range serviceConfig.Listeners {
			// TODO: Support more listener types.
			if listenerConfig.Type != listenerTypeDirect {
				return fmt.Errorf("unsupported listener type: %s", listenerConfig.Type)
			}

			network, _, _, err := SplitNetworkAddr(listenerConfig.Address)
			if err != nil {
				return fmt.Errorf("invalid listener address `%s`: %v", listenerConfig.Address, err)
			}
			if network != "tcp" && network != "udp" {
				return fmt.Errorf("unsupported network: %s", network)
			}
		}
	}
	return nil
}

// readConfig attempts to read a config from a filename and parses it as a [Config].
func readConfig(filename string) (*Config, error) {
	config := Config{}
	configData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &config, nil
}
