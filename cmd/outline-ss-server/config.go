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
	"net"

	"gopkg.in/yaml.v3"
)

type ServiceConfig struct {
	Listeners []ListenerConfig
	Keys      []KeyConfig
	Dialer    DialerConfig
}

type ListenerType string

const listenerTypeTCP ListenerType = "tcp"

const listenerTypeUDP ListenerType = "udp"

type ListenerConfig struct {
	Type    ListenerType
	Address string
}

type DialerConfig struct {
	Fwmark uint
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
	existingListeners := make(map[string]bool)
	for _, serviceConfig := range c.Services {
		for _, lnConfig := range serviceConfig.Listeners {
			// TODO: Support more listener types.
			if lnConfig.Type != listenerTypeTCP && lnConfig.Type != listenerTypeUDP {
				return fmt.Errorf("unsupported listener type: %s", lnConfig.Type)
			}
			host, _, err := net.SplitHostPort(lnConfig.Address)
			if err != nil {
				return fmt.Errorf("invalid listener address `%s`: %v", lnConfig.Address, err)
			}
			if ip := net.ParseIP(host); ip == nil {
				return fmt.Errorf("address must be IP, found: %s", host)
			}
			key := string(lnConfig.Type) + "/" + lnConfig.Address
			if _, exists := existingListeners[key]; exists {
				return fmt.Errorf("listener of type %s with address %s already exists.", lnConfig.Type, lnConfig.Address)
			}
			existingListeners[key] = true
		}
	}
	return nil
}

// readConfig attempts to read a config from a filename and parses it as a [Config].
func readConfig(configData []byte) (*Config, error) {
	config := Config{}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &config, nil
}
