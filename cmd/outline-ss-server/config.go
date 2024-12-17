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
	Listeners []ListenerConfig `yaml:"listeners"`
	Keys      []KeyConfig      `yaml:"keys"`
}

type ListenerType string

const (
	listenerTypeTCP             ListenerType = "tcp"
	listenerTypeUDP             ListenerType = "udp"
	listenerTypeWebsocketStream ListenerType = "websocket-stream"
	listenerTypeWebsocketPacket ListenerType = "websocket-packet"
)

type WebServerConfig struct {
	ID        string   `yaml:"id"`
	Listeners []string `yaml:"listen"`
}

type ListenerConfig struct {
	Type      ListenerType `yaml:"type"`
	Address   string       `yaml:"address,omitempty"`
	WebServer string       `yaml:"web_server,omitempty"`
	Path      string       `yaml:"path,omitempty"`
}

type KeyConfig struct {
	ID     string `yaml:"id"`
	Cipher string `yaml:"cipher"`
	Secret string `yaml:"secret"`
}

type LegacyKeyServiceConfig struct {
	KeyConfig `yaml:",inline"`
	Port      int `yaml:"port"`
}

type WebConfig struct {
	Servers []WebServerConfig `yaml:"servers"`
}

type Config struct {
	Web WebConfig `yaml:"web"`
	Services []ServiceConfig `yaml:"services"`

	// Deprecated: `keys` exists for backward compatibility. Prefer to configure
	// using the newer `services` format.
	Keys []LegacyKeyServiceConfig `yaml:"keys"`
}

// Validate checks that the config is valid.
func (c *Config) Validate() error {
	existingWebServers := make(map[string]bool)
	for _, srv := range c.Web.Servers {
		if srv.ID == "" {
			return fmt.Errorf("web server must have an ID")
		}
		if _, exists := existingWebServers[srv.ID]; exists {
			return fmt.Errorf("web server with ID `%s` already exists", srv.ID)
		}
		existingWebServers[srv.ID] = true

		for _, addr := range srv.Listeners {
			if err := validateAddress(addr); err != nil {
				return fmt.Errorf("invalid listener for web server `%s`: %w", srv.ID, err)
			}
		}
	}

	existingListeners := make(map[string]bool)
	for _, serviceConfig := range c.Services {
		for _, lnConfig := range serviceConfig.Listeners {
			var key string
			switch lnConfig.Type {
			case listenerTypeTCP, listenerTypeUDP:
				if err := validateAddress(lnConfig.Address); err != nil {
					return err
				}
				key = fmt.Sprintf("%s/%s", lnConfig.Type, lnConfig.Address)
				if _, exists := existingListeners[key]; exists {
					return fmt.Errorf("listener of type `%s` with address `%s` already exists.", lnConfig.Type, lnConfig.Address)
				}
			case listenerTypeWebsocketStream, listenerTypeWebsocketPacket:
				if lnConfig.WebServer == "" {
					return fmt.Errorf("listener type `%s` requires a `web_server`", lnConfig.Type)
				}
				if lnConfig.Path == "" {
					return fmt.Errorf("listener type `%s` requires a `path`", lnConfig.Type)
				}
				if _, exists := existingWebServers[lnConfig.WebServer]; !exists {
					return fmt.Errorf("listener type `%s` references unknown web server `%s`", lnConfig.Type, lnConfig.WebServer)
				}
				key = fmt.Sprintf("%s/%s", lnConfig.Type, lnConfig.WebServer)
				if _, exists := existingListeners[key]; exists {
					return fmt.Errorf("listener of type `%s` with web server `%s` already exists.", lnConfig.Type, lnConfig.WebServer)
				}
			default:
				return fmt.Errorf("unsupported listener type: %s", lnConfig.Type)
			}

			existingListeners[key] = true
		}
	}
	return nil
}

func validateAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listener address `%s`: %v", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("address must be IP, found: %s", host)
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
