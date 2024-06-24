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
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
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
		if serviceConfig.Listeners == nil || serviceConfig.Keys == nil {
			return errors.New("must specify at least 1 listener and 1 key per service")
		}

		for _, listenerConfig := range serviceConfig.Listeners {
			// TODO: Support more listener types.
			if listenerConfig.Type != listenerTypeDirect {
				return fmt.Errorf("unsupported listener type: %s", listenerConfig.Type)
			}

			u, err := url.Parse(listenerConfig.Address)
			if err != nil {
				return err
			}
			switch u.Scheme {
			case "tcp", "udp":
				if err := validateListenerAddress(u); err != nil {
					return fmt.Errorf("invalid listener address `%s`: %v", u, err)
				}
			default:
				return fmt.Errorf("unsupported protocol: %s", u.Scheme)
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

// validateListenerAddress asserts that a listener URI conforms to the expected format.
func validateListenerAddress(u *url.URL) error {
	if u.Opaque != "" {
		return errors.New("URI cannot have an opaque part")
	}
	if u.User != nil {
		return errors.New("URI cannot have an userdata part")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("URI cannot have a query part")
	}
	if u.Fragment != "" {
		return errors.New("URI cannot have a fragement")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("URI path not allowed")
	}
	return nil
}

// newListener creates a new listener from a URL-style address specification.
//
// Example addresses:
//
//	tcp://127.0.0.1:8000
//	udp://127.0.0.1:9000
func newListener(addr string) (io.Closer, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "tcp":
		return net.Listen(u.Scheme, u.Host)
	case "udp":
		return net.ListenPacket(u.Scheme, u.Host)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", u.Scheme)
	}
}
