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

type Service struct {
	Listeners []Listener
	Keys      []Key
}

type ListenerType string

const listenerTypeDirect ListenerType = "direct"

type Listener struct {
	Type    ListenerType
	Address string
}

type Key struct {
	ID     string
	Cipher string
	Secret string
}

type LegacyKeyService struct {
	Key  `yaml:",inline"`
	Port int
}

type Config struct {
	Services []Service

	// Deprecated: `keys` exists for backward compatibility. Prefer to configure
	// using the newer `services` format.
	Keys []LegacyKeyService
}

// Reads a config from a filename and parses it as a [Config].
func ReadConfig(filename string) (*Config, error) {
	config := Config{}
	configData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Specifying keys in `config.Keys` is a deprecated config format. We need to
	// transform it to to the new format.
	ports := make(map[int][]Key)
	for _, keyConfig := range config.Keys {
		ports[keyConfig.Port] = append(ports[keyConfig.Port], Key{
			ID:     keyConfig.ID,
			Cipher: keyConfig.Cipher,
			Secret: keyConfig.Secret,
		})
	}
	for port, keys := range ports {
		s := Service{
			Listeners: []Listener{
				Listener{Type: listenerTypeDirect, Address: fmt.Sprintf("tcp://[::]:%d", port)},
				Listener{Type: listenerTypeDirect, Address: fmt.Sprintf("udp://[::]:%d", port)},
			},
			Keys: keys,
		}
		config.Services = append(config.Services, s)
	}
	config.Keys = nil

	return &config, nil
}

// validateListener asserts that a listener URI conforms to the expected format.
func validateListener(u *url.URL) error {
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

func newListener(addr string) (io.Closer, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "tcp", "tcp4", "tcp6":
		if err := validateListener(u); err != nil {
			return nil, fmt.Errorf("invalid listener `%s`: %v", u, err)
		}
		return net.Listen(u.Scheme, u.Host)
	case "udp", "udp4", "udp6":
		if err := validateListener(u); err != nil {
			return nil, fmt.Errorf("invalid listener `%s`: %v", u, err)
		}
		return net.ListenPacket(u.Scheme, u.Host)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", u.Scheme)
	}
}
