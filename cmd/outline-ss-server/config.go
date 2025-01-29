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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

type Validator interface {
	// Validate checks that the type is valid.
	validate() error
}

type ServiceConfig struct {
	Listeners []ListenerConfig
	Keys      []KeyConfig
	Dialer    DialerConfig
}

type ListenerType string

const (
	TCPListenerType             = ListenerType("tcp")
	UDPListenerType             = ListenerType("udp")
	WebsocketStreamListenerType = ListenerType("websocket-stream")
	WebsocketPacketListenerType = ListenerType("websocket-packet")
)

type WebServerConfig struct {
	ID string

	// List of listener addresses (e.g., ":8080", "localhost:8081"). Should be localhost for HTTP.
	Listeners []string `yaml:"listen"`
}

type TCPUDPConfig struct {
	Address string
}

type ListenerConfig struct {
	TCP             *TCPUDPConfig
	UDP             *TCPUDPConfig
	WebsocketStream *WebsocketConfig
	WebsocketPacket *WebsocketConfig
}

var _ Validator = (*ListenerConfig)(nil)
var _ yaml.Unmarshaler = (*ListenerConfig)(nil)

func (c *ListenerConfig) UnmarshalYAML(value *yaml.Node) error {
	raw := make(map[string]interface{})
	if err := value.Decode(&raw); err != nil {
		return err
	}

	// The `type` is embedded in the value, which we should remove.
	rawType, ok := raw["type"]
	if !ok {
		return errors.New("`type` field required")
	}
	delete(raw, "type")

	jsonData, err := json.Marshal(raw)
	if err != nil {
		return err
	}

	switch ListenerType(rawType.(string)) {
	case TCPListenerType:
		c.TCP = &TCPUDPConfig{}
		if err := json.Unmarshal(jsonData, c.TCP); err != nil {
			return err
		}

	case UDPListenerType:
		c.UDP = &TCPUDPConfig{}
		if err := json.Unmarshal(jsonData, c.UDP); err != nil {
			return err
		}

	case WebsocketStreamListenerType:
		c.WebsocketStream = &WebsocketConfig{}
		if err := json.Unmarshal(jsonData, c.WebsocketStream); err != nil {
			return err
		}

	case WebsocketPacketListenerType:
		c.WebsocketPacket = &WebsocketConfig{}
		if err := json.Unmarshal(jsonData, c.WebsocketPacket); err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid listener type: %v", rawType)
	}
	return nil
}

func (c *ListenerConfig) validate() error {
	v := reflect.ValueOf(c).Elem()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.Ptr && field.IsNil() {
			continue
		}
		if field.Type().Implements(reflect.TypeOf((*Validator)(nil)).Elem()) {
			if err := field.Interface().(Validator).validate(); err != nil {
				return fmt.Errorf("invalid config: %v", err)
			}
		}
	}
	return nil
}

var _ Validator = (*TCPUDPConfig)(nil)

func (c *TCPUDPConfig) validate() error {
	if c.Address == "" {
		return errors.New("`address` must be specified")
	}
	if err := validateAddress(c.Address); err != nil {
		return fmt.Errorf("invalid address: %v", err)
	}
	return nil
}

type WebsocketConfig struct {
	WebServer string `json:"web_server"`
	Path      string
}

var _ Validator = (*WebsocketConfig)(nil)

func (c *WebsocketConfig) validate() error {
	if c.WebServer == "" {
		return errors.New("`web_server` must be specified")
	}
	if c.Path == "" {
		return errors.New("`path` must be specified")
	}
	if !strings.HasPrefix(c.Path, "/") {
		return errors.New("`path` must start with `/`")
	}
	return nil
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

type WebConfig struct {
	Servers []WebServerConfig `yaml:"servers"`
}

type Config struct {
	Web      WebConfig
	Services []ServiceConfig

	// Deprecated: `keys` exists for backward compatibility. Prefer to configure
	// using the newer `services` format.
	Keys []LegacyKeyServiceConfig
}

var _ Validator = (*Config)(nil)

func (c *Config) validate() error {
	for _, srv := range c.Web.Servers {
		if srv.ID == "" {
			return fmt.Errorf("web server must have an ID")
		}
		for _, addr := range srv.Listeners {
			if err := validateAddress(addr); err != nil {
				return fmt.Errorf("invalid listener for web server `%s`: %w", srv.ID, err)
			}
		}
	}

	for _, service := range c.Services {
		for _, ln := range service.Listeners {
			if err := ln.validate(); err != nil {
				return fmt.Errorf("invalid listener: %v", err)
			}
		}
	}
	return nil
}

func validateAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
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
