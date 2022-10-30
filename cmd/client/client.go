// Copyright 2022 Jigsaw Operations LLC
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
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Jigsaw-Code/outline-ss-server/client"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"golang.org/x/crypto/ssh/terminal"
)

var logger *logging.Logger

func init() {
	var prefix = "%{level:.1s}%{time:2006-01-02T15:04:05.000Z07:00} %{pid} %{shortfile}]"
	if terminal.IsTerminal(int(os.Stderr.Fd())) {
		// Add color only if the output is the terminal
		prefix = strings.Join([]string{"%{color}", prefix, "%{color:reset}"}, "")
	}
	logging.SetFormatter(logging.MustStringFormatter(strings.Join([]string{prefix, " %{message}"}, "")))
	logging.SetBackend(logging.NewLogBackend(os.Stderr, "", 0))
	logger = logging.MustGetLogger("")
}

type serverConfig struct {
	host   string
	port   int
	cipher string
	secret string
}

func parseKey(k string) (serverConfig, error) {
	u, err := url.Parse(k)
	if err != nil {
		return serverConfig{}, err
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return serverConfig{}, fmt.Errorf("invalid port: %v", err)
	}

	secret := u.User.String()
	if !strings.Contains(secret, ":") {
		b, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(u.User.String())
			if err != nil {
				return serverConfig{}, fmt.Errorf("invalid password in key: %v", err)
			}
		}
		secret = string(bytes.TrimSpace(b))
	}
	p := strings.Split(secret, ":")
	if len(p) != 2 {
		return serverConfig{}, fmt.Errorf("invalid password in key")
	}

	return serverConfig{
		host:   u.Hostname(),
		port:   port,
		cipher: p[0],
		secret: p[1],
	}, nil
}

func resolveHostPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return "", fmt.Errorf("resolving hostname failed: %v", err)
	}
	return net.JoinHostPort(ip.String(), port), err
}

type SocksSSClient struct {
	config   serverConfig
	listener *net.TCPListener
}

// RunSocksSSClient starts a SOCKS server which proxies connections to the specified shadowsocks server.
func RunSocksSSClient(bindAddr string, listenPort int, config serverConfig) (*SocksSSClient, error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(bindAddr), Port: listenPort})
	if err != nil {
		return nil, fmt.Errorf("listenTCP failed: %v", err)
	}
	logger.Infof("Listenting at %v", listener.Addr())

	d, err := client.NewClient(config.host, config.port, config.secret, config.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to server: %v", err)
	}

	go func() {
		for {
			clientConn, err := listener.AcceptTCP()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logger.Info("SOCKS listener closed")
				} else {
					logger.Errorf("Accepting SOCKS connection failed: %v\n", err)
				}
				break
			}
			go func() {
				defer clientConn.Close()

				tgtAddr, err := socks.Handshake(clientConn)
				if err != nil {
					logger.Errorf("SOCKS handshake failed: %v", err)
					return
				}
				addr, err := resolveHostPort(tgtAddr.String())
				if err != nil {
					logger.Errorf("Failed to resolve target address: %v", err)
					return
				}

				logger.Debugf("Opening connection for %s", addr)
				targetConn, err := d.DialTCP(nil, addr)
				if err != nil {
					logger.Errorf("Failed to dial: %v", err)
					return
				}
				defer targetConn.Close()
				_, _, err = onet.Relay(clientConn, targetConn)
				if err != nil {
					logger.Errorf("Relay failed: %v", err)
					return
				}
				logger.Debugf("Connection closed %s", addr)
			}()
		}
	}()
	return &SocksSSClient{listener: listener}, nil
}

// ListenAddr returns the listening address used by the SOCKS server
func (s *SocksSSClient) ListenAddr() net.Addr {
	return s.listener.Addr()
}

// Stop stops the SOCKS server
func (s *SocksSSClient) Stop() error {
	return s.listener.Close()
}

func main() {
	var flags struct {
		BindAddr   string
		ListenPort int
		ServerKey  string
		Verbose    bool
	}

	flag.StringVar(&flags.BindAddr, "bind", "127.0.0.1", "")
	flag.IntVar(&flags.ListenPort, "port", 1080, "")
	flag.StringVar(&flags.ServerKey, "key", "", "")
	flag.BoolVar(&flags.Verbose, "verbose", false, "Enables verbose logging output")

	flag.Parse()

	if flags.Verbose {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.INFO, "")
	}

	if flags.ServerKey == "" {
		flag.Usage()
		return
	}

	sc, err := parseKey(flags.ServerKey)
	if err != nil {
		logger.Fatalf("Invalid key: %v", err)
	}

	_, err = RunSocksSSClient(flags.BindAddr, flags.ListenPort, sc)
	if err != nil {
		logger.Fatalf("Failed running client: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
