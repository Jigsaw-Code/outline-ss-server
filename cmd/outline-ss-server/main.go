// Copyright 2018 Jigsaw Operations LLC
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
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/op/go-logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
)

var logger *logging.Logger

// Set by goreleaser default ldflags. See https://goreleaser.com/customization/build/
var version = "dev"

// 59 seconds is most common timeout for servers that do not respond to invalid requests
const tcpReadTimeout time.Duration = 59 * time.Second

// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
const defaultNatTimeout time.Duration = 5 * time.Minute

func init() {
	var prefix = "%{level:.1s}%{time:2006-01-02T15:04:05.000Z07:00} %{pid} %{shortfile}]"
	if term.IsTerminal(int(os.Stderr.Fd())) {
		// Add color only if the output is the terminal
		prefix = strings.Join([]string{"%{color}", prefix, "%{color:reset}"}, "")
	}
	logging.SetFormatter(logging.MustStringFormatter(strings.Join([]string{prefix, " %{message}"}, "")))
	logging.SetBackend(logging.NewLogBackend(os.Stderr, "", 0))
	logger = logging.MustGetLogger("")
}

type SSServer struct {
	stopConfig  func()
	lnManager   service.ListenerManager
	natTimeout  time.Duration
	m           *outlineMetrics
	replayCache service.ReplayCache
}

func (s *SSServer) loadConfig(filename string) error {
	config, err := readConfig(filename)
	if err != nil {
		return fmt.Errorf("failed to load config (%v): %w", filename, err)
	}
	// We hot swap the config by having the old and new listeners both live at
	// the same time. This means we create listeners for the new config first,
	// and then close the old ones after.
	stopConfig, err := s.runConfig(*config)
	if err != nil {
		return err
	}
	s.stopConfig()
	s.stopConfig = stopConfig
	return nil
}

func (s *SSServer) NewShadowsocksStreamHandler(ciphers service.CipherList) service.StreamHandler {
	authFunc := service.NewShadowsocksStreamAuthenticator(ciphers, &s.replayCache, s.m)
	// TODO: Register initial data metrics at zero.
	return service.NewStreamHandler(authFunc, s.m, tcpReadTimeout)
}

func (s *SSServer) NewShadowsocksPacketHandler(ciphers service.CipherList) service.PacketHandler {
	return service.NewPacketHandler(s.natTimeout, ciphers, s.m)
}

func (s *SSServer) runConfig(config Config) (func(), error) {
	startErrCh := make(chan error)
	stopCh := make(chan struct{})

	go func() {
		startErrCh <- func() error {
			lnSet := s.lnManager.NewListenerSet()
			defer lnSet.Close()

			var totalCipherCount int

			portCiphers := make(map[int]service.CipherList)
			for _, keyConfig := range config.Keys {
				ciphers, ok := portCiphers[keyConfig.Port]
				if !ok {
					ciphers = service.NewCipherList()
					portCiphers[keyConfig.Port] = ciphers
				}
				cryptoKey, err := shadowsocks.NewEncryptionKey(keyConfig.Cipher, keyConfig.Secret)
				if err != nil {
					return fmt.Errorf("failed to create encyption key for key %v: %w", keyConfig.ID, err)
				}
				entry := service.MakeCipherEntry(keyConfig.ID, cryptoKey, keyConfig.Secret)
				ciphers.PushBack(&entry)
			}
			for portNum, ciphers := range portCiphers {
				addr := net.JoinHostPort("::", strconv.Itoa(portNum))

				sh := s.NewShadowsocksStreamHandler(ciphers)
				ln, err := lnSet.Listen("tcp", addr)
				if err != nil {
					return err
				}
				logger.Infof("Shadowsocks TCP service listening on %v", ln.Addr().String())
				accept := func() (transport.StreamConn, error) {
					c, err := ln.Accept()
					if err == nil {
						return c.(transport.StreamConn), err
					}
					return nil, err
				}
				go service.StreamServe(accept, sh.Handle)

				pc, err := lnSet.ListenPacket("udp", addr)
				if err != nil {
					return err
				}
				logger.Infof("Shadowsocks UDP service listening on %v", pc.LocalAddr().String())
				ph := s.NewShadowsocksPacketHandler(ciphers)
				go ph.Handle(pc)

				totalCipherCount += ciphers.Len()
			}
			logger.Infof("Loaded %d access keys over %d listeners", totalCipherCount, lnSet.Len())
			s.m.SetNumAccessKeys(totalCipherCount, lnSet.Len())
			return nil
		}()

		<-stopCh
	}()

	err := <-startErrCh
	if err != nil {
		return nil, err
	}
	return func() {
		logger.Infof("Stopping running config.")
		stopCh <- struct{}{}
	}, nil
}

// Stop serving the current config.
func (s *SSServer) Stop() {
	s.stopConfig()
	logger.Info("Stopped all listeners for running config")
}

// RunSSServer starts a shadowsocks server running, and returns the server or an error.
func RunSSServer(filename string, natTimeout time.Duration, sm *outlineMetrics, replayHistory int) (*SSServer, error) {
	server := &SSServer{
		stopConfig:  func() {},
		lnManager:   service.NewListenerManager(),
		natTimeout:  natTimeout,
		m:           sm,
		replayCache: service.NewReplayCache(replayHistory),
	}
	err := server.loadConfig(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to configure server: %w", err)
	}
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			logger.Infof("SIGHUP received. Loading config from %v", filename)
			if err := server.loadConfig(filename); err != nil {
				logger.Errorf("Failed to update server: %v. Server state may be invalid. Fix the error and try the update again", err)
			}
		}
	}()
	return server, nil
}

type Config struct {
	Keys []struct {
		ID     string
		Port   int
		Cipher string
		Secret string
	}
}

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

func main() {
	var flags struct {
		ConfigFile    string
		MetricsAddr   string
		IPCountryDB   string
		IPASNDB       string
		natTimeout    time.Duration
		replayHistory int
		Verbose       bool
		Version       bool
	}
	flag.StringVar(&flags.ConfigFile, "config", "", "Configuration filename")
	flag.StringVar(&flags.MetricsAddr, "metrics", "", "Address for the Prometheus metrics")
	flag.StringVar(&flags.IPCountryDB, "ip_country_db", "", "Path to the ip-to-country mmdb file")
	flag.StringVar(&flags.IPASNDB, "ip_asn_db", "", "Path to the ip-to-ASN mmdb file")
	flag.DurationVar(&flags.natTimeout, "udptimeout", defaultNatTimeout, "UDP tunnel timeout")
	flag.IntVar(&flags.replayHistory, "replay_history", 0, "Replay buffer size (# of handshakes)")
	flag.BoolVar(&flags.Verbose, "verbose", false, "Enables verbose logging output")
	flag.BoolVar(&flags.Version, "version", false, "The version of the server")

	flag.Parse()

	if flags.Verbose {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.INFO, "")
	}

	if flags.Version {
		fmt.Println(version)
		return
	}

	if flags.ConfigFile == "" {
		flag.Usage()
		return
	}

	if flags.MetricsAddr != "" {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			logger.Fatalf("Failed to run metrics server: %v. Aborting.", http.ListenAndServe(flags.MetricsAddr, nil))
		}()
		logger.Infof("Prometheus metrics available at http://%v/metrics", flags.MetricsAddr)
	}

	var err error
	if flags.IPCountryDB != "" {
		logger.Infof("Using IP-Country database at %v", flags.IPCountryDB)
	}
	if flags.IPASNDB != "" {
		logger.Infof("Using IP-ASN database at %v", flags.IPASNDB)
	}
	ip2info, err := ipinfo.NewMMDBIPInfoMap(flags.IPCountryDB, flags.IPASNDB)
	if err != nil {
		logger.Fatalf("Could create IP info map: %v. Aborting", err)
	}
	defer ip2info.Close()

	m := newPrometheusOutlineMetrics(ip2info, prometheus.DefaultRegisterer)
	m.SetBuildInfo(version)
	_, err = RunSSServer(flags.ConfigFile, flags.natTimeout, m, flags.replayHistory)
	if err != nil {
		logger.Fatalf("Server failed to start: %v. Aborting", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
