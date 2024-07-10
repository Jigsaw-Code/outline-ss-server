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
	"container/list"
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

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/op/go-logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/term"
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
	lnManager   ListenerManager
	natTimeout  time.Duration
	m           *outlineMetrics
	replayCache service.ReplayCache
	services    []*Service
}

func (s *SSServer) loadConfig(filename string) error {
	configData, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", filename, err)
	}
	config, err := readConfig(configData)
	if err != nil {
		return fmt.Errorf("failed to load config (%v): %w", filename, err)
	}
	if err := config.Validate(); err != nil {
		return fmt.Errorf("failed to validate config: %w", err)
	}

	// We hot swap the services by having them both live at the same time. This
	// means we create services for the new config first, and then take down the
	// services from the old config.
	newServices := make([]*Service, 0)

	legacyPortService := make(map[int]*Service) // Values are *List of *CipherEntry.
	for _, legacyKeyServiceConfig := range config.Keys {
		legacyService, ok := legacyPortService[legacyKeyServiceConfig.Port]
		if !ok {
			legacyService = &Service{
				lnManager:   s.lnManager,
				tcpTimeout:  tcpReadTimeout,
				natTimeout:  s.natTimeout,
				m:           s.m,
				replayCache: &s.replayCache,
				ciphers:     list.New(),
			}
			for _, network := range []string{"tcp", "udp"} {
				addr := net.JoinHostPort("::", strconv.Itoa(legacyKeyServiceConfig.Port))
				if err := legacyService.AddListener(network, addr); err != nil {
					return err
				}
			}
			newServices = append(newServices, legacyService)
			legacyPortService[legacyKeyServiceConfig.Port] = legacyService
		}
		cryptoKey, err := shadowsocks.NewEncryptionKey(legacyKeyServiceConfig.Cipher, legacyKeyServiceConfig.Secret)
		if err != nil {
			return fmt.Errorf("failed to create encyption key for key %v: %w", legacyKeyServiceConfig.ID, err)
		}
		entry := service.MakeCipherEntry(legacyKeyServiceConfig.ID, cryptoKey, legacyKeyServiceConfig.Secret)
		legacyService.AddCipher(&entry)
	}

	for _, serviceConfig := range config.Services {
		service, err := NewService(serviceConfig, s.lnManager, tcpReadTimeout, s.natTimeout, s.m, &s.replayCache)
		if err != nil {
			return fmt.Errorf("Failed to create new service: %v", err)
		}
		newServices = append(newServices, service)
	}
	logger.Infof("Loaded %d new services", len(newServices))

	// Take down the old services now that the new ones are created and serving.
	if err := s.Stop(); err != nil {
		logger.Errorf("Failed to stop old services: %w", err)
	}
	s.services = newServices

	var (
		listenerCount int
		cipherCount   int
	)
	for _, service := range s.services {
		listenerCount += service.NumListeners()
		cipherCount += service.NumCiphers()
	}
	logger.Infof("%d services active: %d access keys over %d listeners", len(s.services), cipherCount, listenerCount)
	s.m.SetNumAccessKeys(cipherCount, listenerCount)
	return nil
}

// Stop serving on all existing services.
func (s *SSServer) Stop() error {
	if len(s.services) == 0 {
		return nil
	}
	for _, service := range s.services {
		if err := service.Stop(); err != nil {
			return err
		}
	}
	logger.Infof("Stopped %d old services", len(s.services))
	s.services = nil
	return nil
}

// RunSSServer starts a shadowsocks server running, and returns the server or an error.
func RunSSServer(filename string, natTimeout time.Duration, sm *outlineMetrics, replayHistory int) (*SSServer, error) {
	server := &SSServer{
		lnManager:   NewListenerManager(),
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
