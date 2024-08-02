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
	"sync"
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
	stopConfig  func()
	lnManager   service.ListenerManager
	natTimeout  time.Duration
	m           *outlineMetrics
	replayCache service.ReplayCache
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

	// We hot swap the config by having the old and new listeners both live at
	// the same time. This means we create listeners for the new config first,
	// and then close the old ones after.
	stopConfig, err := s.runConfig(*config)
	if err != nil {
		return err
	}
	go s.stopConfig()
	s.stopConfig = stopConfig
	return nil
}

func newCipherListFromConfig(config ServiceConfig) (service.CipherList, error) {
	type cipherKey struct {
		cipher string
		secret string
	}
	cipherList := list.New()
	existingCiphers := make(map[cipherKey]bool)
	for _, keyConfig := range config.Keys {
		key := cipherKey{keyConfig.Cipher, keyConfig.Secret}
		if _, exists := existingCiphers[key]; exists {
			logger.Debugf("encryption key already exists for ID=`%v`. Skipping.", keyConfig.ID)
			continue
		}
		cryptoKey, err := shadowsocks.NewEncryptionKey(keyConfig.Cipher, keyConfig.Secret)
		if err != nil {
			return nil, fmt.Errorf("failed to create encyption key for key %v: %w", keyConfig.ID, err)
		}
		entry := service.MakeCipherEntry(keyConfig.ID, cryptoKey, keyConfig.Secret)
		cipherList.PushBack(&entry)
		existingCiphers[key] = true
	}
	ciphers := service.NewCipherList()
	ciphers.Update(cipherList)

	return ciphers, nil
}

func (s *SSServer) NewShadowsocksStreamHandler(ciphers service.CipherList) service.StreamHandler {
	authFunc := service.NewShadowsocksStreamAuthenticator(ciphers, &s.replayCache, s.m)
	// TODO: Register initial data metrics at zero.
	return service.NewStreamHandler(authFunc, s.m, tcpReadTimeout)
}

func (s *SSServer) NewShadowsocksPacketHandler(ciphers service.CipherList) service.PacketHandler {
	return service.NewPacketHandler(s.natTimeout, ciphers, s.m)
}

func (s *SSServer) NewShadowsocksStreamHandlerFromConfig(config ServiceConfig) (service.StreamHandler, error) {
	ciphers, err := newCipherListFromConfig(config)
	if err != nil {
		return nil, err
	}
	return s.NewShadowsocksStreamHandler(ciphers), nil
}

func (s *SSServer) NewShadowsocksPacketHandlerFromConfig(config ServiceConfig) (service.PacketHandler, error) {
	ciphers, err := newCipherListFromConfig(config)
	if err != nil {
		return nil, err
	}
	return s.NewShadowsocksPacketHandler(ciphers), nil
}

type listenerSet struct {
	manager            service.ListenerManager
	listenerCloseFuncs map[string]func() error
	listenersMu        sync.Mutex
}

// ListenStream announces on a given TCP network address. Trying to listen on
// the same address twice will result in an error.
func (ls *listenerSet) ListenStream(addr string, proxy bool) (service.StreamListener, error) {
	ls.listenersMu.Lock()
	defer ls.listenersMu.Unlock()

	lnKey := "tcp/" + addr
	if _, exists := ls.listenerCloseFuncs[lnKey]; exists {
		return nil, fmt.Errorf("listener %s already exists", lnKey)
	}
	ln, err := ls.manager.ListenStream("tcp", addr, proxy)
	if err != nil {
		return nil, err
	}
	ls.listenerCloseFuncs[lnKey] = ln.Close
	return ln, nil
}

// ListenPacket announces on a given UDP network address. Trying to listen on
// the same address twice will result in an error.
func (ls *listenerSet) ListenPacket(addr string, proxy bool) (net.PacketConn, error) {
	ls.listenersMu.Lock()
	defer ls.listenersMu.Unlock()

	lnKey := "udp/" + addr
	if _, exists := ls.listenerCloseFuncs[lnKey]; exists {
		return nil, fmt.Errorf("listener %s already exists", lnKey)
	}
	ln, err := ls.manager.ListenPacket("udp", addr, proxy)
	if err != nil {
		return nil, err
	}
	ls.listenerCloseFuncs[lnKey] = ln.Close
	return ln, nil
}

// Close closes all the listeners in the set, after which the set can't be used again.
func (ls *listenerSet) Close() error {
	for addr, listenerCloseFunc := range ls.listenerCloseFuncs {
		if err := listenerCloseFunc(); err != nil {
			return fmt.Errorf("listener on address %s failed to stop: %w", addr, err)
		}
	}
	ls.listenersMu.Lock()
	defer ls.listenersMu.Unlock()
	ls.listenerCloseFuncs = nil
	return nil
}

// Len returns the number of listeners in the set.
func (ls *listenerSet) Len() int {
	return len(ls.listenerCloseFuncs)
}

func (s *SSServer) runConfig(config Config) (func(), error) {
	startErrCh := make(chan error)
	stopCh := make(chan struct{})

	go func() {
		lnSet := &listenerSet{
			manager:            s.lnManager,
			listenerCloseFuncs: make(map[string]func() error),
		}
		defer lnSet.Close() // This closes all the listeners in the set.

		startErrCh <- func() error {
			totalCipherCount := len(config.Keys)
			portCiphers := make(map[int]*list.List) // Values are *List of *CipherEntry.
			for _, keyConfig := range config.Keys {
				cipherList, ok := portCiphers[keyConfig.Port]
				if !ok {
					cipherList = list.New()
					portCiphers[keyConfig.Port] = cipherList
				}
				cryptoKey, err := shadowsocks.NewEncryptionKey(keyConfig.Cipher, keyConfig.Secret)
				if err != nil {
					return fmt.Errorf("failed to create encyption key for key %v: %w", keyConfig.ID, err)
				}
				entry := service.MakeCipherEntry(keyConfig.ID, cryptoKey, keyConfig.Secret)
				cipherList.PushBack(&entry)
			}
			for portNum, cipherList := range portCiphers {
				addr := net.JoinHostPort("::", strconv.Itoa(portNum))

				ciphers := service.NewCipherList()
				ciphers.Update(cipherList)

				sh := s.NewShadowsocksStreamHandler(ciphers)
				ln, err := lnSet.ListenStream(addr, false)
				if err != nil {
					return err
				}
				logger.Infof("Shadowsocks service listening on tcp/%s", ln.Addr().String())
				go service.StreamServe(ln.AcceptStream, sh.Handle)

				pc, err := lnSet.ListenPacket(addr, false)
				if err != nil {
					return err
				}
				logger.Infof("Shadowsocks service listening on udp/%s", pc.LocalAddr().String())
				ph := s.NewShadowsocksPacketHandler(ciphers)
				go ph.Handle(pc)
			}

			for _, serviceConfig := range config.Services {
				var (
					sh service.StreamHandler
					ph service.PacketHandler
				)
				for _, lnConfig := range serviceConfig.Listeners {
					err := s.startListenerFromConfig(lnSet, serviceConfig, lnConfig, false, sh, ph)
					if err != nil {
						return err
					}
				}
				totalCipherCount += len(serviceConfig.Keys)
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
		// TODO(sbruens): Actually wait for all handlers to be stopped, e.g. by
		// using a https://pkg.go.dev/sync#WaitGroup.
		stopCh <- struct{}{}
	}, nil
}

func (s *SSServer) startListenerFromConfig(lnSet *listenerSet, serviceConfig ServiceConfig, lnConfig ListenerConfig, proxy bool, sh service.StreamHandler, ph service.PacketHandler) error {
	lnLogFunc := func(key string) {
		var serviceToLog string
		if proxy {
			serviceToLog = "Proxy"
		} else {
			serviceToLog = "Shadowsocks"
		}
		logger.Infof("%s service listening on %s", serviceToLog, key)
	}
	switch lnConfig.Type {
	case listenerTypeTCP:
		ln, err := lnSet.ListenStream(lnConfig.Address, proxy)
		if err != nil {
			return err
		}
		lnLogFunc("tcp/" + ln.Addr().String())
		if sh == nil {
			sh, err = s.NewShadowsocksStreamHandlerFromConfig(serviceConfig)
			if err != nil {
				return err
			}
		}
		go service.StreamServe(ln.AcceptStream, sh.Handle)

	case listenerTypeUDP:
		pc, err := lnSet.ListenPacket(lnConfig.Address, proxy)
		if err != nil {
			return err
		}
		lnLogFunc("udp/" + pc.LocalAddr().String())
		if ph == nil {
			ph, err = s.NewShadowsocksPacketHandlerFromConfig(serviceConfig)
			if err != nil {
				return err
			}
		}
		go ph.Handle(pc)

	case listenerTypeProxy:
		for _, proxyLnConfig := range lnConfig.Listeners {
			err := s.startListenerFromConfig(lnSet, serviceConfig, proxyLnConfig, true, sh, ph)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Stop stops serving the current config.
func (s *SSServer) Stop() {
	go s.stopConfig()
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
