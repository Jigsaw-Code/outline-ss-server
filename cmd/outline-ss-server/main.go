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
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	outline_prometheus "github.com/Jigsaw-Code/outline-ss-server/prometheus"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/lmittmann/tint"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/term"
)

var logLevel = new(slog.LevelVar) // Info by default
var logHandler slog.Handler

// Set by goreleaser default ldflags. See https://goreleaser.com/customization/build/
var version = "dev"

// 59 seconds is most common timeout for servers that do not respond to invalid requests
const tcpReadTimeout time.Duration = 59 * time.Second

// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
const defaultNatTimeout time.Duration = 5 * time.Minute

func init() {
	logHandler = tint.NewHandler(
		os.Stderr,
		&tint.Options{NoColor: !term.IsTerminal(int(os.Stderr.Fd())), Level: logLevel},
	)
}

type OutlineServer struct {
	stopConfig     func() error
	lnManager      service.ListenerManager
	natTimeout     time.Duration
	serverMetrics  *serverMetrics
	serviceMetrics service.ServiceMetrics
	replayCache    service.ReplayCache
}

func (s *OutlineServer) loadConfig(filename string) error {
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
	if err := s.Stop(); err != nil {
		slog.Warn("Failed to stop old config.", "err", err)
	}
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
			slog.Debug("Encryption key already exists. Skipping.", "id", keyConfig.ID)
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

type listenerSet struct {
	manager            service.ListenerManager
	listenerCloseFuncs map[string]func() error
	listenersMu        sync.Mutex
}

// ListenStream announces on a given network address. Trying to listen for stream connections
// on the same address twice will result in an error.
func (ls *listenerSet) ListenStream(addr string) (service.StreamListener, error) {
	ls.listenersMu.Lock()
	defer ls.listenersMu.Unlock()

	lnKey := "stream/" + addr
	if _, exists := ls.listenerCloseFuncs[lnKey]; exists {
		return nil, fmt.Errorf("stream listener for %s already exists", addr)
	}
	ln, err := ls.manager.ListenStream(addr)
	if err != nil {
		return nil, err
	}
	ls.listenerCloseFuncs[lnKey] = ln.Close
	return ln, nil
}

// ListenPacket announces on a given network address. Trying to listen for packet connections
// on the same address twice will result in an error.
func (ls *listenerSet) ListenPacket(addr string) (net.PacketConn, error) {
	ls.listenersMu.Lock()
	defer ls.listenersMu.Unlock()

	lnKey := "packet/" + addr
	if _, exists := ls.listenerCloseFuncs[lnKey]; exists {
		return nil, fmt.Errorf("packet listener for %s already exists", addr)
	}
	ln, err := ls.manager.ListenPacket(addr)
	if err != nil {
		return nil, err
	}
	ls.listenerCloseFuncs[lnKey] = ln.Close
	return ln, nil
}

// Close closes all the listeners in the set, after which the set can't be used again.
func (ls *listenerSet) Close() error {
	ls.listenersMu.Lock()
	defer ls.listenersMu.Unlock()

	for addr, listenerCloseFunc := range ls.listenerCloseFuncs {
		if err := listenerCloseFunc(); err != nil {
			return fmt.Errorf("listener on address %s failed to stop: %w", addr, err)
		}
	}
	ls.listenerCloseFuncs = nil
	return nil
}

// Len returns the number of listeners in the set.
func (ls *listenerSet) Len() int {
	return len(ls.listenerCloseFuncs)
}

func (s *OutlineServer) runConfig(config Config) (func() error, error) {
	startErrCh := make(chan error)
	stopErrCh := make(chan error)
	stopCh := make(chan struct{})

	go func() {
		lnSet := &listenerSet{
			manager:            s.lnManager,
			listenerCloseFuncs: make(map[string]func() error),
		}
		defer func() {
			stopErrCh <- lnSet.Close()
		}()

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
				// NOTE: We explicitly construct the address string with only the port
				// number. This will result in an address that listens on all available
				// network interfaces (both IPv4 and IPv6).
				addr := fmt.Sprintf(":%d", portNum)

				ciphers := service.NewCipherList()
				ciphers.Update(cipherList)

				ssService, err := service.NewShadowsocksService(
					service.WithCiphers(ciphers),
					service.WithNatTimeout(s.natTimeout),
					service.WithMetrics(s.serviceMetrics),
					service.WithReplayCache(&s.replayCache),
					service.WithLogger(slog.Default()),
				)
				ln, err := lnSet.ListenStream(addr)
				if err != nil {
					return err
				}
				slog.Info("TCP service started.", "address", ln.Addr().String())
				go service.StreamServe(ln.AcceptStream, ssService.HandleStream)

				pc, err := lnSet.ListenPacket(addr)
				if err != nil {
					return err
				}
				slog.Info("UDP service started.", "address", pc.LocalAddr().String())
				go ssService.HandlePacket(pc)
			}

			for _, serviceConfig := range config.Services {
				ciphers, err := newCipherListFromConfig(serviceConfig)
				if err != nil {
					return fmt.Errorf("failed to create cipher list from config: %v", err)
				}
				ssService, err := service.NewShadowsocksService(
					service.WithCiphers(ciphers),
					service.WithNatTimeout(s.natTimeout),
					service.WithMetrics(s.serviceMetrics),
					service.WithReplayCache(&s.replayCache),
					service.WithLogger(slog.Default()),
				)
				if err != nil {
					return err
				}
				for _, lnConfig := range serviceConfig.Listeners {
					switch lnConfig.Type {
					case listenerTypeTCP:
						ln, err := lnSet.ListenStream(lnConfig.Address)
						if err != nil {
							return err
						}
						slog.Info("TCP service started.", "address", ln.Addr().String())
						go service.StreamServe(ln.AcceptStream, ssService.HandleStream)
					case listenerTypeUDP:
						pc, err := lnSet.ListenPacket(lnConfig.Address)
						if err != nil {
							return err
						}
						slog.Info("UDP service started.", "address", pc.LocalAddr().String())
						go ssService.HandlePacket(pc)
					}
				}
				totalCipherCount += len(serviceConfig.Keys)
			}

			slog.Info("Loaded config.", "access_keys", totalCipherCount, "listeners", lnSet.Len())
			s.serverMetrics.SetNumAccessKeys(totalCipherCount, lnSet.Len())
			return nil
		}()

		<-stopCh
	}()

	err := <-startErrCh
	if err != nil {
		return nil, err
	}
	return func() error {
		slog.Info("Stopping running config.")
		// TODO(sbruens): Actually wait for all handlers to be stopped, e.g. by
		// using a https://pkg.go.dev/sync#WaitGroup.
		stopCh <- struct{}{}
		stopErr := <-stopErrCh
		return stopErr
	}, nil
}

// Stop stops serving the current config.
func (s *OutlineServer) Stop() error {
	stopFunc := s.stopConfig
	if stopFunc == nil {
		return nil
	}
	if err := stopFunc(); err != nil {
		slog.Error("Error stopping config.", "err", err)
		return err
	}
	slog.Info("Stopped all listeners for running config.")
	return nil
}

// RunOutlineServer starts an Outline server running, and returns the server or an error.
func RunOutlineServer(filename string, natTimeout time.Duration, serverMetrics *serverMetrics, serviceMetrics service.ServiceMetrics, replayHistory int) (*OutlineServer, error) {
	server := &OutlineServer{
		lnManager:      service.NewListenerManager(),
		natTimeout:     natTimeout,
		serverMetrics:  serverMetrics,
		serviceMetrics: serviceMetrics,
		replayCache:    service.NewReplayCache(replayHistory),
	}
	err := server.loadConfig(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to configure server: %w", err)
	}
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			slog.Info("SIGHUP received. Loading config.", "config", filename)
			if err := server.loadConfig(filename); err != nil {
				slog.Error("Failed to update server. Server state may be invalid. Fix the error and try the update again", "err", err)
			}
		}
	}()
	return server, nil
}

func main() {
	slog.SetDefault(slog.New(logHandler))

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
		logLevel.Set(slog.LevelDebug)
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
			slog.Error("Failed to run metrics server. Aborting.", "err", http.ListenAndServe(flags.MetricsAddr, nil))
		}()
		slog.Info(fmt.Sprintf("Prometheus metrics available at http://%v/metrics.", flags.MetricsAddr))
	}

	var err error
	if flags.IPCountryDB != "" {
		slog.Info("Using IP-Country database.", "db", flags.IPCountryDB)
	}
	if flags.IPASNDB != "" {
		slog.Info("Using IP-ASN database.", "db", flags.IPASNDB)
	}
	ip2info, err := ipinfo.NewMMDBIPInfoMap(flags.IPCountryDB, flags.IPASNDB)
	if err != nil {
		slog.Error("Failed to create IP info map. Aborting.", "err", err)
	}
	defer ip2info.Close()

	serverMetrics := newPrometheusServerMetrics()
	serverMetrics.SetVersion(version)
	serviceMetrics, err := outline_prometheus.NewServiceMetrics(ip2info)
	if err != nil {
		slog.Error("Failed to create Outline Prometheus service metrics. Aborting.", "err", err)
	}
	r := prometheus.WrapRegistererWithPrefix("shadowsocks_", prometheus.DefaultRegisterer)
	r.MustRegister(serverMetrics, serviceMetrics)

	_, err = RunOutlineServer(flags.ConfigFile, flags.natTimeout, serverMetrics, serviceMetrics, flags.replayHistory)
	if err != nil {
		slog.Error("Server failed to start. Aborting.", "err", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
