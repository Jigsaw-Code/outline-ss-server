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
	"bufio"
	"container/list"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"

	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/op/go-logging"
	proxyproto "github.com/pires/go-proxyproto"
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

type ListenerConfig = Listener

type ssListener struct {
	io.Closer
	cipherList service.CipherList
}

type SSServer struct {
	natTimeout  time.Duration
	m           *outlineMetrics
	replayCache service.ReplayCache
	listeners   map[ListenerConfig]*ssListener
}

func (s *SSServer) serve(lnType ListenerType, listener io.Closer, cipherList service.CipherList) error {
	switch ln := listener.(type) {
	case net.Listener:
		authFunc := service.NewShadowsocksStreamAuthenticator(cipherList, &s.replayCache, s.m)
		// TODO: Register initial data metrics at zero.
		tcpHandler := service.NewTCPHandler(authFunc, s.m, tcpReadTimeout)
		accept := func() (service.ClientStreamConn, error) {
			conn, err := ln.Accept()
			if err != nil {
				return service.ClientStreamConn{}, err
			}
			c := conn.(*net.TCPConn)
			c.SetKeepAlive(true)
			switch lnType {
			case listenerTypeDirect:
				return service.ClientStreamConn{StreamConn: c, ClientAddress: c.RemoteAddr()}, err
			case listenerTypeProxy:
				r := bufio.NewReader(c)
				h, err := proxyproto.Read(r)
				if err == proxyproto.ErrNoProxyProtocol {
					logger.Warningf("Received connection from %v without proxy header.", c.RemoteAddr())
					return service.ClientStreamConn{StreamConn: c, ClientAddress: c.RemoteAddr()}, nil
				}
				if err != nil {
					return service.ClientStreamConn{}, fmt.Errorf("error parsing proxy header: %v", err)
				}
				return service.ClientStreamConn{StreamConn: c, ClientAddress: h.SourceAddr}, nil
			default:
				return service.ClientStreamConn{}, fmt.Errorf("unknown listener config: %v", lnType)
			}
		}
		go service.StreamServe(accept, tcpHandler.Handle)
	case net.PacketConn:
		packetHandler := service.NewPacketHandler(s.natTimeout, cipherList, s.m)
		go packetHandler.Handle(ln)
	default:
		return fmt.Errorf("unknown listener type: %v", ln)
	}
	return nil
}

func (s *SSServer) start(lnConfig ListenerConfig, cipherList service.CipherList) (io.Closer, error) {
	listener, err := newListener(lnConfig.Address)
	if err != nil {
		return nil, fmt.Errorf("%s service failed to start on address %v: %w", lnConfig.Type, lnConfig.Address, err)
	}
	logger.Infof("%s service listening on %v", lnConfig.Type, lnConfig.Address)

	err = s.serve(lnConfig.Type, listener, cipherList)
	if err != nil {
		return nil, fmt.Errorf("failed to serve %s on listener %v: %w", lnConfig.Type, listener, err)
	}

	return listener, nil
}

func (s *SSServer) remove(lnConfig ListenerConfig) error {
	listener, ok := s.listeners[lnConfig]
	if !ok {
		return fmt.Errorf("address %v doesn't exist", lnConfig.Address)
	}
	err := listener.Close()
	delete(s.listeners, lnConfig)
	if err != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks service on address %v failed to stop: %w", lnConfig.Address, err)
	}
	logger.Infof("Shadowsocks service on address %v stopped", lnConfig.Address)
	return nil
}

func (s *SSServer) loadConfig(filename string) error {
	config, err := readConfig(filename)
	if err != nil {
		return fmt.Errorf("failed to load config (%v): %w", filename, err)
	}

	uniqueCiphers := 0
	listenerChanges := make(map[ListenerConfig]int)
	listenerCiphers := make(map[ListenerConfig]*list.List) // Values are *List of *CipherEntry.

	for _, legacyKeyConfig := range config.Keys {
		cryptoKey, err := shadowsocks.NewEncryptionKey(legacyKeyConfig.Cipher, legacyKeyConfig.Secret)
		if err != nil {
			return fmt.Errorf("failed to create encyption key for key %v: %w", legacyKeyConfig.ID, err)
		}
		entry := service.MakeCipherEntry(legacyKeyConfig.ID, cryptoKey, legacyKeyConfig.Secret)
		for _, ln := range []string{"tcp", "udp"} {
			lnConfig := ListenerConfig{Type: listenerTypeDirect, Address: fmt.Sprintf("%s://[::]:%d", ln, legacyKeyConfig.Port)}
			listenerChanges[lnConfig] = 1
			ciphers, ok := listenerCiphers[lnConfig]
			if !ok {
				ciphers = list.New()
				listenerCiphers[lnConfig] = ciphers
			}
			ciphers.PushBack(&entry)
		}
		uniqueCiphers += 1
	}

	for _, serviceConfig := range config.Services {
		if serviceConfig.Listeners == nil || serviceConfig.Keys == nil {
			return fmt.Errorf("must specify at least 1 listener and 1 key per service")
		}

		ciphers := list.New()
		type cipherKey struct {
			cipher string
			secret string
		}
		existingCiphers := make(map[cipherKey]bool)
		for _, keyConfig := range serviceConfig.Keys {
			key := cipherKey{keyConfig.Cipher, keyConfig.Secret}
			_, ok := existingCiphers[key]
			if ok {
				logger.Debugf("encryption key already exists for ID=`%v`. Skipping.", keyConfig.ID)
				continue
			}
			cryptoKey, err := shadowsocks.NewEncryptionKey(keyConfig.Cipher, keyConfig.Secret)
			if err != nil {
				return fmt.Errorf("failed to create encyption key for key %v: %w", keyConfig.ID, err)
			}
			entry := service.MakeCipherEntry(keyConfig.ID, cryptoKey, keyConfig.Secret)
			ciphers.PushBack(&entry)
			existingCiphers[key] = true
		}
		uniqueCiphers += ciphers.Len()

		for _, lnConfig := range serviceConfig.Listeners {
			listenerChanges[lnConfig] = 1
			listenerCiphers[lnConfig] = ciphers
		}
	}
	for lnConfig := range s.listeners {
		listenerChanges[lnConfig] = listenerChanges[lnConfig] - 1
	}
	for lnConfig, count := range listenerChanges {
		if count == -1 {
			if err := s.remove(lnConfig); err != nil {
				return fmt.Errorf("failed to remove %s listener on address %v: %w", lnConfig.Type, lnConfig.Address, err)
			}
		} else if count == +1 {
			cipherList := service.NewCipherList()
			listener, err := s.start(lnConfig, cipherList)
			if err != nil {
				return err
			}
			s.listeners[lnConfig] = &ssListener{Closer: listener, cipherList: cipherList}
		}
	}
	for lnConfig, ciphers := range listenerCiphers {
		listener, ok := s.listeners[lnConfig]
		if !ok {
			return fmt.Errorf("unable to find listener for address: %v", lnConfig.Address)
		}
		listener.cipherList.Update(ciphers)
	}
	logger.Infof("Loaded %v access keys over %v listeners", uniqueCiphers, len(s.listeners))
	s.m.SetNumAccessKeys(uniqueCiphers, len(s.listeners))
	return nil
}

// Stop serving on all ports.
func (s *SSServer) Stop() error {
	for lnConfig := range s.listeners {
		if err := s.remove(lnConfig); err != nil {
			return err
		}
	}
	return nil
}

// RunSSServer starts a shadowsocks server running, and returns the server or an error.
func RunSSServer(filename string, natTimeout time.Duration, sm *outlineMetrics, replayHistory int) (*SSServer, error) {
	server := &SSServer{
		natTimeout:  natTimeout,
		m:           sm,
		replayCache: service.NewReplayCache(replayHistory),
		listeners:   make(map[ListenerConfig]*ssListener),
	}
	err := server.loadConfig(filename)
	if err != nil {
		return nil, fmt.Errorf("failed configure server: %w", err)
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
