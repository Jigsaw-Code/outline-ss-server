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
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/lmittmann/tint"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
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

type ssPort struct {
	tcpListener *net.TCPListener
	packetConn  net.PacketConn
	cipherList  service.CipherList
}

type SSServer struct {
	natTimeout  time.Duration
	m           *outlineMetricsCollector
	replayCache service.ReplayCache
	ports       map[int]*ssPort
}

func (s *SSServer) startPort(portNum int) error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: portNum})
	if err != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks TCP service failed to start on port %v: %w", portNum, err)
	}
	slog.Info("Shadowsocks TCP service started.", "address", listener.Addr().String())
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: portNum})
	if err != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks UDP service failed to start on port %v: %w", portNum, err)
	}
	slog.Info("Shadowsocks UDP service started.", "address", packetConn.LocalAddr().String())
	port := &ssPort{tcpListener: listener, packetConn: packetConn, cipherList: service.NewCipherList()}
	authFunc := service.NewShadowsocksStreamAuthenticator(port.cipherList, &s.replayCache, s.m)
	// TODO: Register initial data metrics at zero.
	tcpHandler := service.NewTCPHandler(authFunc, s.m, tcpReadTimeout)
	packetHandler := service.NewPacketHandler(s.natTimeout, port.cipherList, s.m)
	s.ports[portNum] = port
	go service.StreamServe(service.WrapStreamListener(listener.AcceptTCP), tcpHandler.Handle)
	go packetHandler.Handle(port.packetConn)
	return nil
}

func (s *SSServer) removePort(portNum int) error {
	port, ok := s.ports[portNum]
	if !ok {
		return fmt.Errorf("port %v doesn't exist", portNum)
	}
	tcpErr := port.tcpListener.Close()
	udpErr := port.packetConn.Close()
	delete(s.ports, portNum)
	if tcpErr != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks TCP service on port %v failed to stop: %w", portNum, tcpErr)
	}
	slog.Info("Shadowsocks TCP service stopped.", "port", portNum)
	if udpErr != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks UDP service on port %v failed to stop: %w", portNum, udpErr)
	}
	slog.Info("Shadowsocks UDP service stopped.", "port", portNum)
	return nil
}

func (s *SSServer) loadConfig(filename string) error {
	config, err := readConfig(filename)
	if err != nil {
		return fmt.Errorf("failed to load config (%v): %w", filename, err)
	}

	portChanges := make(map[int]int)
	portCiphers := make(map[int]*list.List) // Values are *List of *CipherEntry.
	for _, keyConfig := range config.Keys {
		portChanges[keyConfig.Port] = 1
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
	for port := range s.ports {
		portChanges[port] = portChanges[port] - 1
	}
	for portNum, count := range portChanges {
		if count == -1 {
			if err := s.removePort(portNum); err != nil {
				return fmt.Errorf("failed to remove port %v: %w", portNum, err)
			}
		} else if count == +1 {
			if err := s.startPort(portNum); err != nil {
				return err
			}
		}
	}
	for portNum, cipherList := range portCiphers {
		s.ports[portNum].cipherList.Update(cipherList)
	}
	slog.Info("Loaded config.", "access keys", len(config.Keys), "ports", len(s.ports))
	s.m.SetNumAccessKeys(len(config.Keys), len(portCiphers))
	return nil
}

// Stop serving on all ports.
func (s *SSServer) Stop() error {
	for portNum := range s.ports {
		if err := s.removePort(portNum); err != nil {
			return err
		}
	}
	return nil
}

// RunSSServer starts a shadowsocks server running, and returns the server or an error.
func RunSSServer(filename string, natTimeout time.Duration, sm *outlineMetricsCollector, replayHistory int) (*SSServer, error) {
	server := &SSServer{
		natTimeout:  natTimeout,
		m:           sm,
		replayCache: service.NewReplayCache(replayHistory),
		ports:       make(map[int]*ssPort),
	}
	err := server.loadConfig(filename)
	if err != nil {
		return nil, fmt.Errorf("failed configure server: %w", err)
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

	metrics := newPrometheusOutlineMetrics(ip2info)
	r := prometheus.WrapRegistererWithPrefix("shadowsocks_", prometheus.DefaultRegisterer)
	r.MustRegister(metrics)
	metrics.SetBuildInfo(version)
	_, err = RunSSServer(flags.ConfigFile, flags.natTimeout, metrics, flags.replayHistory)
	if err != nil {
		slog.Error("Server failed to start. Aborting.", "err", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
