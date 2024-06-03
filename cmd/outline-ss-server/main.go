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
	"strings"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"

	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
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

var directListenerType = "direct"

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

type ssPort struct {
	tcpListener *net.TCPListener
	packetConn  net.PacketConn
	cipherList  service.CipherList
}

type SSServer struct {
	natTimeout  time.Duration
	m           *outlineMetrics
	replayCache service.ReplayCache
	ports       map[int]*ssPort
}

func (s *SSServer) startTCP(portNum int, cipherList service.CipherList) (*net.TCPListener, error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: portNum})
	if err != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return nil, fmt.Errorf("Shadowsocks TCP service failed to start on port %v: %w", portNum, err)
	}
	logger.Infof("Shadowsocks TCP service listening on %v", listener.Addr().String())
	authFunc := service.NewShadowsocksStreamAuthenticator(cipherList, &s.replayCache, s.m)
	// TODO: Register initial data metrics at zero.
	tcpHandler := service.NewTCPHandler(portNum, authFunc, s.m, tcpReadTimeout)
	accept := func() (transport.StreamConn, error) {
		conn, err := listener.AcceptTCP()
		if err == nil {
			conn.SetKeepAlive(true)
		}
		return conn, err
	}
	go service.StreamServe(accept, tcpHandler.Handle)
	return listener, nil
}

func (s *SSServer) startUDP(portNum int, cipherList service.CipherList) (*net.UDPConn, error) {
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: portNum})
	if err != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return nil, fmt.Errorf("Shadowsocks UDP service failed to start on port %v: %w", portNum, err)
	}
	logger.Infof("Shadowsocks UDP service listening on %v", packetConn.LocalAddr().String())
	packetHandler := service.NewPacketHandler(s.natTimeout, cipherList, s.m)
	go packetHandler.Handle(packetConn)
	return packetConn, nil
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
	logger.Infof("Shadowsocks TCP service on port %v stopped", portNum)
	if udpErr != nil {
		//lint:ignore ST1005 Shadowsocks is capitalized.
		return fmt.Errorf("Shadowsocks UDP service on port %v failed to stop: %w", portNum, udpErr)
	}
	logger.Infof("Shadowsocks UDP service on port %v stopped", portNum)
	return nil
}

func (s *SSServer) loadConfig(filename string) error {
	config, err := ReadConfig(filename)
	if err != nil {
		return fmt.Errorf("failed to load config (%v): %w", filename, err)
	}

	portChanges := make(map[int]int)
	portCiphers := make(map[int]*list.List) // Values are *List of *CipherEntry.
	for _, serviceConfig := range config.Services {
		if serviceConfig.Listeners == nil || serviceConfig.Keys == nil {
			return fmt.Errorf("must specify at least 1 listener and 1 key per service")
		}
		addrs := []net.Addr{}
		for _, listener := range serviceConfig.Listeners {
			switch t := listener.Type; t {
			// TODO: Support more listener types.
			case directListenerType:
				addr, err := onet.ResolveAddr(listener.Address)
				if err != nil {
					return fmt.Errorf("failed to resolve direct address: %v: %w", listener.Address, err)
				}
				addrs = append(addrs, addr)
				port, err := onet.GetPort(addr)
				if err != nil {
					return err
				}
				portChanges[int(port)] = 1
			default:
				return fmt.Errorf("unsupported listener type: %s", t)
			}
		}

		type key struct {
			c string
			s string
		}
		existingCipher := make(map[key]bool)
		for _, keyConfig := range serviceConfig.Keys {
			for _, addr := range addrs {
				port, err := onet.GetPort(addr)
				if err != nil {
					return err
				}
				cipherList, ok := portCiphers[port]
				if !ok {
					cipherList = list.New()
					portCiphers[port] = cipherList
				}
				_, ok = existingCipher[key{keyConfig.Cipher, keyConfig.Secret}]
				if ok {
					logger.Debugf("encryption key already exists for port=%v, ID=`%v`. Skipping.", port, keyConfig.ID)
					continue
				}
				cryptoKey, err := shadowsocks.NewEncryptionKey(keyConfig.Cipher, keyConfig.Secret)
				if err != nil {
					return fmt.Errorf("failed to create encyption key for key %v: %w", keyConfig.ID, err)
				}
				entry := service.MakeCipherEntry(keyConfig.ID, cryptoKey, keyConfig.Secret)
				cipherList.PushBack(&entry)
				existingCipher[key{keyConfig.Cipher, keyConfig.Secret}] = true
			}
		}
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
			cipherList := service.NewCipherList()
			tcpListener, err := s.startTCP(portNum, cipherList)
			if err != nil {
				return err
			}
			packetConn, err := s.startUDP(portNum, cipherList)
			if err != nil {
				return err
			}
			s.ports[portNum] = &ssPort{tcpListener, packetConn, cipherList}
		}
	}
	numServices := 0
	for portNum, cipherList := range portCiphers {
		s.ports[portNum].cipherList.Update(cipherList)
		numServices += cipherList.Len()
	}
	logger.Infof("Loaded %v access keys over %v ports", numServices, len(s.ports))
	s.m.SetNumAccessKeys(numServices, len(s.ports))
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
func RunSSServer(filename string, natTimeout time.Duration, sm *outlineMetrics, replayHistory int) (*SSServer, error) {
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
