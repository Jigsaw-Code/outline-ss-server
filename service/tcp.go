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

package service

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-internal-sdk/transport"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func remoteIP(conn net.Conn) net.IP {
	addr := conn.RemoteAddr()
	if addr == nil {
		return nil
	}
	if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		return tcpaddr.IP
	}
	ipstr, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return net.ParseIP(ipstr)
	}
	return nil
}

// Wrapper for logger.Debugf during TCP access key searches.
func debugTCP(cipherID, template string, val interface{}) {
	// This is an optimization to reduce unnecessary allocations due to an interaction
	// between Go's inlining/escape analysis and varargs functions like logger.Debugf.
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("TCP(%s): "+template, cipherID, val)
	}
}

// bytesForKeyFinding is the number of bytes to read for finding the AccessKey.
// Is must satisfy provided >= bytesForKeyFinding >= required for every cipher in the list.
// provided = saltSize + 2 + 2 * cipher.TagSize, the minimum number of bytes we will see in a valid connection
// required = saltSize + 2 + cipher.TagSize, the number of bytes needed to authenticate the connection.
const bytesForKeyFinding = 50

func findAccessKey(clientReader io.Reader, clientIP net.IP, cipherList CipherList) (*CipherEntry, io.Reader, []byte, time.Duration, error) {
	// We snapshot the list because it may be modified while we use it.
	ciphers := cipherList.SnapshotForClientIP(clientIP)
	firstBytes := make([]byte, bytesForKeyFinding)
	if n, err := io.ReadFull(clientReader, firstBytes); err != nil {
		return nil, clientReader, nil, 0, fmt.Errorf("Reading header failed after %d bytes: %v", n, err)
	}

	findStartTime := time.Now()
	entry, elt := findEntry(firstBytes, ciphers)
	timeToCipher := time.Now().Sub(findStartTime)
	if entry == nil {
		// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
		return nil, clientReader, nil, timeToCipher, fmt.Errorf("Could not find valid TCP cipher")
	}

	// Move the active cipher to the front, so that the search is quicker next time.
	cipherList.MarkUsedByClientIP(elt, clientIP)
	salt := firstBytes[:entry.Cipher.SaltSize()]
	return entry, io.MultiReader(bytes.NewReader(firstBytes), clientReader), salt, timeToCipher, nil
}

// Implements a trial decryption search.  This assumes that all ciphers are AEAD.
func findEntry(firstBytes []byte, ciphers []*list.Element) (*CipherEntry, *list.Element) {
	// To hold the decrypted chunk length.
	chunkLenBuf := [2]byte{}
	for ci, elt := range ciphers {
		entry := elt.Value.(*CipherEntry)
		id, cipher := entry.ID, entry.Cipher
		saltsize := cipher.SaltSize()
		salt := firstBytes[:saltsize]
		cipherTextLength := 2 + cipher.TagSize()
		cipherText := firstBytes[saltsize : saltsize+cipherTextLength]
		_, err := ss.DecryptOnce(cipher, salt, chunkLenBuf[:0], cipherText)
		if err != nil {
			debugTCP(id, "Failed to decrypt length: %v", err)
			continue
		}
		debugTCP(id, "Found cipher at index %d", ci)
		// Move the active cipher to the front, so that the search is quicker next time.
		return entry, elt
	}
	return nil, nil
}

type tcpService struct {
	mu          sync.RWMutex // Protects .listeners and .stopped
	listener    *net.TCPListener
	stopped     bool
	ciphers     CipherList
	m           metrics.ShadowsocksMetrics
	running     sync.WaitGroup
	readTimeout time.Duration
	// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
	replayCache       *ReplayCache
	targetIPValidator onet.TargetIPValidator
}

// NewTCPService creates a TCPService
// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
func NewTCPService(ciphers CipherList, replayCache *ReplayCache, m metrics.ShadowsocksMetrics, timeout time.Duration) TCPService {
	return &tcpService{
		ciphers:           ciphers,
		m:                 m,
		readTimeout:       timeout,
		replayCache:       replayCache,
		targetIPValidator: onet.RequirePublicIP,
	}
}

// TCPService is a Shadowsocks TCP service that can be started and stopped.
type TCPService interface {
	// SetTargetIPValidator sets the function to be used to validate the target IP addresses.
	SetTargetIPValidator(targetIPValidator onet.TargetIPValidator)
	// Serve adopts the listener, which will be closed before Serve returns.  Serve returns an error unless Stop() was called.
	Serve(listener *net.TCPListener) error
	// Stop closes the listener but does not interfere with existing connections.
	Stop() error
	// GracefulStop calls Stop(), and then blocks until all resources have been cleaned up.
	GracefulStop() error
}

func (s *tcpService) SetTargetIPValidator(targetIPValidator onet.TargetIPValidator) {
	s.targetIPValidator = targetIPValidator
}

func dialTarget(tgtAddr socks.Addr, proxyMetrics *metrics.ProxyMetrics, targetIPValidator onet.TargetIPValidator) (onet.DuplexConn, *onet.ConnectionError) {
	var ipError *onet.ConnectionError
	dialer := net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		ip, _, _ := net.SplitHostPort(address)
		ipError = targetIPValidator(net.ParseIP(ip))
		if ipError != nil {
			return errors.New(ipError.Message)
		}
		return nil
	}}
	tgtConn, err := dialer.Dial("tcp", tgtAddr.String())
	if ipError != nil {
		return nil, ipError
	} else if err != nil {
		return nil, onet.NewConnectionError("ERR_CONNECT", "Failed to connect to target", err)
	}
	tgtTCPConn := tgtConn.(*net.TCPConn)
	tgtTCPConn.SetKeepAlive(true)
	return metrics.MeasureConn(tgtTCPConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy), nil
}

func (s *tcpService) Serve(listener *net.TCPListener) error {
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		listener.Close()
		return errors.New("Serve can only be called once")
	}
	if s.stopped {
		s.mu.Unlock()
		return listener.Close()
	}
	s.listener = listener
	s.running.Add(1)
	s.mu.Unlock()

	defer s.running.Done()
	for {
		clientTCPConn, err := listener.AcceptTCP()
		if err != nil {
			s.mu.RLock()
			stopped := s.stopped
			s.mu.RUnlock()
			if stopped {
				return nil
			}
			logger.Errorf("Accept failed: %v", err)
			continue
		}

		s.running.Add(1)
		go func() {
			defer s.running.Done()
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in TCP handler: %v", r)
				}
			}()

			clientTCPConn.SetKeepAlive(true)
			clientLocation, err := s.m.GetLocation(clientTCPConn.RemoteAddr())
			if err != nil {
				logger.Warningf("Failed location lookup: %v", err)
			}
			logger.Debugf("Got location \"%v\" for IP %v", clientLocation, clientTCPConn.RemoteAddr().String())
			s.m.AddOpenTCPConnection(clientLocation)
			var proxyMetrics metrics.ProxyMetrics
			clientConn := metrics.MeasureConn(clientTCPConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
			connStart := time.Now()

			id, connError := s.handleConnection(listener.Addr().(*net.TCPAddr).Port, clientConn, &proxyMetrics)

			connDuration := time.Now().Sub(connStart)
			status := "OK"
			if connError != nil {
				status = connError.Status
				logger.Debugf("TCP Error: %v: %v", connError.Message, connError.Cause)
			}
			s.m.AddClosedTCPConnection(clientLocation, id, status, proxyMetrics, connDuration)
			clientConn.Close() // Closing after the metrics are added aids integration testing.
			logger.Debugf("Done with status %v, duration %v", status, connDuration)
		}()
	}
}

func (s *tcpService) handleConnection(listenerPort int, clientConn transport.StreamConn, proxyMetrics *metrics.ProxyMetrics) (string, *onet.ConnectionError) {
	// Set a deadline to receive the address to the target.
	clientConn.SetReadDeadline(time.Now().Add(s.readTimeout))

	// 1. Find the cipher and acess key id.
	cipherEntry, clientReader, clientSalt, timeToCipher, keyErr := findAccessKey(clientConn, remoteIP(clientConn), s.ciphers)
	s.m.AddTCPCipherSearch(keyErr == nil, timeToCipher)
	if keyErr != nil {
		logger.Debugf("Failed to find a valid cipher after reading %v bytes: %v", proxyMetrics.ClientProxy, keyErr)
		const status = "ERR_CIPHER"
		s.absorbProbe(listenerPort, clientConn, status, proxyMetrics)
		return "", onet.NewConnectionError(status, "Failed to find a valid cipher", keyErr)
	}
	var id string
	if cipherEntry != nil {
		id = cipherEntry.ID
	}

	// 2. Check if the connection is a replay.
	isServerSalt := cipherEntry.SaltGenerator.IsServerSalt(clientSalt)
	// Only check the cache if findAccessKey succeeded and the salt is unrecognized.
	if isServerSalt || !s.replayCache.Add(cipherEntry.ID, clientSalt) {
		var status string
		if isServerSalt {
			status = "ERR_REPLAY_SERVER"
		} else {
			status = "ERR_REPLAY_CLIENT"
		}
		s.absorbProbe(listenerPort, clientConn, status, proxyMetrics)
		logger.Debugf(status+": %v sent %d bytes", clientConn.RemoteAddr(), proxyMetrics.ClientProxy)
		return id, onet.NewConnectionError(status, "Replay detected", nil)
	}

	// 3. Read target address and dial it.
	ssr := ss.NewShadowsocksReader(clientReader, cipherEntry.Cipher)
	tgtAddr, err := socks.ReadAddr(ssr)
	// Clear the deadline for the target address
	clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		// Drain to prevent a close on cipher error.
		io.Copy(ioutil.Discard, clientConn)
		return id, onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", err)
	}
	tgtConn, dialErr := dialTarget(tgtAddr, proxyMetrics, s.targetIPValidator)
	if dialErr != nil {
		// We don't drain so dial errors and invalid addresses are communicated quickly.
		return id, dialErr
	}
	defer tgtConn.Close()

	// 4. Bridge the client and target connections
	logger.Debugf("proxy %s <-> %s", clientConn.RemoteAddr().String(), tgtConn.RemoteAddr().String())
	ssw := ss.NewShadowsocksWriter(clientConn, cipherEntry.Cipher)
	ssw.SetSaltGenerator(cipherEntry.SaltGenerator)

	fromClientErrCh := make(chan error)
	go func() {
		_, fromClientErr := ssr.WriteTo(tgtConn)
		if fromClientErr != nil {
			// Drain to prevent a close in the case of a cipher error.
			io.Copy(ioutil.Discard, clientConn)
		}
		clientConn.CloseRead()
		// Send FIN to target.
		// We must do this after the drain is completed, otherwise the target will close its
		// connection with the proxy, which will, in turn, close the connection with the client.
		tgtConn.CloseWrite()
		fromClientErrCh <- fromClientErr
	}()
	_, fromTargetErr := ssw.ReadFrom(tgtConn)
	// Send FIN to client.
	clientConn.CloseWrite()
	tgtConn.CloseRead()

	fromClientErr := <-fromClientErrCh
	if fromClientErr != nil {
		return id, onet.NewConnectionError("ERR_RELAY_CLIENT", "Failed to relay traffic from client", fromClientErr)
	}
	if fromTargetErr != nil {
		return id, onet.NewConnectionError("ERR_RELAY_TARGET", "Failed to relay traffic from target", fromTargetErr)
	}
	return id, nil
}

// Keep the connection open until we hit the authentication deadline to protect against probing attacks
// `proxyMetrics` is a pointer because its value is being mutated by `clientConn`.
func (s *tcpService) absorbProbe(listenerPort int, clientConn io.ReadCloser, status string, proxyMetrics *metrics.ProxyMetrics) {
	// This line updates proxyMetrics.ClientProxy before it's used in AddTCPProbe.
	_, drainErr := io.Copy(ioutil.Discard, clientConn) // drain socket
	drainResult := drainErrToString(drainErr)
	logger.Debugf("Drain error: %v, drain result: %v", drainErr, drainResult)
	s.m.AddTCPProbe(status, drainResult, listenerPort, proxyMetrics.ClientProxy)
}

func drainErrToString(drainErr error) string {
	netErr, ok := drainErr.(net.Error)
	switch {
	case drainErr == nil:
		return "eof"
	case ok && netErr.Timeout():
		return "timeout"
	default:
		return "other"
	}
}

func (s *tcpService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *tcpService) GracefulStop() error {
	err := s.Stop()
	s.running.Wait()
	return err
}
