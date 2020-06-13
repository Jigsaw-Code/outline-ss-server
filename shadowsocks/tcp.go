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

package shadowsocks

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	logging "github.com/op/go-logging"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Reads bytes from reader and appends to buf to ensure the needed number of bytes.
// The capacity of buf must be at least bytesNeeded.
func ensureBytes(reader io.Reader, buf []byte, bytesNeeded int) ([]byte, error) {
	if cap(buf) < bytesNeeded {
		return buf, io.ErrShortBuffer
	}
	bytesToRead := bytesNeeded - len(buf)
	if bytesToRead <= 0 {
		return buf, nil
	}
	n, err := io.ReadFull(reader, buf[len(buf):bytesNeeded])
	buf = buf[:len(buf)+n]
	if (err == nil || err == io.EOF) && n < bytesToRead {
		err = io.ErrUnexpectedEOF
	}
	return buf, err
}

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

func findAccessKey(clientConn onet.DuplexConn, cipherList CipherList) (string, onet.DuplexConn, []byte, error) {
	// This must have enough space to hold the salt + 2 bytes chunk length + AEAD tag (Overhead) for any cipher
	firstBytes := make([]byte, 0, 32+2+16)
	// Constant of zeroes to use as the start chunk count. This must be as big as the max NonceSize() across all ciphers.
	zeroCountBuf := [12]byte{} // MaxCountSize
	// To hold the decrypted chunk length.
	chunkLenBuf := [2]byte{}
	var err error

	clientIP := remoteIP(clientConn)
	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	// We snapshot the list because it may be modified while we use it.
	// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
	for ci, entry := range cipherList.SnapshotForClientIP(clientIP) {
		id, cipher := entry.Value.(*CipherEntry).ID, entry.Value.(*CipherEntry).Cipher
		saltsize := cipher.SaltSize()
		firstBytes, err = ensureBytes(clientConn, firstBytes, saltsize)
		if err != nil {
			debugTCP(id, "Failed to read salt: %v", err)
			continue
		}
		salt := firstBytes[:saltsize]
		aead, err := cipher.Decrypter(salt)
		if err != nil {
			debugTCP(id, "Failed to create decrypter: %v", err)
			continue
		}
		cipherTextLength := 2 + aead.Overhead()
		firstBytes, err = ensureBytes(clientConn, firstBytes, saltsize+cipherTextLength)
		if err != nil {
			debugTCP(id, "Failed to read length: %v", err)
			continue
		}
		cipherText := firstBytes[saltsize : saltsize+cipherTextLength]
		_, err = aead.Open(chunkLenBuf[:0], zeroCountBuf[:aead.NonceSize()], cipherText, nil)
		if err != nil {
			debugTCP(id, "Failed to decrypt length: %v", err)
			continue
		}
		debugTCP(id, "Found cipher at index %d", ci)
		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.MarkUsedByClientIP(entry, clientIP)
		ssr := NewShadowsocksReader(io.MultiReader(bytes.NewReader(firstBytes), clientConn), cipher)
		ssw := NewShadowsocksWriter(clientConn, cipher)
		return id, onet.WrapConn(clientConn, ssr, ssw).(onet.DuplexConn), salt, nil
	}
	return "", clientConn, nil, fmt.Errorf("Could not find valid TCP cipher")
}

type tcpService struct {
	listener    *net.TCPListener
	ciphers     CipherList
	m           metrics.ShadowsocksMetrics
	isRunning   bool
	readTimeout time.Duration
	// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
	replayCache    *ReplayCache
	checkAllowedIP func(net.IP) *onet.ConnectionError
}

// NewTCPService creates a TCPService
func NewTCPService(listener *net.TCPListener, ciphers CipherList, replayCache *ReplayCache, m metrics.ShadowsocksMetrics, timeout time.Duration) TCPService {
	return &tcpService{
		listener:       listener,
		ciphers:        ciphers,
		m:              m,
		readTimeout:    timeout,
		replayCache:    replayCache,
		checkAllowedIP: onet.RequirePublicIP,
	}
}

// TCPService is a Shadowsocks TCP service that can be started and stopped.
type TCPService interface {
	Start()
	Stop() error
}

// proxyConnection will route the clientConn according to the address read from the connection.
func proxyConnection(clientConn onet.DuplexConn, proxyMetrics *metrics.ProxyMetrics, checkAllowedIP func(net.IP) *onet.ConnectionError) *onet.ConnectionError {
	tgtAddr, err := socks.ReadAddr(clientConn)
	if err != nil {
		return onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", err)
	}
	tgtTCPAddr, err := net.ResolveTCPAddr("tcp", tgtAddr.String())
	if err != nil {
		return onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr.String()), err)
	}
	if err := checkAllowedIP(tgtTCPAddr.IP); err != nil {
		return err
	}

	tgtTCPConn, err := net.DialTCP("tcp", nil, tgtTCPAddr)
	if err != nil {
		return onet.NewConnectionError("ERR_CONNECT", "Failed to connect to target", err)
	}
	defer tgtTCPConn.Close()
	tgtTCPConn.SetKeepAlive(true)
	tgtConn := metrics.MeasureConn(tgtTCPConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy)

	logger.Debugf("proxy %s <-> %s", clientConn.RemoteAddr().String(), tgtConn.RemoteAddr().String())
	_, _, err = onet.Relay(clientConn, tgtConn)
	if err != nil {
		return onet.NewConnectionError("ERR_RELAY", "Failed to relay traffic", err)
	}
	return nil
}

func (s *tcpService) Start() {
	s.isRunning = true
	for s.isRunning {
		var clientConn onet.DuplexConn
		clientConn, err := s.listener.AcceptTCP()
		if err != nil {
			if !s.isRunning {
				return
			}
			logger.Errorf("Failed to accept: %v", err)
			continue
		}

		go func() (connError *onet.ConnectionError) {
			clientLocation, err := s.m.GetLocation(clientConn.RemoteAddr())
			if err != nil {
				logger.Warningf("Failed location lookup: %v", err)
			}
			logger.Debugf("Got location \"%v\" for IP %v", clientLocation, clientConn.RemoteAddr().String())
			s.m.AddOpenTCPConnection(clientLocation)
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in TCP handler: %v", r)
				}
			}()
			connStart := time.Now()
			clientConn.(*net.TCPConn).SetKeepAlive(true)
			// Set a deadline for connection authentication
			clientConn.SetReadDeadline(connStart.Add(s.readTimeout))
			keyID := ""
			var proxyMetrics metrics.ProxyMetrics
			var timeToCipher time.Duration
			clientConn = metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
			defer func() {
				connDuration := time.Now().Sub(connStart)
				status := "OK"
				if connError != nil {
					logger.Debugf("TCP Error: %v: %v", connError.Message, connError.Cause)
					status = connError.Status
				}
				s.m.AddClosedTCPConnection(clientLocation, keyID, status, proxyMetrics, timeToCipher, connDuration)
				clientConn.Close() // Closing after the metrics are added aids integration testing.
				logger.Debugf("Done with status %v, duration %v", status, connDuration)
			}()

			findStartTime := time.Now()
			keyID, clientConn, salt, err := findAccessKey(clientConn, s.ciphers)
			timeToCipher = time.Now().Sub(findStartTime)

			if err != nil {
				logger.Debugf("Failed to find a valid cipher after reading %v bytes: %v", proxyMetrics.ClientProxy, err)
				const status = "ERR_CIPHER"
				s.absorbProbe(clientConn, clientLocation, status, &proxyMetrics)
				return onet.NewConnectionError(status, "Failed to find a valid cipher", err)
			} else if !s.replayCache.Add(keyID, salt) { // Only check the cache if findAccessKey succeeded.
				const status = "ERR_REPLAY"
				s.absorbProbe(clientConn, clientLocation, status, &proxyMetrics)
				logger.Debugf("Replay: %v in %s sent %d bytes", clientConn.RemoteAddr(), clientLocation, proxyMetrics.ClientProxy)
				return onet.NewConnectionError(status, "Replay detected", nil)
			}

			// Clear the authentication deadline
			clientConn.SetReadDeadline(time.Time{})
			return proxyConnection(clientConn, &proxyMetrics, s.checkAllowedIP)
		}()
	}
}

// Keep the connection open until we hit the authentication deadline to protect against probing attacks
// `proxyMetrics` is a pointer because its value is being mutated by `clientConn`.
func (s *tcpService) absorbProbe(clientConn io.ReadCloser, clientLocation, status string, proxyMetrics *metrics.ProxyMetrics) {
	_, drainErr := io.Copy(ioutil.Discard, clientConn) // drain socket
	drainResult := drainErrToString(drainErr)
	port := s.listener.Addr().(*net.TCPAddr).Port
	logger.Debugf("Drain error: %v, drain result: %v", drainErr, drainResult)
	s.m.AddTCPProbe(clientLocation, status, drainResult, port, *proxyMetrics)
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
	s.isRunning = false
	return s.listener.Close()
}
