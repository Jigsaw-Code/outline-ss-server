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
	"net"
	"time"

	logging "github.com/op/go-logging"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Reads bytes from reader and appends to buf to ensure the needed number of bytes.
// The cpacity of buf must be at least bytesNeeded.
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

func findAccessKey(clientConn onet.DuplexConn, cipherList CipherList) (string, onet.DuplexConn, error) {
	// This must have enough space to hold the salt + 2 bytes chunk length + AEAD tag (Oeverhead) for any cipher
	replayBytes := make([]byte, 0, 32+2+16)
	// Constant of zeroes to use as the start chunk count. This must be as big as the max NonceSize() across all ciphers.
	zeroCountBuf := make([]byte, 12) // MaxCountSize
	// To hold the decrypted chunk length.
	chunkLenBuf := [2]byte{}
	var err error

	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	// We snapshot the list because it may be modified while we use it.
	// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
	for _, entry := range cipherList.SafeSnapshot() {
		id, cipher := entry.Value.(*CipherEntry).ID, entry.Value.(*CipherEntry).Cipher
		replayBytes, err = ensureBytes(clientConn, replayBytes, cipher.SaltSize())
		if err != nil {
			if logger.IsEnabledFor(logging.DEBUG) {
				logger.Debugf("Failed TCP ciper %v: %v", id, err)
			}
			continue
		}
		salt := replayBytes[:cipher.SaltSize()]
		aead, err := cipher.Decrypter(salt)
		replayBytes, err = ensureBytes(clientConn, replayBytes, cipher.SaltSize()+2+aead.Overhead())
		if err != nil {
			if logger.IsEnabledFor(logging.DEBUG) {
				logger.Debugf("Failed TCP ciper %v: %v", id, err)
			}
			continue
		}
		cipherText := replayBytes[cipher.SaltSize() : cipher.SaltSize()+2+aead.Overhead()]
		_, err = aead.Open(chunkLenBuf[:0], zeroCountBuf[:aead.NonceSize()], cipherText, nil)
		if err != nil {
			if logger.IsEnabledFor(logging.DEBUG) {
				logger.Debugf("Failed TCP ciper %v: %v", id, err)
			}
			continue
		}
		if logger.IsEnabledFor(logging.DEBUG) {
			logger.Debugf("Selected TCP cipher %v", id)
		}
		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.SafeMoveToFront(entry)
		ssr := NewShadowsocksReader(io.MultiReader(bytes.NewReader(replayBytes), clientConn), cipher)
		ssw := NewShadowsocksWriter(clientConn, cipher)
		return id, onet.WrapConn(clientConn, ssr, ssw).(onet.DuplexConn), nil
	}
	return "", nil, fmt.Errorf("Could not find valid TCP cipher")
}

type tcpService struct {
	listener  *net.TCPListener
	ciphers   *CipherList
	m         metrics.ShadowsocksMetrics
	isRunning bool
}

// NewTCPService creates a TCPService
func NewTCPService(listener *net.TCPListener, ciphers *CipherList, m metrics.ShadowsocksMetrics) TCPService {
	return &tcpService{listener: listener, ciphers: ciphers, m: m}
}

// TCPService is a Shadowsocks TCP service that can be started and stopped.
type TCPService interface {
	Start()
	Stop() error
}

// proxyConnection will route the clientConn according to the address read from the connection.
func proxyConnection(clientConn onet.DuplexConn, proxyMetrics *metrics.ProxyMetrics) *onet.ConnectionError {
	tgtAddr, err := socks.ReadAddr(clientConn)
	if err != nil {
		return onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", err)
	}
	tgtTCPAddr, err := net.ResolveTCPAddr("tcp", tgtAddr.String())
	if err != nil {
		return onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr.String()), err)
	}
	if !tgtTCPAddr.IP.IsGlobalUnicast() {
		return onet.NewConnectionError("ERR_ADDRESS_INVALID", fmt.Sprintf("Target address is not global unicast: %v", tgtAddr.String()), err)
	}
	if onet.IsPrivateAddress(tgtTCPAddr.IP) {
		return onet.NewConnectionError("ERR_ADDRESS_PRIVATE", fmt.Sprintf("Target address is a private address: %v", tgtAddr.String()), nil)
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
			keyID := ""
			var proxyMetrics metrics.ProxyMetrics
			var timeToCipher time.Duration
			clientConn = metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
			defer func() {
				connDuration := time.Now().Sub(connStart)
				clientConn.Close()
				status := "OK"
				if connError != nil {
					logger.Debugf("TCP Error: %v: %v", connError.Message, connError.Cause)
					status = connError.Status
				}
				logger.Debugf("Done with status %v, duration %v", status, connDuration)
				s.m.AddClosedTCPConnection(clientLocation, keyID, status, proxyMetrics, timeToCipher, connDuration)
			}()

			findStartTime := time.Now()
			keyID, clientConn, err := findAccessKey(clientConn, *s.ciphers)
			timeToCipher = time.Now().Sub(findStartTime)

			if err != nil {
				return onet.NewConnectionError("ERR_CIPHER", "Failed to find a valid cipher", err)
			}

			return proxyConnection(clientConn, &proxyMetrics)
		}()
	}
}

func (s *tcpService) Stop() error {
	s.isRunning = false
	return s.listener.Close()
}
