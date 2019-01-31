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
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"time"

	"github.com/Jigsaw-Code/outline-ss-server/metrics"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	logging "github.com/op/go-logging"

	"sync"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

const udpBufSize = 64 * 1024

// upack decrypts src into dst. It tries each cipher until it finds one that authenticates
// correctly. dst and src must not overlap.
func unpack(dst, src []byte, cipherList CipherList) ([]byte, string, shadowaead.Cipher, error) {
	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	// We snapshot the list because it may be modified while we use it.
	for _, entry := range cipherList.SafeSnapshot() {
		id, cipher := entry.Value.(*CipherEntry).ID, entry.Value.(*CipherEntry).Cipher
		buf, err := shadowaead.Unpack(dst, src, cipher)
		if err != nil {
			if logger.IsEnabledFor(logging.DEBUG) {
				logger.Debugf("Failed UDP cipher %v: %v", id, err)
			}
			continue
		}
		if logger.IsEnabledFor(logging.DEBUG) {
			logger.Debugf("Selected UDP cipher %v", id)
		}
		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.SafeMoveToFront(entry)
		return buf, id, cipher, nil
	}
	return nil, "", nil, errors.New("could not find valid cipher")
}

type udpService struct {
	clientConn net.PacketConn
	natTimeout time.Duration
	ciphers    *CipherList
	m          metrics.ShadowsocksMetrics
	isRunning  bool
}

// NewUDPService creates a UDPService
func NewUDPService(clientConn net.PacketConn, natTimeout time.Duration, cipherList *CipherList, m metrics.ShadowsocksMetrics) UDPService {
	return &udpService{clientConn: clientConn, natTimeout: natTimeout, ciphers: cipherList, m: m}
}

// UDPService is a UDP shadowsocks service that can be started and stopped.
type UDPService interface {
	Start()
	Stop() error
}

// Listen on addr for encrypted packets and basically do UDP NAT.
// We take the ciphers as a pointer because it gets replaced on config updates.
func (s *udpService) Start() {
	defer s.clientConn.Close()

	nm := newNATmap(s.natTimeout, s.m)
	cipherBuf := make([]byte, udpBufSize)
	textBuf := make([]byte, udpBufSize)

	s.isRunning = true
	for s.isRunning {
		func() (connError *onet.ConnectionError) {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in UDP loop: %v", r)
					debug.PrintStack()
				}
			}()
			clientLocation := ""
			keyID := ""
			var clientProxyBytes, proxyTargetBytes int
			var timeToCipher time.Duration
			defer func() {
				status := "OK"
				if connError != nil {
					logger.Debugf("UDP Error: %v: %v", connError.Message, connError.Cause)
					status = connError.Status
				}
				s.m.AddUDPPacketFromClient(clientLocation, keyID, status, clientProxyBytes, proxyTargetBytes, timeToCipher)
			}()
			clientProxyBytes, clientAddr, err := s.clientConn.ReadFrom(cipherBuf)
			if err != nil {
				if !s.isRunning {
					return nil
				}
				return onet.NewConnectionError("ERR_READ", "Failed to read from client", err)
			}
			clientLocation, locErr := s.m.GetLocation(clientAddr)
			if locErr != nil {
				logger.Warningf("Failed location lookup: %v", locErr)
			}
			logger.Debugf("Got location \"%v\" for IP %v", clientLocation, clientAddr.String())
			defer logger.Debugf("UDP done with %v", clientAddr.String())
			logger.Debugf("UDP Request from %v with %v bytes", clientAddr, clientProxyBytes)
			unpackStart := time.Now()
			buf, keyID, cipher, err := unpack(textBuf, cipherBuf[:clientProxyBytes], *s.ciphers)
			timeToCipher = time.Now().Sub(unpackStart)

			if err != nil {
				return onet.NewConnectionError("ERR_CIPHER", "Failed to upack data from client", err)
			}

			tgtAddr := socks.SplitAddr(buf)
			if tgtAddr == nil {
				return onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", nil)
			}

			tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
			if err != nil {
				return onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr.String()), err)
			}
			if !tgtUDPAddr.IP.IsGlobalUnicast() {
				return onet.NewConnectionError("ERR_ADDRESS_INVALID", fmt.Sprintf("Target address is not global unicast: %v", tgtAddr.String()), err)
			}
			if onet.IsPrivateAddress(tgtUDPAddr.IP) {
				return onet.NewConnectionError("ERR_ADDRESS_PRIVATE", fmt.Sprintf("Target address is a private address: %v", tgtAddr.String()), nil)
			}

			payload := buf[len(tgtAddr):]

			targetConn := nm.Get(clientAddr.String())
			if targetConn == nil {
				targetConn, err = net.ListenPacket("udp", "")
				if err != nil {
					return onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to create UDP socket", err)
				}
				nm.Add(clientAddr, s.clientConn, cipher, targetConn, clientLocation, keyID)
			}
			logger.Debugf("UDP Nat: client %v <-> proxy exit %v", clientAddr, targetConn.LocalAddr())

			proxyTargetBytes, err = targetConn.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to target", err)
			}
			return nil
		}()
	}
}

func (s *udpService) Stop() error {
	s.isRunning = false
	return s.clientConn.Close()
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	keyConn map[string]net.PacketConn
	timeout time.Duration
	metrics metrics.ShadowsocksMetrics
}

func newNATmap(timeout time.Duration, sm metrics.ShadowsocksMetrics) *natmap {
	m := &natmap{metrics: sm}
	m.keyConn = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *natmap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.keyConn[key]
}

func (m *natmap) set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.keyConn[key] = pc
}

func (m *natmap) del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.keyConn[key]
	if ok {
		delete(m.keyConn, key)
		return pc
	}
	return nil
}

func (m *natmap) Add(clientAddr net.Addr, clientConn net.PacketConn, cipher shadowaead.Cipher, targetConn net.PacketConn, clientLocation, keyID string) {
	m.set(clientAddr.String(), targetConn)

	m.metrics.AddUDPNatEntry()
	go func() {
		timedCopy(clientAddr, clientConn, cipher, targetConn, m.timeout, clientLocation, keyID, m.metrics)
		m.metrics.RemoveUDPNatEntry()
		if pc := m.del(clientAddr.String()); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func timedCopy(clientAddr net.Addr, clientConn net.PacketConn, cipher shadowaead.Cipher, targetConn net.PacketConn,
	timeout time.Duration, clientLocation, keyID string, sm metrics.ShadowsocksMetrics) {
	textBuf := make([]byte, udpBufSize)
	cipherBuf := make([]byte, udpBufSize)

	expired := false
	for !expired {
		var targetProxyBytes, proxyClientBytes int
		connError := func() (connError *onet.ConnectionError) {
			var (
				raddr net.Addr
				err   error
			)
			targetConn.SetReadDeadline(time.Now().Add(timeout))
			targetProxyBytes, raddr, err = targetConn.ReadFrom(textBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						expired = true
						return nil
					}
				}
				return onet.NewConnectionError("ERR_READ", "Failed to read from target", err)
			}

			srcAddr := socks.ParseAddr(raddr.String())
			logger.Debugf("UDP response from %v to %v", srcAddr, clientAddr)
			// Shift data buffer to prepend with srcAddr.
			copy(textBuf[len(srcAddr):], textBuf[:targetProxyBytes])
			copy(textBuf, srcAddr)

			buf, err := shadowaead.Pack(cipherBuf, textBuf[:len(srcAddr)+targetProxyBytes], cipher)
			if err != nil {
				return onet.NewConnectionError("ERR_PACK", "Failed to pack data to client", err)
			}
			proxyClientBytes, err = clientConn.WriteTo(buf, clientAddr)
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to client", err)
			}
			return nil
		}()
		status := "OK"
		if connError != nil {
			logger.Debugf("UDP Error: %v: %v", connError.Message, connError.Cause)
			status = connError.Status
		}
		sm.AddUDPPacketFromTarget(clientLocation, keyID, status, targetProxyBytes, proxyClientBytes)
	}
}
