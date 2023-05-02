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
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-internal-sdk/transport"
	"github.com/Jigsaw-Code/outline-internal-sdk/transport/shadowsocks"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
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
		return nil, clientReader, nil, 0, fmt.Errorf("reading header failed after %d bytes: %w", n, err)
	}

	findStartTime := time.Now()
	entry, elt := findEntry(firstBytes, ciphers)
	timeToCipher := time.Now().Sub(findStartTime)
	if entry == nil {
		// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
		return nil, clientReader, nil, timeToCipher, fmt.Errorf("could not find valid TCP cipher")
	}

	// Move the active cipher to the front, so that the search is quicker next time.
	cipherList.MarkUsedByClientIP(elt, clientIP)
	salt := firstBytes[:entry.CryptoKey.SaltSize()]
	return entry, io.MultiReader(bytes.NewReader(firstBytes), clientReader), salt, timeToCipher, nil
}

// Implements a trial decryption search.  This assumes that all ciphers are AEAD.
func findEntry(firstBytes []byte, ciphers []*list.Element) (*CipherEntry, *list.Element) {
	// To hold the decrypted chunk length.
	chunkLenBuf := [2]byte{}
	for ci, elt := range ciphers {
		entry := elt.Value.(*CipherEntry)
		cryptoKey := entry.CryptoKey
		_, err := shadowsocks.Unpack(chunkLenBuf[:0], firstBytes[:cryptoKey.SaltSize()+2+cryptoKey.TagSize()], cryptoKey)
		if err != nil {
			debugTCP(entry.ID, "Failed to decrypt length: %v", err)
			continue
		}
		debugTCP(entry.ID, "Found cipher at index %d", ci)
		return entry, elt
	}
	return nil, nil
}

type tcpHandler struct {
	port        int
	ciphers     CipherList
	m           metrics.ShadowsocksMetrics
	readTimeout time.Duration
	// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
	replayCache       *ReplayCache
	targetIPValidator onet.TargetIPValidator
}

// NewTCPService creates a TCPService
// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
func NewTCPHandler(port int, ciphers CipherList, replayCache *ReplayCache, m metrics.ShadowsocksMetrics, timeout time.Duration) TCPHandler {
	return &tcpHandler{
		port:              port,
		ciphers:           ciphers,
		m:                 m,
		readTimeout:       timeout,
		replayCache:       replayCache,
		targetIPValidator: onet.RequirePublicIP,
	}
}

// TCPService is a Shadowsocks TCP service that can be started and stopped.
type TCPHandler interface {
	Handle(ctx context.Context, conn transport.StreamConn)
	// SetTargetIPValidator sets the function to be used to validate the target IP addresses.
	SetTargetIPValidator(targetIPValidator onet.TargetIPValidator)
}

func (s *tcpHandler) SetTargetIPValidator(targetIPValidator onet.TargetIPValidator) {
	s.targetIPValidator = targetIPValidator
}

func dialTarget(tgtAddr socks.Addr, proxyMetrics *metrics.ProxyMetrics, targetIPValidator onet.TargetIPValidator) (transport.StreamConn, *onet.ConnectionError) {
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

type StreamListener func() (transport.StreamConn, error)

func WrapStreamListener[T transport.StreamConn](f func() (T, error)) StreamListener {
	return func() (transport.StreamConn, error) {
		return f()
	}
}

type StreamHandler func(ctx context.Context, conn transport.StreamConn)

// StreamServe repeatedly calls `accept` to obtain connections and `handle` to handle them until
// accept() returns [ErrClosed]. When that happens, all connection handlers will be notified
// via their [context.Context]. StreamServe will return after all pending handlers return.
func StreamServe(accept StreamListener, handle StreamHandler) {
	var running sync.WaitGroup
	defer running.Wait()
	ctx, contextCancel := context.WithCancel(context.Background())
	defer contextCancel()
	for {
		clientConn, err := accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			logger.Warningf("AcceptTCP failed: %v. Continuing to listen.", err)
			continue
		}

		running.Add(1)
		go func() {
			defer running.Done()
			defer clientConn.Close()
			defer func() {
				if r := recover(); r != nil {
					logger.Warningf("Panic in TCP handler: %v. Continuing to listen.", r)
				}
			}()
			handle(ctx, clientConn)
		}()
	}
}

func (h *tcpHandler) Handle(ctx context.Context, clientConn transport.StreamConn) {
	clientLocation, err := h.m.GetLocation(clientConn.RemoteAddr())
	if err != nil {
		logger.Warningf("Failed location lookup: %v", err)
	}
	logger.Debugf("Got location \"%v\" for IP %v", clientLocation, clientConn.RemoteAddr().String())
	h.m.AddOpenTCPConnection(clientLocation)
	var proxyMetrics metrics.ProxyMetrics
	measuredClientConn := metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
	connStart := time.Now()

	id, connError := h.handleConnection(h.port, measuredClientConn, &proxyMetrics)

	connDuration := time.Now().Sub(connStart)
	status := "OK"
	if connError != nil {
		status = connError.Status
		logger.Debugf("TCP Error: %v: %v", connError.Message, connError.Cause)
	}
	h.m.AddClosedTCPConnection(clientLocation, id, status, proxyMetrics, connDuration)
	measuredClientConn.Close() // Closing after the metrics are added aids integration testing.
	logger.Debugf("Done with status %v, duration %v", status, connDuration)
}

func (h *tcpHandler) handleConnection(listenerPort int, clientConn transport.StreamConn, proxyMetrics *metrics.ProxyMetrics) (string, *onet.ConnectionError) {
	// Set a deadline to receive the address to the target.
	clientConn.SetReadDeadline(time.Now().Add(h.readTimeout))

	// 1. Find the cipher and acess key id.
	cipherEntry, clientReader, clientSalt, timeToCipher, keyErr := findAccessKey(clientConn, remoteIP(clientConn), h.ciphers)
	h.m.AddTCPCipherSearch(keyErr == nil, timeToCipher)
	if keyErr != nil {
		logger.Debugf("Failed to find a valid cipher after reading %v bytes: %v", proxyMetrics.ClientProxy, keyErr)
		const status = "ERR_CIPHER"
		h.absorbProbe(listenerPort, clientConn, status, proxyMetrics)
		return "", onet.NewConnectionError(status, "Failed to find a valid cipher", keyErr)
	}
	var id string
	if cipherEntry != nil {
		id = cipherEntry.ID
	}

	// 2. Check if the connection is a replay.
	isServerSalt := cipherEntry.SaltGenerator.IsServerSalt(clientSalt)
	// Only check the cache if findAccessKey succeeded and the salt is unrecognized.
	if isServerSalt || !h.replayCache.Add(cipherEntry.ID, clientSalt) {
		var status string
		if isServerSalt {
			status = "ERR_REPLAY_SERVER"
		} else {
			status = "ERR_REPLAY_CLIENT"
		}
		h.absorbProbe(listenerPort, clientConn, status, proxyMetrics)
		logger.Debugf(status+": %v sent %d bytes", clientConn.RemoteAddr(), proxyMetrics.ClientProxy)
		return id, onet.NewConnectionError(status, "Replay detected", nil)
	}

	// 3. Read target address and dial it.
	ssr := shadowsocks.NewReader(clientReader, cipherEntry.CryptoKey)
	tgtAddr, err := socks.ReadAddr(ssr)
	// Clear the deadline for the target address
	clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		// Drain to prevent a close on cipher error.
		io.Copy(ioutil.Discard, clientConn)
		return id, onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", err)
	}
	tgtConn, dialErr := dialTarget(tgtAddr, proxyMetrics, h.targetIPValidator)
	if dialErr != nil {
		// We don't drain so dial errors and invalid addresses are communicated quickly.
		return id, dialErr
	}
	defer tgtConn.Close()

	// 4. Bridge the client and target connections
	logger.Debugf("proxy %s <-> %s", clientConn.RemoteAddr().String(), tgtConn.RemoteAddr().String())
	ssw := shadowsocks.NewWriter(clientConn, cipherEntry.CryptoKey)
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
func (h *tcpHandler) absorbProbe(listenerPort int, clientConn io.ReadCloser, status string, proxyMetrics *metrics.ProxyMetrics) {
	// This line updates proxyMetrics.ClientProxy before it's used in AddTCPProbe.
	_, drainErr := io.Copy(ioutil.Discard, clientConn) // drain socket
	drainResult := drainErrToString(drainErr)
	logger.Debugf("Drain error: %v, drain result: %v", drainErr, drainResult)
	h.m.AddTCPProbe(status, drainResult, listenerPort, proxyMetrics.ClientProxy)
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
