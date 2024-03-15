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
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/ipinfo"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// TCPMetrics is used to report metrics on TCP connections.
type TCPMetrics interface {
	ipinfo.IPInfoMap

	// TCP metrics
	AddOpenTCPConnection(clientInfo ipinfo.IPInfo)
	AddClosedTCPConnection(clientInfo ipinfo.IPInfo, accessKey, status string, data metrics.ProxyMetrics, duration time.Duration)

	// Shadowsocks TCP metrics
	AddTCPProbe(status, drainResult string, port int, clientProxyBytes int64)
	AddTCPCipherSearch(accessKeyFound bool, timeToCipher time.Duration)
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
	timeToCipher := time.Since(findStartTime)
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
	m           TCPMetrics
	readTimeout time.Duration
	// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
	replayCache *ReplayCache
	dialer      transport.StreamDialer
}

// NewTCPService creates a TCPService
// `replayCache` is a pointer to SSServer.replayCache, to share the cache among all ports.
func NewTCPHandler(port int, ciphers CipherList, replayCache *ReplayCache, m TCPMetrics, timeout time.Duration) TCPHandler {
	return &tcpHandler{
		port:        port,
		ciphers:     ciphers,
		m:           m,
		readTimeout: timeout,
		replayCache: replayCache,
		dialer:      defaultDialer,
	}
}

var defaultDialer = makeValidatingTCPStreamDialer(onet.RequirePublicIP)

func makeValidatingTCPStreamDialer(targetIPValidator onet.TargetIPValidator) transport.StreamDialer {
	return &transport.TCPDialer{Dialer: net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		ip, _, _ := net.SplitHostPort(address)
		return targetIPValidator(net.ParseIP(ip))
	}}}
}

// TCPService is a Shadowsocks TCP service that can be started and stopped.
type TCPHandler interface {
	Handle(ctx context.Context, conn transport.StreamConn)
	// SetTargetDialer sets the [transport.StreamDialer] to be used to connect to target addresses.
	SetTargetDialer(dialer transport.StreamDialer)
}

func (s *tcpHandler) SetTargetDialer(dialer transport.StreamDialer) {
	s.dialer = dialer
}

func ensureConnectionError(err error, fallbackStatus string, fallbackMsg string) *onet.ConnectionError {
	if err == nil {
		return nil
	}
	var connErr *onet.ConnectionError
	if errors.As(err, &connErr) {
		return connErr
	} else {
		return onet.NewConnectionError(fallbackStatus, fallbackMsg, err)
	}
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
	clientInfo, err := ipinfo.GetIPInfoFromAddr(h.m, clientConn.RemoteAddr())
	if err != nil {
		logger.Warningf("Failed client info lookup: %v", err)
	}
	logger.Debugf("Got info \"%#v\" for IP %v", clientInfo, clientConn.RemoteAddr().String())
	h.m.AddOpenTCPConnection(clientInfo)
	var proxyMetrics metrics.ProxyMetrics
	measuredClientConn := metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
	connStart := time.Now()

	id, connError := h.handleConnection(ctx, h.port, measuredClientConn, &proxyMetrics)

	connDuration := time.Since(connStart)
	status := "OK"
	if connError != nil {
		status = connError.Status
		logger.Debugf("TCP Error: %v: %v", connError.Message, connError.Cause)
	}
	h.m.AddClosedTCPConnection(clientInfo, id, status, proxyMetrics, connDuration)
	measuredClientConn.Close() // Closing after the metrics are added aids integration testing.
	logger.Debugf("Done with status %v, duration %v", status, connDuration)
}

func (h *tcpHandler) authenticate(clientConn transport.StreamConn, proxyMetrics *metrics.ProxyMetrics) (string, transport.StreamConn, *onet.ConnectionError) {
	// TODO(fortuna): Offer alternative transports.
	// Find the cipher and acess key id.
	cipherEntry, clientReader, clientSalt, timeToCipher, keyErr := findAccessKey(clientConn, remoteIP(clientConn), h.ciphers)
	h.m.AddTCPCipherSearch(keyErr == nil, timeToCipher)
	if keyErr != nil {
		logger.Debugf("Failed to find a valid cipher after reading %v bytes: %v", proxyMetrics.ClientProxy, keyErr)
		const status = "ERR_CIPHER"
		return "", nil, onet.NewConnectionError(status, "Failed to find a valid cipher", keyErr)
	}
	var id string
	if cipherEntry != nil {
		id = cipherEntry.ID
	}

	// Check if the connection is a replay.
	isServerSalt := cipherEntry.SaltGenerator.IsServerSalt(clientSalt)
	// Only check the cache if findAccessKey succeeded and the salt is unrecognized.
	if isServerSalt || !h.replayCache.Add(cipherEntry.ID, clientSalt) {
		var status string
		if isServerSalt {
			status = "ERR_REPLAY_SERVER"
		} else {
			status = "ERR_REPLAY_CLIENT"
		}
		logger.Debugf(status+": %v sent %d bytes", clientConn.RemoteAddr(), proxyMetrics.ClientProxy)
		return id, nil, onet.NewConnectionError(status, "Replay detected", nil)
	}
	ssr := shadowsocks.NewReader(clientReader, cipherEntry.CryptoKey)
	ssw := shadowsocks.NewWriter(clientConn, cipherEntry.CryptoKey)
	ssw.SetSaltGenerator(cipherEntry.SaltGenerator)
	return id, transport.WrapConn(clientConn, ssr, ssw), nil
}

func getProxyRequest(clientConn transport.StreamConn) (string, error) {
	// TODO(fortuna): Use Shadowsocks proxy, HTTP CONNECT or SOCKS5 based on first byte:
	// case 1, 3 or 4: Shadowsocks (address type)
	// case 5: SOCKS5 (protocol version)
	// case "C": HTTP CONNECT (first char of method)
	tgtAddr, err := socks.ReadAddr(clientConn)
	if err != nil {
		return "", err
	}
	return tgtAddr.String(), nil
}

func proxyConnection(ctx context.Context, dialer transport.StreamDialer, tgtAddr string, clientConn transport.StreamConn) *onet.ConnectionError {
	tgtConn, dialErr := dialer.DialStream(ctx, tgtAddr)
	if dialErr != nil {
		// We don't drain so dial errors and invalid addresses are communicated quickly.
		return ensureConnectionError(dialErr, "ERR_CONNECT", "Failed to connect to target")
	}
	defer tgtConn.Close()
	logger.Debugf("proxy %s <-> %s", clientConn.RemoteAddr().String(), tgtConn.RemoteAddr().String())

	fromClientErrCh := make(chan error)
	go func() {
		_, fromClientErr := io.Copy(tgtConn, clientConn)
		if fromClientErr != nil {
			// Drain to prevent a close in the case of a cipher error.
			io.Copy(io.Discard, clientConn)
		}
		clientConn.CloseRead()
		// Send FIN to target.
		// We must do this after the drain is completed, otherwise the target will close its
		// connection with the proxy, which will, in turn, close the connection with the client.
		tgtConn.CloseWrite()
		fromClientErrCh <- fromClientErr
	}()
	_, fromTargetErr := io.Copy(clientConn, tgtConn)
	// Send FIN to client.
	clientConn.CloseWrite()
	tgtConn.CloseRead()

	fromClientErr := <-fromClientErrCh
	if fromClientErr != nil {
		return onet.NewConnectionError("ERR_RELAY_CLIENT", "Failed to relay traffic from client", fromClientErr)
	}
	if fromTargetErr != nil {
		return onet.NewConnectionError("ERR_RELAY_TARGET", "Failed to relay traffic from target", fromTargetErr)
	}
	return nil
}

func (h *tcpHandler) handleConnection(ctx context.Context, listenerPort int, outerConn transport.StreamConn, proxyMetrics *metrics.ProxyMetrics) (string, *onet.ConnectionError) {
	// Set a deadline to receive the address to the target.
	readDeadline := time.Now().Add(h.readTimeout)
	if deadline, ok := ctx.Deadline(); ok {
		outerConn.SetDeadline(deadline)
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
	}
	outerConn.SetReadDeadline(readDeadline)

	id, innerConn, authErr := h.authenticate(outerConn, proxyMetrics)
	if authErr != nil {
		// Drain to protect against probing attacks.
		h.absorbProbe(listenerPort, outerConn, authErr.Status, proxyMetrics)
		return id, authErr
	}

	// Read target address and dial it.
	tgtAddr, err := getProxyRequest(innerConn)
	// Clear the deadline for the target address
	outerConn.SetReadDeadline(time.Time{})
	if err != nil {
		// Drain to prevent a close on cipher error.
		io.Copy(io.Discard, outerConn)
		return id, onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", err)
	}

	dialer := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		tgtConn, err := h.dialer.DialStream(ctx, tgtAddr)
		if err != nil {
			return nil, err
		}
		tgtConn = metrics.MeasureConn(tgtConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy)
		return tgtConn, nil
	})
	return id, proxyConnection(ctx, dialer, tgtAddr, innerConn)
}

// Keep the connection open until we hit the authentication deadline to protect against probing attacks
// `proxyMetrics` is a pointer because its value is being mutated by `clientConn`.
func (h *tcpHandler) absorbProbe(listenerPort int, clientConn io.ReadCloser, status string, proxyMetrics *metrics.ProxyMetrics) {
	// This line updates proxyMetrics.ClientProxy before it's used in AddTCPProbe.
	_, drainErr := io.Copy(io.Discard, clientConn) // drain socket
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

// NoOpTCPMetrics is a [TCPMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpTCPMetrics struct{}

var _ TCPMetrics = (*NoOpTCPMetrics)(nil)

func (m *NoOpTCPMetrics) AddClosedTCPConnection(clientInfo ipinfo.IPInfo, accessKey, status string, data metrics.ProxyMetrics, duration time.Duration) {
}
func (m *NoOpTCPMetrics) GetIPInfo(net.IP) (ipinfo.IPInfo, error) {
	return ipinfo.IPInfo{}, nil
}
func (m *NoOpTCPMetrics) AddOpenTCPConnection(clientInfo ipinfo.IPInfo) {}
func (m *NoOpTCPMetrics) AddTCPProbe(status, drainResult string, port int, clientProxyBytes int64) {
}
func (m *NoOpTCPMetrics) AddTCPCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {}
