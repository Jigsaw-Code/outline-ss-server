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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// UDPConnMetrics is used to report metrics on UDP connections.
type UDPConnMetrics interface {
	AddAuthenticated(accessKey string)
	AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64)
	AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64)
	AddClosed()
}

// Max UDP buffer size for the server code.
const serverUDPBufferSize = 64 * 1024

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, serverUDPBufferSize)
	},
}

// Wrapper for slog.Debug during UDP proxying.
func debugUDP(l *slog.Logger, template string, cipherID string, attr slog.Attr) {
	// This is an optimization to reduce unnecessary allocations due to an interaction
	// between Go's inlining/escape analysis and varargs functions like slog.Debug.
	if l.Enabled(nil, slog.LevelDebug) {
		l.LogAttrs(nil, slog.LevelDebug, fmt.Sprintf("UDP: %s", template), slog.String("ID", cipherID), attr)
	}
}

func debugUDPAddr(l *slog.Logger, template string, addr net.Addr, attr slog.Attr) {
	if l.Enabled(nil, slog.LevelDebug) {
		l.LogAttrs(nil, slog.LevelDebug, fmt.Sprintf("UDP: %s", template), slog.String("address", addr.String()), attr)
	}
}

// Decrypts src into dst. It tries each cipher until it finds one that authenticates
// correctly. dst and src must not overlap.
func findAccessKeyUDP(clientIP netip.Addr, dst, src []byte, cipherList CipherList, l *slog.Logger) ([]byte, string, *shadowsocks.EncryptionKey, error) {
	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	// We snapshot the list because it may be modified while we use it.
	snapshot := cipherList.SnapshotForClientIP(clientIP)
	for ci, entry := range snapshot {
		id, cryptoKey := entry.Value.(*CipherEntry).ID, entry.Value.(*CipherEntry).CryptoKey
		buf, err := shadowsocks.Unpack(dst, src, cryptoKey)
		if err != nil {
			debugUDP(l, "Failed to unpack.", id, slog.Any("err", err))
			continue
		}
		debugUDP(l, "Found cipher.", id, slog.Int("index", ci))
		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.MarkUsedByClientIP(entry, clientIP)
		return buf, id, cryptoKey, nil
	}
	return nil, "", nil, errors.New("could not find valid UDP cipher")
}

type packetHandler struct {
	logger            *slog.Logger
	natTimeout        time.Duration
	ciphers           CipherList
	ssm               ShadowsocksConnMetrics
	targetIPValidator onet.TargetIPValidator
}

// NewPacketHandler creates a UDPService
func NewPacketHandler(natTimeout time.Duration, cipherList CipherList, ssMetrics ShadowsocksConnMetrics) PacketHandler {
	if ssMetrics == nil {
		ssMetrics = &NoOpShadowsocksConnMetrics{}
	}
	return &packetHandler{
		logger:            noopLogger(),
		natTimeout:        natTimeout,
		ciphers:           cipherList,
		ssm:               ssMetrics,
		targetIPValidator: onet.RequirePublicIP,
	}
}

// PacketHandler is a running UDP shadowsocks proxy that can be stopped.
type PacketHandler interface {
	Handle(conn net.Conn, connMetrics UDPConnMetrics)
	// SetLogger sets the logger used to log messages. Uses a no-op logger if nil.
	SetLogger(l *slog.Logger)
	// SetTargetIPValidator sets the function to be used to validate the target IP addresses.
	SetTargetIPValidator(targetIPValidator onet.TargetIPValidator)
}

func (h *packetHandler) SetLogger(l *slog.Logger) {
	if l == nil {
		l = noopLogger()
	}
	h.logger = l
}

func (h *packetHandler) SetTargetIPValidator(targetIPValidator onet.TargetIPValidator) {
	h.targetIPValidator = targetIPValidator
}

type PacketHandleFunc func(conn net.Conn)

// PacketServe listens for packets and calls `handle` to handle them until the connection
// returns [ErrClosed].
func PacketServe(clientConn net.PacketConn, handle PacketHandleFunc) {
	nm := newNATmap()
	defer nm.Close()
	for {
		buffer := bufferPool.Get().([]byte)
		defer bufferPool.Put(buffer)
		n, addr, err := clientConn.ReadFrom(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			slog.Warn("Failed to read from client. Continuing to listen.", "err", err)
			continue
		}
		pkt := buffer[:n]

		conn := nm.Get(addr.String())
		if conn == nil {
			conn = &natconn{
				Conn:   &packetConnWrapper{PacketConn: clientConn, raddr: addr},
				readCh: make(chan []byte, 1),
			}
			deleteEntry := nm.Add(addr, conn)
			go func(conn *natconn) {
				defer func() {
					conn.Close()
					deleteEntry()
				}()
				handle(conn)
			}(conn)
		}
		conn.readCh <- pkt
	}
}

type natconn struct {
	net.Conn
	readCh chan []byte
}

var _ net.Conn = (*natconn)(nil)

func (c *natconn) Read(p []byte) (int, error) {
	select {
	case pkt := <-c.readCh:
		if pkt == nil {
			break
		}
		return copy(p, pkt), nil
	case <-time.After(30 * time.Second):
		break
	}
	return 0, io.EOF
}

func (c *natconn) Close() error {
	close(c.readCh)
	c.Conn.Close()
	return nil
}

func (h *packetHandler) Handle(clientConn net.Conn, connMetrics UDPConnMetrics) {
	if connMetrics == nil {
		connMetrics = &NoOpUDPConnMetrics{}
	}

	targetConn, err := newTargetConn(h.natTimeout)
	if err != nil {
		slog.Error("UDP: failed to create target connection", slog.Any("err", err))
		return
	}

	var cryptoKey *shadowsocks.EncryptionKey
	var proxyTargetBytes int
	cipherBuf := make([]byte, serverUDPBufferSize)
	textBuf := make([]byte, serverUDPBufferSize)
	for {
		clientProxyBytes, err := clientConn.Read(cipherBuf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		debugUDPAddr(h.logger, "Outbound packet.", clientConn.RemoteAddr(), slog.Int("bytes", clientProxyBytes))
		pkt := cipherBuf[:clientProxyBytes]

		connError := func() *onet.ConnectionError {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Panic in UDP loop. Continuing to listen.", "err", r)
					debug.PrintStack()
				}
				slog.LogAttrs(nil, slog.LevelDebug, "UDP: Done", slog.String("address", clientConn.RemoteAddr().String()))
			}()

			var err error
			if cryptoKey == nil {
				ip := clientConn.RemoteAddr().(*net.UDPAddr).AddrPort().Addr()
				var keyID string
				var cryptoKey *shadowsocks.EncryptionKey
				unpackStart := time.Now()
				pkt, keyID, cryptoKey, err = findAccessKeyUDP(ip, textBuf, pkt, h.ciphers, h.logger)
				timeToCipher := time.Since(unpackStart)
				h.ssm.AddCipherSearch(err == nil, timeToCipher)
				wrappedClientConn := shadowsocks.NewPacketConn(clientConn, cryptoKey)
				clientConn = &packetConnWrapper{
					PacketConn: wrappedClientConn,
					raddr:      clientConn.RemoteAddr(),
				}
				connMetrics.AddAuthenticated(keyID)
				go func() {
					defer connMetrics.AddClosed()
					timedCopy(clientConn.RemoteAddr(), wrappedClientConn, targetConn, connMetrics, h.logger)
				}()
			}
			if err != nil {
				return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack packet from client", err)
			}

			payload, tgtUDPAddr, onetErr := h.validatePacket(pkt)
			if onetErr != nil {
				return onetErr
			}

			debugUDPAddr(h.logger, "Proxy exit.", clientConn.RemoteAddr(), slog.Any("target", targetConn.LocalAddr()))
			proxyTargetBytes, err = targetConn.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to target", err)
			}
			return nil
		}()

		status := "OK"
		if connError != nil {
			h.logger.LogAttrs(nil, slog.LevelDebug, "UDP: Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
			status = connError.Status
		}
		connMetrics.AddPacketFromClient(status, int64(len(pkt)), int64(proxyTargetBytes))
	}
}

// Given the decrypted contents of a UDP packet, return
// the payload and the destination address, or an error if
// this packet cannot or should not be forwarded.
func (h *packetHandler) validatePacket(textData []byte) ([]byte, *net.UDPAddr, *onet.ConnectionError) {
	tgtAddr := socks.SplitAddr(textData)
	if tgtAddr == nil {
		return nil, nil, onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", nil)
	}

	tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
	if err != nil {
		return nil, nil, onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr), err)
	}
	if err := h.targetIPValidator(tgtUDPAddr.IP); err != nil {
		return nil, nil, ensureConnectionError(err, "ERR_ADDRESS_INVALID", "invalid address")
	}

	payload := textData[len(tgtAddr):]
	return payload, tgtUDPAddr, nil
}

func isDNS(addr net.Addr) bool {
	_, port, _ := net.SplitHostPort(addr.String())
	return port == "53"
}

type targetconn struct {
	net.PacketConn
	// Connection timeout to apply for non-DNS packets.
	defaultTimeout time.Duration
	// Current read deadline of PacketConn.  Used to avoid decreasing the
	// deadline.  Initially zero.
	readDeadline time.Time
	// If the connection has only sent one DNS query, it will close
	// if it receives a DNS response.
	fastClose sync.Once
}

func newTargetConn(defaultTimeout time.Duration) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %v", err)
	}
	return &targetconn{
		PacketConn:     pc,
		defaultTimeout: defaultTimeout,
	}, nil
}

func (c *targetconn) onWrite(addr net.Addr) {
	// Fast close is only allowed if there has been exactly one write,
	// and it was a DNS query.
	isDNS := isDNS(addr)
	isFirstWrite := c.readDeadline.IsZero()
	if !isDNS || !isFirstWrite {
		// Disable fast close.  (Idempotent.)
		c.fastClose.Do(func() {})
	}

	timeout := c.defaultTimeout
	if isDNS {
		// Shorten timeout as required by RFC 5452 Section 10.
		timeout = 17 * time.Second
	}

	newDeadline := time.Now().Add(timeout)
	if newDeadline.After(c.readDeadline) {
		c.readDeadline = newDeadline
		c.SetReadDeadline(newDeadline)
	}
}

func (c *targetconn) onRead(addr net.Addr) {
	c.fastClose.Do(func() {
		if isDNS(addr) {
			// The next ReadFrom() should time out immediately.
			c.SetReadDeadline(time.Now())
		}
	})
}

func (c *targetconn) WriteTo(buf []byte, dst net.Addr) (int, error) {
	c.onWrite(dst)
	return c.PacketConn.WriteTo(buf, dst)
}

func (c *targetconn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err == nil {
		c.onRead(addr)
	}
	return n, addr, err
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	keyConn map[string]*natconn
}

func newNATmap() *natmap {
	return &natmap{keyConn: make(map[string]*natconn)}
}

func (m *natmap) Get(key string) *natconn {
	m.RLock()
	defer m.RUnlock()
	return m.keyConn[key]
}

func (m *natmap) set(key string, pc *natconn) {
	m.Lock()
	defer m.Unlock()

	m.keyConn[key] = pc
	return
}

func (m *natmap) del(key string) *natconn {
	m.Lock()
	defer m.Unlock()

	entry, ok := m.keyConn[key]
	if ok {
		delete(m.keyConn, key)
		return entry
	}
	return nil
}

// Add adds a new UDP NAT entry to the natmap and returns a closure to delete
// the entry.
func (m *natmap) Add(addr net.Addr, pc *natconn) func() {
	key := addr.String()
	m.set(key, pc)
	return func() {
		m.del(key)
	}
}

func (m *natmap) Close() error {
	m.Lock()
	defer m.Unlock()

	var err error
	now := time.Now()
	for _, pc := range m.keyConn {
		if e := pc.SetReadDeadline(now); e != nil {
			err = e
		}
	}
	return err
}

// packetConnWrapper wraps a [net.PacketConn] and provides a [net.Conn] interface
// with a given remote address.
type packetConnWrapper struct {
	net.PacketConn
	raddr net.Addr
}

var _ net.Conn = (*packetConnWrapper)(nil)

// ReadFrom reads data from the connection.
func (pcw *packetConnWrapper) Read(b []byte) (n int, err error) {
	n, _, err = pcw.PacketConn.ReadFrom(b)
	return
}

// WriteTo writes data to the connection.
func (pcw *packetConnWrapper) Write(b []byte) (n int, err error) {
	return pcw.PacketConn.WriteTo(b, pcw.raddr)
}

// RemoteAddr returns the remote network address.
func (pcw *packetConnWrapper) RemoteAddr() net.Addr {
	return pcw.raddr
}

// copy from target to client until read timeout
func timedCopy(clientAddr net.Addr, clientConn net.PacketConn, targetConn net.PacketConn, m UDPConnMetrics, l *slog.Logger) {
	buffer := make([]byte, serverUDPBufferSize)

	expired := false
	for {
		var bodyLen, proxyClientBytes int
		connError := func() (connError *onet.ConnectionError) {
			n, raddr, err := targetConn.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						expired = true
						return nil
					}
				}
				return onet.NewConnectionError("ERR_READ", "Failed to read from target", err)
			}
			payload := buffer[:n]
			debugUDPAddr(l, "Got response.", clientAddr, slog.Any("target", raddr))
			proxyClientBytes, err = clientConn.WriteTo(payload, raddr)
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to client", err)
			}
			return nil
		}()
		status := "OK"
		if connError != nil {
			l.LogAttrs(nil, slog.LevelDebug, "UDP: Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
			status = connError.Status
		}
		if expired {
			break
		}
		m.AddPacketFromTarget(status, int64(bodyLen), int64(proxyClientBytes))
	}
}

// NoOpUDPConnMetrics is a [UDPConnMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpUDPConnMetrics struct{}

var _ UDPConnMetrics = (*NoOpUDPConnMetrics)(nil)

func (m *NoOpUDPConnMetrics) AddAuthenticated(accessKey string) {}

func (m *NoOpUDPConnMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
}
func (m *NoOpUDPConnMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
}
func (m *NoOpUDPConnMetrics) AddClosed() {
}