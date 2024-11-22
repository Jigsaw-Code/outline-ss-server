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
	AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64)
	AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64)
	RemoveNatEntry()
}

type UDPMetrics interface {
	AddUDPNatEntry(clientAddr net.Addr, accessKey string) UDPConnMetrics
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
	nm                *natmap
	ssm               ShadowsocksConnMetrics
	targetIPValidator onet.TargetIPValidator
}

// NewPacketHandler creates a UDPService
func NewPacketHandler(natTimeout time.Duration, cipherList CipherList, m UDPMetrics, ssMetrics ShadowsocksConnMetrics) PacketHandler {
	if m == nil {
		m = &NoOpUDPMetrics{}
	}
	if ssMetrics == nil {
		ssMetrics = &NoOpShadowsocksConnMetrics{}
	}
	nm := newNATmap(natTimeout, m, noopLogger())
	return &packetHandler{
		logger:            noopLogger(),
		ciphers:           cipherList,
		nm:                nm,
		ssm:               ssMetrics,
		targetIPValidator: onet.RequirePublicIP,
	}
}

// PacketHandler is a running UDP shadowsocks proxy that can be stopped.
type PacketHandler interface {
	Handle(conn net.Conn)
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
	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	for {
		n, addr, err := clientConn.ReadFrom(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			slog.Warn("Failed to read from client. Continuing to listen.", "err", err)
			continue
		}
		pkt := buffer[:n]
		conn := &packetConn{
			PacketConn: clientConn,
			readCh:     make(chan []byte, 1),
			raddr:      addr,
		}

		go func(conn *packetConn) {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Panic in UDP loop. Continuing to listen.", "err", r)
					debug.PrintStack()
				}
			}()
			handle(conn)
		}(conn)
		conn.readCh <- pkt
	}
}

type packetConn struct {
	net.PacketConn
	readCh chan []byte
	raddr  net.Addr
}

var _ net.Conn = (*packetConn)(nil)

func (pc *packetConn) Read(p []byte) (int, error) {
	data := <-pc.readCh
	return copy(p, data), nil
}

func (pc *packetConn) Write(b []byte) (n int, err error) {
	return pc.PacketConn.WriteTo(b, pc.raddr)
}

func (pc *packetConn) RemoteAddr() net.Addr {
	return pc.raddr
}

func (h *packetHandler) Handle(clientConn net.Conn) {
	cipherBuf := bufferPool.Get().([]byte)
	defer bufferPool.Put(cipherBuf)
	clientProxyBytes, err := clientConn.Read(cipherBuf)
	if errors.Is(err, net.ErrClosed) {
		return
	}
	debugUDPAddr(h.logger, "Outbound packet.", clientConn.RemoteAddr(), slog.Int("bytes", clientProxyBytes))
	pkt := cipherBuf[:clientProxyBytes]

	var proxyTargetBytes int
	var targetConn *natconn

	connError := func() (connError *onet.ConnectionError) {
		defer slog.LogAttrs(nil, slog.LevelDebug, "UDP: Done", slog.String("address", clientConn.RemoteAddr().String()))

		var payload []byte
		var tgtUDPAddr *net.UDPAddr
		targetConn = h.nm.Get(clientConn.RemoteAddr().String())
		if targetConn == nil {
			ip := clientConn.RemoteAddr().(*net.UDPAddr).AddrPort().Addr()
			var textData []byte
			var cryptoKey *shadowsocks.EncryptionKey
			textBuf := bufferPool.Get().([]byte)
			defer bufferPool.Put(textBuf)
			unpackStart := time.Now()
			textData, keyID, cryptoKey, err := findAccessKeyUDP(ip, textBuf, pkt, h.ciphers, h.logger)
			timeToCipher := time.Since(unpackStart)
			h.ssm.AddCipherSearch(err == nil, timeToCipher)

			if err != nil {
				return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack initial packet", err)
			}

			var onetErr *onet.ConnectionError
			if payload, tgtUDPAddr, onetErr = h.validatePacket(textData); onetErr != nil {
				return onetErr
			}

			udpConn, err := net.ListenPacket("udp", "")
			if err != nil {
				return onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to create UDP socket", err)
			}
			targetConn = h.nm.Add(clientConn, udpConn, cryptoKey, keyID)
		} else {
			unpackStart := time.Now()
			textData, err := shadowsocks.Unpack(nil, pkt, targetConn.cryptoKey)
			timeToCipher := time.Since(unpackStart)
			h.ssm.AddCipherSearch(err == nil, timeToCipher)

			if err != nil {
				return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack data from client", err)
			}

			var onetErr *onet.ConnectionError
			if payload, tgtUDPAddr, onetErr = h.validatePacket(textData); onetErr != nil {
				return onetErr
			}
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
		slog.LogAttrs(nil, slog.LevelDebug, "UDP: Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
		status = connError.Status
	}
	if targetConn != nil {
		targetConn.metrics.AddPacketFromClient(status, int64(len(pkt)), int64(proxyTargetBytes))
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

type natconn struct {
	net.PacketConn
	cryptoKey *shadowsocks.EncryptionKey
	metrics   UDPConnMetrics
	// NAT timeout to apply for non-DNS packets.
	defaultTimeout time.Duration
	// Current read deadline of PacketConn.  Used to avoid decreasing the
	// deadline.  Initially zero.
	readDeadline time.Time
	// If the connection has only sent one DNS query, it will close
	// if it receives a DNS response.
	fastClose sync.Once
}

func (c *natconn) onWrite(addr net.Addr) {
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

func (c *natconn) onRead(addr net.Addr) {
	c.fastClose.Do(func() {
		if isDNS(addr) {
			// The next ReadFrom() should time out immediately.
			c.SetReadDeadline(time.Now())
		}
	})
}

func (c *natconn) WriteTo(buf []byte, dst net.Addr) (int, error) {
	c.onWrite(dst)
	return c.PacketConn.WriteTo(buf, dst)
}

func (c *natconn) ReadFrom(buf []byte) (int, net.Addr, error) {
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
	logger  *slog.Logger
	timeout time.Duration
	metrics UDPMetrics
}

func newNATmap(timeout time.Duration, sm UDPMetrics, l *slog.Logger) *natmap {
	m := &natmap{logger: l, metrics: sm}
	m.keyConn = make(map[string]*natconn)
	m.timeout = timeout
	return m
}

func (m *natmap) Get(key string) *natconn {
	m.RLock()
	defer m.RUnlock()
	return m.keyConn[key]
}

func (m *natmap) set(key string, pc net.PacketConn, cryptoKey *shadowsocks.EncryptionKey, connMetrics UDPConnMetrics) *natconn {
	entry := &natconn{
		PacketConn:     pc,
		cryptoKey:      cryptoKey,
		metrics:        connMetrics,
		defaultTimeout: m.timeout,
	}

	m.Lock()
	defer m.Unlock()

	m.keyConn[key] = entry
	return entry
}

func (m *natmap) del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	entry, ok := m.keyConn[key]
	if ok {
		delete(m.keyConn, key)
		return entry
	}
	return nil
}

func (m *natmap) Add(clientConn net.Conn, targetConn net.PacketConn, cryptoKey *shadowsocks.EncryptionKey, keyID string) *natconn {
	connMetrics := m.metrics.AddUDPNatEntry(clientConn.RemoteAddr(), keyID)
	entry := m.set(clientConn.RemoteAddr().String(), targetConn, cryptoKey, connMetrics)

	go func() {
		timedCopy(clientConn, entry, m.logger)
		connMetrics.RemoveNatEntry()
		if pc := m.del(clientConn.RemoteAddr().String()); pc != nil {
			pc.Close()
		}
	}()
	return entry
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

// Get the maximum length of the shadowsocks address header by parsing
// and serializing an IPv6 address from the example range.
var maxAddrLen int = len(socks.ParseAddr("[2001:db8::1]:12345"))

// copy from target to client until read timeout
func timedCopy(clientConn net.Conn, targetConn *natconn, l *slog.Logger) {
	// pkt is used for in-place encryption of downstream UDP packets, with the layout
	// [padding?][salt][address][body][tag][extra]
	// Padding is only used if the address is IPv4.
	pkt := make([]byte, serverUDPBufferSize)

	saltSize := targetConn.cryptoKey.SaltSize()
	// Leave enough room at the beginning of the packet for a max-length header (i.e. IPv6).
	bodyStart := saltSize + maxAddrLen

	expired := false
	for {
		var bodyLen, proxyClientBytes int
		connError := func() (connError *onet.ConnectionError) {
			var (
				raddr net.Addr
				err   error
			)
			// `readBuf` receives the plaintext body in `pkt`:
			// [padding?][salt][address][body][tag][unused]
			// |--     bodyStart     --|[      readBuf    ]
			readBuf := pkt[bodyStart:]
			bodyLen, raddr, err = targetConn.ReadFrom(readBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						expired = true
						return nil
					}
				}
				return onet.NewConnectionError("ERR_READ", "Failed to read from target", err)
			}

			debugUDPAddr(l, "Got response.", clientConn.RemoteAddr(), slog.Any("target", raddr))
			srcAddr := socks.ParseAddr(raddr.String())
			addrStart := bodyStart - len(srcAddr)
			// `plainTextBuf` concatenates the SOCKS address and body:
			// [padding?][salt][address][body][tag][unused]
			// |-- addrStart -|[plaintextBuf ]
			plaintextBuf := pkt[addrStart : bodyStart+bodyLen]
			copy(plaintextBuf, srcAddr)

			// saltStart is 0 if raddr is IPv6.
			saltStart := addrStart - saltSize
			// `packBuf` adds space for the salt and tag.
			// `buf` shows the space that was used.
			// [padding?][salt][address][body][tag][unused]
			//           [            packBuf             ]
			//           [          buf           ]
			packBuf := pkt[saltStart:]
			buf, err := shadowsocks.Pack(packBuf, plaintextBuf, targetConn.cryptoKey) // Encrypt in-place
			if err != nil {
				return onet.NewConnectionError("ERR_PACK", "Failed to pack data to client", err)
			}
			proxyClientBytes, err = clientConn.Write(buf)
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to client", err)
			}
			return nil
		}()
		status := "OK"
		if connError != nil {
			slog.LogAttrs(nil, slog.LevelDebug, "UDP: Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
			status = connError.Status
		}
		if expired {
			break
		}
		targetConn.metrics.AddPacketFromTarget(status, int64(bodyLen), int64(proxyClientBytes))
	}
}

// NoOpUDPConnMetrics is a [UDPConnMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpUDPConnMetrics struct{}

var _ UDPConnMetrics = (*NoOpUDPConnMetrics)(nil)

func (m *NoOpUDPConnMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
}
func (m *NoOpUDPConnMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
}
func (m *NoOpUDPConnMetrics) RemoveNatEntry() {}

// NoOpUDPMetrics is a [UDPMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpUDPMetrics struct{}

var _ UDPMetrics = (*NoOpUDPMetrics)(nil)

func (m *NoOpUDPMetrics) AddUDPNatEntry(clientAddr net.Addr, accessKey string) UDPConnMetrics {
	return &NoOpUDPConnMetrics{}
}
