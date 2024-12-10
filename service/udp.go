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
	"github.com/shadowsocks/go-shadowsocks2/socks"

	"github.com/Jigsaw-Code/outline-ss-server/internal/slicepool"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
)

// NATMetrics is used to report NAT related metrics.
type NATMetrics interface {
	AddNATEntry()
	RemoveNATEntry()
}

// UDPAssocationMetrics is used to report metrics on UDP associations.
type UDPAssocationMetrics interface {
	AddAuthenticated(accessKey string)
	AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64)
	AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64)
	AddClosed()
}

// Max UDP buffer size for the server code.
const serverUDPBufferSize = 64 * 1024

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

type associationHandler struct {
	logger *slog.Logger
	// bufPool stores the byte slices used for reading and decrypting packets.
	bufPool           slicepool.Pool
	ciphers           CipherList
	ssm               ShadowsocksConnMetrics
	targetIPValidator onet.TargetIPValidator
	targetConnFactory func() (net.PacketConn, error)
}

var _ AssociationHandler = (*associationHandler)(nil)

// NewAssociationHandler creates an AssociationHandler
func NewAssociationHandler(natTimeout time.Duration, cipherList CipherList, ssMetrics ShadowsocksConnMetrics) AssociationHandler {
	if ssMetrics == nil {
		ssMetrics = &NoOpShadowsocksConnMetrics{}
	}
	return &associationHandler{
		logger:            noopLogger(),
		bufPool:           slicepool.MakePool(serverUDPBufferSize),
		ciphers:           cipherList,
		ssm:               ssMetrics,
		targetIPValidator: onet.RequirePublicIP,
		targetConnFactory: func() (net.PacketConn, error) {
			pc, err := net.ListenPacket("udp", "")
			if err != nil {
				return nil, fmt.Errorf("failed to create UDP socket: %v", err)
			}
			return &timedPacketConn{
				PacketConn:     pc,
				defaultTimeout: natTimeout,
			}, nil
		},
	}
}

// AssociationHandler is a handler that handles UDP assocations.
type AssociationHandler interface {
	Handle(association net.Conn, metrics UDPAssocationMetrics)
	// SetLogger sets the logger used to log messages. Uses a no-op logger if nil.
	SetLogger(l *slog.Logger)
	// SetTargetIPValidator sets the function to be used to validate the target IP addresses.
	SetTargetIPValidator(targetIPValidator onet.TargetIPValidator)
	// SetTargetConnFactory sets the function to be used to create new target connections.
	SetTargetConnFactory(factory func() (net.PacketConn, error))
}

func (h *associationHandler) SetLogger(l *slog.Logger) {
	if l == nil {
		l = noopLogger()
	}
	h.logger = l
}

func (h *associationHandler) SetTargetIPValidator(targetIPValidator onet.TargetIPValidator) {
	h.targetIPValidator = targetIPValidator
}

func (h *associationHandler) SetTargetConnFactory(factory func() (net.PacketConn, error)) {
	h.targetConnFactory = factory
}

type AssocationHandleFunc func(assocation net.Conn)

// PacketServe listens for UDP packets on the provided [net.PacketConn], creates
// creates and manages NAT associations, and invokes the provided `handle`
// function for each association. It uses a NAT map to track active associations
// and handles their lifecycle.
func PacketServe(clientConn net.PacketConn, handle AssocationHandleFunc, metrics NATMetrics) {
	nm := newNATmap()
	defer nm.Close()
	buffer := make([]byte, serverUDPBufferSize)
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

		// TODO: Include server address in the NAT key as well.
		conn := nm.Get(addr.String())
		if conn == nil {
			conn = &natconn{
				PacketConn: clientConn,
				raddr: addr,
				readBufCh: make(chan []byte, 1),
				bytesReadCh: make(chan int, 1),
			}
			metrics.AddNATEntry()
			deleteEntry := nm.Add(addr, conn)
			go func(conn *natconn) {
				defer func() {
					conn.Close()
					deleteEntry()
					metrics.RemoveNATEntry()
				}()
				handle(conn)
			}(conn)
		}
		readBuf, ok := <-conn.readBufCh
		if !ok {
			continue
		}
		copy(readBuf, pkt)
		conn.bytesReadCh <- n
	}
}

// natconn adapts a [net.Conn] to provide a synchronized reading mechanism for NAT traversal.
//
// The application provides the buffer to `Read()` (BYOB: Bring Your Own Buffer!)
// which minimizes buffer allocations and copying.
type natconn struct {
	net.PacketConn
	raddr net.Addr

	// readBufCh provides a buffer to copy incoming packet data into.
	readBufCh chan []byte 

	// bytesReadCh is used to signal the availability of new data and carries
	// the length of the received packet.
	bytesReadCh chan int
}

var _ net.Conn = (*natconn)(nil)

func (c *natconn) Read(p []byte) (int, error) {
	c.readBufCh <- p
	n, ok := <-c.bytesReadCh
	if !ok {
		return 0, net.ErrClosed
	}
	return n, nil
}

func (c *natconn) Write(b []byte) (n int, err error) {
	return c.PacketConn.WriteTo(b, c.raddr)
}

func (c *natconn) Close() error {
	close(c.readBufCh)
	close(c.bytesReadCh)
	c.PacketConn.Close()
	return nil
}

func (c *natconn) RemoteAddr() net.Addr {
	return c.raddr
}


func (h *associationHandler) Handle(clientAssociation net.Conn, connMetrics UDPAssocationMetrics) {
	if connMetrics == nil {
		connMetrics = &NoOpUDPAssocationMetrics{}
	}

	targetConn, err := h.targetConnFactory()
	if err != nil {
		slog.Error("UDP: failed to create target connection", slog.Any("err", err))
		return
	}

	cipherLazySlice := h.bufPool.LazySlice()
	cipherBuf := cipherLazySlice.Acquire()
	defer cipherLazySlice.Release()

	textLazySlice := h.bufPool.LazySlice()

	var cryptoKey *shadowsocks.EncryptionKey
	var proxyTargetBytes int
	for {
		clientProxyBytes, err := clientAssociation.Read(cipherBuf)
		if errors.Is(err, net.ErrClosed) {
			cipherLazySlice.Release()
			return
		}
		debugUDPAddr(h.logger, "Outbound packet.", clientAssociation.RemoteAddr(), slog.Int("bytes", clientProxyBytes))
		
		connError := func() *onet.ConnectionError {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Panic in UDP loop. Continuing to listen.", "err", r)
					debug.PrintStack()
				}
				slog.LogAttrs(nil, slog.LevelDebug, "UDP: Done", slog.String("address", clientAssociation.RemoteAddr().String()))
			}()

			cipherData := cipherBuf[:clientProxyBytes]
			var textData []byte
			var err error

			if cryptoKey == nil {
				ip := clientAssociation.RemoteAddr().(*net.UDPAddr).AddrPort().Addr()
				var keyID string
				var cryptoKey *shadowsocks.EncryptionKey
				textBuf := textLazySlice.Acquire()
				unpackStart := time.Now()
				textData, keyID, cryptoKey, err = findAccessKeyUDP(ip, textBuf, cipherData, h.ciphers, h.logger)
				timeToCipher := time.Since(unpackStart)
				textLazySlice.Release()
				h.ssm.AddCipherSearch(err == nil, timeToCipher)

				if err != nil {
					return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack initial packet", err)
				}

				connMetrics.AddAuthenticated(keyID)
				go func() {
					defer connMetrics.AddClosed()
					timedCopy(clientAssociation, targetConn, cryptoKey, connMetrics, h.logger)
					targetConn.Close()
				}()

			} else {
				unpackStart := time.Now()
				textData, err = shadowsocks.Unpack(nil, cipherData, cryptoKey)
				timeToCipher := time.Since(unpackStart)
				h.ssm.AddCipherSearch(err == nil, timeToCipher)

				if err != nil {
					return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack data from client", err)
				}
			}

			payload, tgtUDPAddr, onetErr := h.validatePacket(textData)
			if onetErr != nil {
				return onetErr
			}

			debugUDPAddr(h.logger, "Proxy exit.", clientAssociation.RemoteAddr(), slog.Any("target", targetConn.LocalAddr()))
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
		connMetrics.AddPacketFromClient(status, int64(clientProxyBytes), int64(proxyTargetBytes))
	}
}

// Given the decrypted contents of a UDP packet, return
// the payload and the destination address, or an error if
// this packet cannot or should not be forwarded.
func (h *associationHandler) validatePacket(textData []byte) ([]byte, *net.UDPAddr, *onet.ConnectionError) {
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

type timedPacketConn struct {
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

func (c *timedPacketConn) onWrite(addr net.Addr) {
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

func (c *timedPacketConn) onRead(addr net.Addr) {
	c.fastClose.Do(func() {
		if isDNS(addr) {
			// The next ReadFrom() should time out immediately.
			c.SetReadDeadline(time.Now())
		}
	})
}

func (c *timedPacketConn) WriteTo(buf []byte, dst net.Addr) (int, error) {
	c.onWrite(dst)
	return c.PacketConn.WriteTo(buf, dst)
}

func (c *timedPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
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

// Get the maximum length of the shadowsocks address header by parsing
// and serializing an IPv6 address from the example range.
var maxAddrLen int = len(socks.ParseAddr("[2001:db8::1]:12345"))

// copy from target to client until read timeout
func timedCopy(clientConn net.Conn, targetConn net.PacketConn, cryptoKey *shadowsocks.EncryptionKey, m UDPAssocationMetrics, l *slog.Logger) {
	// pkt is used for in-place encryption of downstream UDP packets, with the layout
	// [padding?][salt][address][body][tag][extra]
	// Padding is only used if the address is IPv4.
	pkt := make([]byte, serverUDPBufferSize)

	saltSize := cryptoKey.SaltSize()
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
			buf, err := shadowsocks.Pack(packBuf, plaintextBuf, cryptoKey) // Encrypt in-place
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
			l.LogAttrs(nil, slog.LevelDebug, "UDP: Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
			status = connError.Status
		}
		if expired {
			break
		}
		m.AddPacketFromTarget(status, int64(bodyLen), int64(proxyClientBytes))
	}
}

// NoOpUDPAssocationMetrics is a [UDPAssocationMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpUDPAssocationMetrics struct{}

var _ UDPAssocationMetrics = (*NoOpUDPAssocationMetrics)(nil)

func (m *NoOpUDPAssocationMetrics) AddAuthenticated(accessKey string) {}

func (m *NoOpUDPAssocationMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
}
func (m *NoOpUDPAssocationMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
}
func (m *NoOpUDPAssocationMetrics) AddClosed() {
}
