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

// Buffer pool used for reading UDP packets.
var readBufPool = slicepool.MakePool(serverUDPBufferSize)

// Wrapper for slog.Debug during UDP proxying.
func debugUDP(l *slog.Logger, template string, attrs ...slog.Attr) {
	// This is an optimization to reduce unnecessary allocations due to an interaction
	// between Go's inlining/escape analysis and varargs functions like slog.Debug.
	if l.Enabled(nil, slog.LevelDebug) {
		l.LogAttrs(nil, slog.LevelDebug, fmt.Sprintf("UDP: %s", template), attrs...)
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
			debugUDP(l, "Failed to unpack.", slog.String("ID", id), slog.Any("err", err))
			continue
		}
		debugUDP(l, "Found cipher.", slog.String("ID", id), slog.Int("index", ci))
		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.MarkUsedByClientIP(entry, clientIP)
		return buf, id, cryptoKey, nil
	}
	return nil, "", nil, errors.New("could not find valid UDP cipher")
}

type packetHandler struct {
	logger *slog.Logger
	// bufPool stores the byte slices used for reading and decrypting packets.
	bufPool           slicepool.Pool
	ciphers           CipherList
	ssm               ShadowsocksConnMetrics
	targetIPValidator onet.TargetIPValidator
	targetConnFactory func() (net.PacketConn, error)
}

var _ PacketHandler = (*packetHandler)(nil)

// NewPacketHandler creates an PacketHandler
func NewPacketHandler(natTimeout time.Duration, cipherList CipherList, ssMetrics ShadowsocksConnMetrics) PacketHandler {
	if ssMetrics == nil {
		ssMetrics = &NoOpShadowsocksConnMetrics{}
	}
	return &packetHandler{
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

// PacketHandler is a handler that handles UDP assocations.
type PacketHandler interface {
	// SetLogger sets the logger used to log messages. Uses a no-op logger if nil.
	SetLogger(l *slog.Logger)
	// SetTargetIPValidator sets the function to be used to validate the target IP addresses.
	SetTargetIPValidator(targetIPValidator onet.TargetIPValidator)
	// SetTargetConnFactory sets the function to be used to create new target connections.
	SetTargetConnFactory(factory func() (net.PacketConn, error))
	// NewAssociation creates a new Association instance.
	NewAssociation(conn net.Conn, connMetrics UDPAssocationMetrics) (Association, error)
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

func (h *packetHandler) SetTargetConnFactory(factory func() (net.PacketConn, error)) {
	h.targetConnFactory = factory
}

func (h *packetHandler) NewAssociation(conn net.Conn, m UDPAssocationMetrics) (Association, error) {
	if m == nil {
		m = &NoOpUDPAssocationMetrics{}
	}

	// Create the target connection
	targetConn, err := h.targetConnFactory()
	if err != nil {
		return nil, fmt.Errorf("failed to create target connection: %w", err)
	}

	return &association{
		Conn:              conn,
		m:                 m,
		targetConn:        targetConn,
		logger:            h.logger.With(slog.Any("client", conn.RemoteAddr()), slog.Any("ltarget", targetConn.LocalAddr())),
		bufPool:           &h.bufPool,
		ciphers:           h.ciphers,
		ssm:               h.ssm,
		targetIPValidator: h.targetIPValidator,
		doneCh:            make(chan struct{}),
	}, nil
}

type NewAssociationFunc func(conn net.Conn) (Association, error)

// PacketServe listens for UDP packets on the provided [net.PacketConn], creates
// creates and manages NAT associations, and invokes the provided `handle`
// function for each association. It uses a NAT map to track active associations
// and handles their lifecycle.
func PacketServe(clientConn net.PacketConn, newAssociation NewAssociationFunc, metrics NATMetrics) {
	nm := newNATmap()
	defer nm.Close()

	for {
		lazySlice := readBufPool.LazySlice()
		buffer := lazySlice.Acquire()

		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Panic in UDP loop. Continuing to listen.", "err", r)
					debug.PrintStack()
					lazySlice.Release()
				}
			}()
			n, addr, err := clientConn.ReadFrom(buffer)
			if err != nil {
				lazySlice.Release()
				if errors.Is(err, net.ErrClosed) {
					return
				}
				slog.Warn("Failed to read from client. Continuing to listen.", "err", err)
				return
			}
			pkt := buffer[:n]

			// TODO(#19): Include server address in the NAT key as well.
			assoc := nm.Get(addr.String())
			if assoc == nil {
				conn := &natconn{PacketConn: clientConn, raddr: addr}
				assoc, err = newAssociation(conn)
				if err != nil {
					slog.Error("Failed to handle association", slog.Any("err", err))
					return
				}

				metrics.AddNATEntry()
				nm.Add(addr.String(), assoc)
			}
			select {
			case <-assoc.Done():
				lazySlice.Release()
				metrics.RemoveNATEntry()
				nm.Del(addr.String())
			default:
				go assoc.HandlePacket(pkt, lazySlice)
			}
		}()
	}
}

// natconn wraps a [net.PacketConn] with an address into a [net.Conn].
type natconn struct {
	net.PacketConn
	raddr net.Addr
}

var _ net.Conn = (*natconn)(nil)

func (c *natconn) Read(p []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(p)
	return n, err
}

func (c *natconn) Write(b []byte) (n int, err error) {
	return c.PacketConn.WriteTo(b, c.raddr)
}

func (c *natconn) RemoteAddr() net.Addr {
	return c.raddr
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
	associations map[string]Association
}

func newNATmap() *natmap {
	return &natmap{associations: make(map[string]Association)}
}

func (m *natmap) Get(clientAddr string) Association {
	m.RLock()
	defer m.RUnlock()
	return m.associations[clientAddr]
}

func (m *natmap) Del(clientAddr string) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.associations[clientAddr]; ok {
		delete(m.associations, clientAddr)
	}
}

// Add adds a new UDP NAT entry to the natmap and returns a closure to delete
// the entry.
func (m *natmap) Add(clientAddr string, assoc Association) {
	m.Lock()
	defer m.Unlock()

	m.associations[clientAddr] = assoc
}

func (m *natmap) Close() error {
	m.Lock()
	defer m.Unlock()

	var err error
	for _, assoc := range m.associations {
		if e := assoc.Close(); e != nil {
			err = e
		}
	}
	return err
}

// Association represents a UDP association that handles incoming packets
// and forwards them to a target connection.
type Association interface {
	// Handle reads data from the given connection and handles incoming packets.
	Handle(conn net.Conn)

	// HandlePacket processes a single incoming packet.
	//
	// pkt contains the raw packet data.
	// lazySlice is the LazySlice that holds the pkt buffer, which should be
	// released after the packet is processed.
	HandlePacket(pkt []byte, lazySlice slicepool.LazySlice)

	// Done returns a channel that is closed when the association is closed.
	Done() <-chan struct{}

	// Close closes the association and releases any associated resources.
	Close() error
}

type association struct {
	net.Conn
	raddr             net.UDPAddr
	m                 UDPAssocationMetrics
	logger            *slog.Logger
	targetConn        net.PacketConn
	cryptoKey         *shadowsocks.EncryptionKey
	bufPool           *slicepool.Pool
	ciphers           CipherList
	ssm               ShadowsocksConnMetrics
	targetIPValidator onet.TargetIPValidator
	doneCh            chan struct{}
	findAccessKeyOnce sync.Once
}

var _ Association = (*association)(nil)

func (a *association) debugLog(template string, attrs ...slog.Attr) {
	debugUDP(a.logger, template, attrs...)
}

// Given the decrypted contents of a UDP packet, return
// the payload and the destination address, or an error if
// this packet cannot or should not be forwarded.
func (a *association) validatePacket(textData []byte) ([]byte, *net.UDPAddr, *onet.ConnectionError) {
	tgtAddr := socks.SplitAddr(textData)
	if tgtAddr == nil {
		return nil, nil, onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", nil)
	}

	tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
	if err != nil {
		return nil, nil, onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", tgtAddr), err)
	}
	if err := a.targetIPValidator(tgtUDPAddr.IP); err != nil {
		return nil, nil, ensureConnectionError(err, "ERR_ADDRESS_INVALID", "invalid address")
	}

	payload := textData[len(tgtAddr):]
	return payload, tgtUDPAddr, nil
}

func (a *association) Handle(conn net.Conn) {
	for {
		lazySlice := a.bufPool.LazySlice()
		buf := lazySlice.Acquire()
		n, err := conn.Read(buf)
		if errors.Is(err, net.ErrClosed) {
			lazySlice.Release()
			return
		}
		pkt := buf[:n]
		select {
		case <-a.Done():
			lazySlice.Release()
			return
		default:
			go a.HandlePacket(pkt, lazySlice)
		}
	}
}

func (a *association) HandlePacket(pkt []byte, lazySlice slicepool.LazySlice) {
	defer lazySlice.Release()
	defer a.debugLog("Done")

	a.debugLog("Outbound packet.", slog.Int("bytes", len(pkt)))

	var proxyTargetBytes int
	connError := func() *onet.ConnectionError {
		var textData []byte
		var err error

		a.findAccessKeyOnce.Do(func() {
			ip := a.raddr.AddrPort().Addr()
			var keyID string
			textLazySlice := a.bufPool.LazySlice()
			textBuf := textLazySlice.Acquire()
			unpackStart := time.Now()
			textData, keyID, a.cryptoKey, err = findAccessKeyUDP(ip, textBuf, pkt, a.ciphers, a.logger)
			timeToCipher := time.Since(unpackStart)
			textLazySlice.Release()
			a.ssm.AddCipherSearch(err == nil, timeToCipher)

			if err != nil {
				return
			}

			a.m.AddAuthenticated(keyID)
			go a.timedCopy()
		})
		if err != nil {
			return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack initial packet", err)
		}

		if a.cryptoKey == nil {
			// This should not happen since findAccessKeyUDP should have set `a.cryptoKey`.
			return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack data from client", err)
		}

		if textData == nil {
			// This is a subsequent packet. First packets are already decrypted as part of the
			// initial access key search.
			unpackStart := time.Now()
			textData, err = shadowsocks.Unpack(nil, pkt, a.cryptoKey)
			timeToCipher := time.Since(unpackStart)
			a.ssm.AddCipherSearch(err == nil, timeToCipher)
		}

		if err != nil {
			return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack data from client", err)
		}

		payload, tgtUDPAddr, onetErr := a.validatePacket(textData)
		if onetErr != nil {
			return onetErr
		}

		a.debugLog("Proxy exit.")
		proxyTargetBytes, err = a.targetConn.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
		if err != nil {
			return onet.NewConnectionError("ERR_WRITE", "Failed to write to target", err)
		}
		return nil
	}()

	status := "OK"
	if connError != nil {
		a.logger.LogAttrs(nil, slog.LevelDebug, "UDP: Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
		status = connError.Status
	}
	a.m.AddPacketFromClient(status, int64(len(pkt)), int64(proxyTargetBytes))
}

func (a *association) Done() <-chan struct{} {
	return a.doneCh
}

func (a *association) Close() error {
	now := time.Now()
	return a.SetReadDeadline(now)
}

// Get the maximum length of the shadowsocks address header by parsing
// and serializing an IPv6 address from the example range.
var maxAddrLen int = len(socks.ParseAddr("[2001:db8::1]:12345"))

// copy from target to client until read timeout
func (a *association) timedCopy() {
	defer func() {
		a.m.AddClosed()
		a.targetConn.Close()
		close(a.doneCh)
	}()

	// pkt is used for in-place encryption of downstream UDP packets, with the layout
	// [padding?][salt][address][body][tag][extra]
	// Padding is only used if the address is IPv4.
	pkt := make([]byte, serverUDPBufferSize)

	saltSize := a.cryptoKey.SaltSize()
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
			bodyLen, raddr, err = a.targetConn.ReadFrom(readBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						expired = true
						return nil
					}
				}
				return onet.NewConnectionError("ERR_READ", "Failed to read from target", err)
			}

			a.debugLog("Got response.", slog.Any("rtarget", raddr))
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
			buf, err := shadowsocks.Pack(packBuf, plaintextBuf, a.cryptoKey) // Encrypt in-place
			if err != nil {
				return onet.NewConnectionError("ERR_PACK", "Failed to pack data to client", err)
			}
			proxyClientBytes, err = a.Write(buf)
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to client", err)
			}
			return nil
		}()
		status := "OK"
		if connError != nil {
			a.debugLog("Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
			status = connError.Status
		}
		if expired {
			break
		}
		a.m.AddPacketFromTarget(status, int64(bodyLen), int64(proxyClientBytes))
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
