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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
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

// UDPAssociationMetrics is used to report metrics on UDP associations.
type UDPAssociationMetrics interface {
	AddAuthentication(accessKey string)
	AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64)
	AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64)
	AddClose()
}

// Max UDP buffer size for the server code.
const serverUDPBufferSize = 64 * 1024

// Buffer pool used for reading UDP packets.
var readBufPool = slicepool.MakePool(serverUDPBufferSize)

// Wrapper for slog.Debug during UDP proxying.
func debugUDP(l *slog.Logger, msg string, attrs ...slog.Attr) {
	// This is an optimization to reduce unnecessary allocations due to an interaction
	// between Go's inlining/escape analysis and varargs functions like slog.Debug.
	if l.Enabled(nil, slog.LevelDebug) {
		l.LogAttrs(nil, slog.LevelDebug, fmt.Sprintf("UDP: %s", msg), attrs...)
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
	logger            *slog.Logger
	ciphers           CipherList
	ssm               ShadowsocksConnMetrics
	targetIPValidator onet.TargetIPValidator
}

var _ PacketHandler = (*packetHandler)(nil)

// NewPacketHandler creates a PacketHandler
func NewPacketHandler(cipherList CipherList, ssMetrics ShadowsocksConnMetrics) PacketHandler {
	if ssMetrics == nil {
		ssMetrics = &NoOpShadowsocksConnMetrics{}
	}
	return &packetHandler{
		logger:            noopLogger(),
		ciphers:           cipherList,
		ssm:               ssMetrics,
		targetIPValidator: onet.RequirePublicIP,
	}
}

// PacketHandler is a handler that handles UDP assocations.
type PacketHandler interface {
	Handle(pkt []byte, assoc PacketAssociation, lazySlice slicepool.LazySlice)
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

func (h *packetHandler) authenticate(pkt []byte, assoc PacketAssociation) ([]byte, error) {
	var textData []byte
	keyResult, err := assoc.DoOnce(func() (any, error) {
		var (
			keyID  string
			key    *shadowsocks.EncryptionKey
			keyErr error
		)
		ip := assoc.ClientAddr().AddrPort().Addr()
		textLazySlice := readBufPool.LazySlice()
		textBuf := textLazySlice.Acquire()
		unpackStart := time.Now()
		textData, keyID, key, keyErr = findAccessKeyUDP(ip, textBuf, pkt, h.ciphers, h.logger)
		timeToCipher := time.Since(unpackStart)
		textLazySlice.Release()
		h.ssm.AddCipherSearch(keyErr == nil, timeToCipher)

		assoc.AddAuthentication(keyID)
		if keyErr != nil {
			return nil, keyErr
		}
		go HandleAssociationTimedCopy(assoc, func(pkt []byte, assoc PacketAssociation) error {
			return h.handleTarget(pkt, assoc, key)
		})
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	cryptoKey, ok := keyResult.(*shadowsocks.EncryptionKey)
	if !ok {
		// This should never happen in practice. We return a `shadowsocks.EncrypTionKey`
		// in the `authenticate` anonymous function above.
		return nil, errors.New("authentication result is not an encryption key")
	}

	if textData == nil {
		// This is a subsequent packet. First packets are already decrypted as part of the
		// initial access key search.
		unpackStart := time.Now()
		textData, err = shadowsocks.Unpack(nil, pkt, cryptoKey)
		timeToCipher := time.Since(unpackStart)
		h.ssm.AddCipherSearch(err == nil, timeToCipher)
	}

	return textData, nil
}

func (h *packetHandler) Handle(pkt []byte, assoc PacketAssociation, lazySlice slicepool.LazySlice) {
	l := h.logger.With(slog.Any("association", assoc))
	defer debugUDP(l, "Done")

	debugUDP(l, "Outbound packet.", slog.Int("bytes", len(pkt)))

	var proxyTargetBytes int
	connError := func() *onet.ConnectionError {
		textData, err := h.authenticate(pkt, assoc)
		lazySlice.Release()
		if err != nil {
			return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack data from client", err)
		}

		payload, tgtUDPAddr, onetErr := h.validatePacket(textData)
		if onetErr != nil {
			return onetErr
		}

		debugUDP(l, "Proxy exit.")
		proxyTargetBytes, err = assoc.WriteToTarget(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
		if err != nil {
			return onet.NewConnectionError("ERR_WRITE", "Failed to write to target", err)
		}
		return nil
	}()

	status := "OK"
	if connError != nil {
		debugUDP(l, "Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
		status = connError.Status
	}
	assoc.AddPacketFromClient(status, int64(len(pkt)), int64(proxyTargetBytes))
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

// Get the maximum length of the shadowsocks address header by parsing
// and serializing an IPv6 address from the example range.
var maxAddrLen int = len(socks.ParseAddr("[2001:db8::1]:12345"))

func (h *packetHandler) handleTarget(pkt []byte, assoc PacketAssociation, cryptoKey *shadowsocks.EncryptionKey) error {
	l := h.logger.With(slog.Any("association", assoc))

	expired := false

	saltSize := cryptoKey.SaltSize()
	// Leave enough room at the beginning of the packet for a max-length header (i.e. IPv6).
	bodyStart := saltSize + maxAddrLen

	var bodyLen, proxyClientBytes int
	connError := func() *onet.ConnectionError {
		var (
			raddr net.Addr
			err   error
		)
		// `readBuf` receives the plaintext body in `pkt`:
		// [padding?][salt][address][body][tag][unused]
		// |--     bodyStart     --|[      readBuf    ]
		readBuf := pkt[bodyStart:]
		bodyLen, raddr, err = assoc.ReadFromTarget(readBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if netErr.Timeout() {
					expired = true
					return nil
				}
			}
			return onet.NewConnectionError("ERR_READ", "Failed to read from target", err)
		}

		debugUDP(l, "Got response.", slog.Any("rtarget", raddr))
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
		proxyClientBytes, err = assoc.WriteToClient(buf)
		if err != nil {
			return onet.NewConnectionError("ERR_WRITE", "Failed to write to client", err)
		}
		return nil
	}()
	status := "OK"
	if connError != nil {
		debugUDP(l, "Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
		status = connError.Status
	}
	if expired {
		return errors.New("target connection has expired")
	}
	assoc.AddPacketFromTarget(status, int64(bodyLen), int64(proxyClientBytes))
	return nil
}

type NewAssociationFunc func(conn net.Conn) (PacketAssociation, error)

// PacketServe listens for UDP packets on the provided [net.PacketConn], creates
// and manages NAT associations, and invokes the `handle` function for each
// packet. It uses a NAT map to track active associations and handles their
// lifecycle.
func PacketServe(clientConn net.PacketConn, newAssociation NewAssociationFunc, handle PacketHandleFuncWithLazySlice, metrics NATMetrics) {
	nm := newNATmap()
	defer nm.Close()

	for {
		lazySlice := readBufPool.LazySlice()
		buffer := lazySlice.Acquire()

		isClosed := func() bool {
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
					return true
				}
				slog.Warn("Failed to read from client. Continuing to listen.", "err", err)
				return false
			}
			pkt := buffer[:n]

			// TODO(#19): Include server address in the NAT key as well.
			assoc := nm.Get(addr.String())
			if assoc == nil {
				conn := &natconn{PacketConn: clientConn, raddr: addr}
				assoc, err = newAssociation(conn)
				if err != nil {
					slog.Error("Failed to handle association", slog.Any("err", err))
					return false
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
				go handle(pkt, assoc, lazySlice)
			}
			return false
		}()
		if isClosed {
			return
		}
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
	associations map[string]PacketAssociation
}

func newNATmap() *natmap {
	return &natmap{associations: make(map[string]PacketAssociation)}
}

// Get returns a UDP NAT entry from the natmap.
func (m *natmap) Get(clientAddr string) PacketAssociation {
	m.RLock()
	defer m.RUnlock()
	return m.associations[clientAddr]
}

// Del deletes a UDP NAT entry from the natmap.
func (m *natmap) Del(clientAddr string) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.associations[clientAddr]; ok {
		delete(m.associations, clientAddr)
	}
}

// Add adds a new UDP NAT entry to the natmap.
func (m *natmap) Add(clientAddr string, assoc PacketAssociation) {
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

// PacketHandleFunc processes a single incoming packet.
type PacketHandleFunc func(pkt []byte, assoc PacketAssociation) error

// PacketHandleFuncWithLazySlice processes a single incoming packet.
//
// lazySlice is the LazySlice that holds the pkt buffer, which should be
// released as soon as the packet is processed.
type PacketHandleFuncWithLazySlice func(pkt []byte, assoc PacketAssociation, lazySlice slicepool.LazySlice)

func HandleAssociation(assoc PacketAssociation, handle PacketHandleFuncWithLazySlice) {
	for {
		lazySlice := readBufPool.LazySlice()
		buf := lazySlice.Acquire()
		n, err := assoc.ReadFromClient(buf)
		if errors.Is(err, net.ErrClosed) {
			lazySlice.Release()
			return
		}
		pkt := buf[:n]
		select {
		case <-assoc.Done():
			lazySlice.Release()
			return
		default:
			go handle(pkt, assoc, lazySlice)
		}
	}
}

// HandleAssociationTimedCopy handles the target-side of the association by
// copying from target to client until read timeout.
func HandleAssociationTimedCopy(assoc PacketAssociation, handle PacketHandleFunc) {
	defer assoc.CloseTarget()

	// pkt is used for in-place encryption of downstream UDP packets.
	// Padding is only used if the address is IPv4.
	pkt := make([]byte, serverUDPBufferSize)

	for {
		if err := handle(pkt, assoc); err != nil {
			break
		}
	}
}

// PacketAssociation represents a UDP association.
type PacketAssociation interface {
	// TODO(sbruens): Decouple the metrics from the association.
	UDPAssociationMetrics

	// ReadFromClient reads data from the client side of the association.
	ReadFromClient(b []byte) (n int, err error)

	// WriteToClient writes data to the client side of the association.
	WriteToClient(b []byte) (n int, err error)

	// ReadFromTarget reads data from the target side of the association.
	ReadFromTarget(p []byte) (n int, addr net.Addr, err error)

	// WriteToTarget writes data to the target side of the association.
	WriteToTarget(b []byte, addr net.Addr) (int, error)

	// ClientAddr returns the remote network address of the client connection, if known.
	ClientAddr() *net.UDPAddr

	// DoOnce executes the provided function only once and caches the result.
	DoOnce(f func() (any, error)) (any, error)

	// Done returns a channel that is closed when the association is closed.
	Done() <-chan struct{}

	// Close closes the association and releases any associated resources.
	Close() error

	// Closes the target side of the association.
	CloseTarget() error
}

type association struct {
	clientConn net.Conn
	targetConn net.PacketConn

	once         sync.Once
	cachedResult any

	UDPAssociationMetrics
	doneCh chan struct{}
}

var _ PacketAssociation = (*association)(nil)
var _ UDPAssociationMetrics = (*association)(nil)
var _ slog.LogValuer = (*association)(nil)

// NewPacketAssociation creates a new packet-based association.
func NewPacketAssociation(conn net.Conn, listener transport.PacketListener, m UDPAssociationMetrics) (PacketAssociation, error) {
	if m == nil {
		m = &NoOpUDPAssociationMetrics{}
	}
	// Create the target connection
	targetConn, err := listener.ListenPacket(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create target connection: %w", err)
	}

	return &association{
		clientConn:            conn,
		targetConn:            targetConn,
		UDPAssociationMetrics: m,
		doneCh:                make(chan struct{}),
	}, nil
}

func (a *association) ReadFromClient(b []byte) (n int, err error) {
	return a.clientConn.Read(b)
}

func (a *association) WriteToClient(b []byte) (n int, err error) {
	return a.clientConn.Write(b)
}

func (a *association) ReadFromTarget(p []byte) (n int, addr net.Addr, err error) {
	return a.targetConn.ReadFrom(p)
}

func (a *association) WriteToTarget(b []byte, addr net.Addr) (int, error) {
	return a.targetConn.WriteTo(b, addr)
}

func (a *association) ClientAddr() *net.UDPAddr {
	return a.clientConn.RemoteAddr().(*net.UDPAddr)
}

func (a *association) DoOnce(f func() (any, error)) (any, error) {
	var err error
	a.once.Do(func() {
		result, err := f()
		if err == nil {
			a.cachedResult = result
		}
	})
	return a.cachedResult, err
}

func (a *association) Done() <-chan struct{} {
	return a.doneCh
}

func (a *association) Close() error {
	now := time.Now()
	return a.clientConn.SetReadDeadline(now)
}

func (a *association) CloseTarget() error {
	a.UDPAssociationMetrics.AddClose()
	err := a.targetConn.Close()
	if err != nil {
		return err
	}
	close(a.doneCh)
	return nil
}

func (a *association) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("client", a.clientConn.RemoteAddr()),
		slog.Any("ltarget", a.targetConn.LocalAddr()),
	)
}

// NoOpUDPAssociationMetrics is a [UDPAssociationMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpUDPAssociationMetrics struct{}

var _ UDPAssociationMetrics = (*NoOpUDPAssociationMetrics)(nil)

func (m *NoOpUDPAssociationMetrics) AddAuthentication(accessKey string) {}

func (m *NoOpUDPAssociationMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
}
func (m *NoOpUDPAssociationMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
}
func (m *NoOpUDPAssociationMetrics) AddClose() {
}
