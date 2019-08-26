package shadowsocks

import (
	"errors"
	"io"
	"net"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Client is a client for Shadowsocks TCP and UDP connections.
type Client interface {
	// DialTCP connects to `raddr` over TCP though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil.
	// `raddr` has the form `host:port`, where `host` can be a domain name or IP address.
	DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error)

	// ListenUDP relays UDP packets though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil.
	ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error)
}

// NewClient creates a client that routes connections to a Shadowsocks proxy listening at
// `host:port`, with authentication parameters `cipher` (AEAD) and `password`.
// TODO: add a dialer argument to support proxy chaining and transport changes.
func NewClient(host string, port int, password, cipher string) (Client, error) {
	// TODO: consider using net.LookupIP to get a list of IPs, and add logic for optimal selection.
	proxyIP, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, errors.New("Failed to resolve proxy address")
	}
	aead, err := newAeadCipher(cipher, password)
	if err != nil {
		return nil, err
	}
	d := ssClient{proxyIP: proxyIP.IP, proxyPort: port, cipher: aead}
	return &d, nil
}

type ssClient struct {
	proxyIP   net.IP
	proxyPort int
	cipher    shadowaead.Cipher
}

func (c *ssClient) DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error) {
	socksTargetAddr := socks.ParseAddr(raddr)
	if socksTargetAddr == nil {
		return nil, errors.New("Failed to parse target address")
	}
	proxyAddr := &net.TCPAddr{IP: c.proxyIP, Port: c.proxyPort}
	proxyConn, err := net.DialTCP("tcp", laddr, proxyAddr)
	if err != nil {
		return nil, err
	}
	ssw := NewShadowsocksWriter(proxyConn, c.cipher)
	_, err = ssw.Write(socksTargetAddr)
	if err != nil {
		proxyConn.Close()
		return nil, errors.New("Failed to write target address")
	}
	ssr := NewShadowsocksReader(proxyConn, c.cipher)
	return onet.WrapConn(proxyConn, ssr, ssw), nil
}

func (c *ssClient) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	proxyAddr := &net.UDPAddr{IP: c.proxyIP, Port: c.proxyPort}
	pc, err := net.DialUDP("udp", laddr, proxyAddr)
	if err != nil {
		return nil, err
	}
	conn := packetConn{UDPConn: pc, cipher: c.cipher}
	return &conn, nil
}

type packetConn struct {
	*net.UDPConn
	cipher shadowaead.Cipher
}

// WriteTo encrypts `b` and writes to `addr` through the proxy.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	socksTargetAddr := socks.ParseAddr(addr.String())
	if socksTargetAddr == nil {
		return 0, errors.New("Failed to parse target address")
	}
	cipherBuf := newUDPBuffer()
	defer freeUDPBuffer(cipherBuf)
	saltSize := c.cipher.SaltSize()
	// Copy the SOCKS target address and payload, reserving space for the generated salt to avoid
	// partially overlapping the plaintext and cipher slices since `Pack` skips the salt when calling
	// `AEAD.Seal` (see https://golang.org/pkg/crypto/cipher/#AEAD).
	plaintextBuf := append(append(cipherBuf[saltSize:saltSize], socksTargetAddr...), b...)
	buf, err := shadowaead.Pack(cipherBuf, plaintextBuf, c.cipher)
	if err != nil {
		return 0, err
	}
	_, err = c.UDPConn.Write(buf)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts into `b`.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	cipherBuf := newUDPBuffer()
	defer freeUDPBuffer(cipherBuf)
	n, err := c.UDPConn.Read(cipherBuf)
	if err != nil {
		return 0, nil, err
	}
	// Avoid partially overlapping the plaintext and cipher slices since `Unpack` skips the salt
	// when calling `AEAD.Open` (see https://golang.org/pkg/crypto/cipher/#AEAD).
	buf, err := shadowaead.Unpack(cipherBuf[c.cipher.SaltSize():], cipherBuf[:n], c.cipher)
	if err != nil {
		return 0, nil, err
	}
	socksSrcAddr := socks.SplitAddr(buf)
	if socksSrcAddr == nil {
		return 0, nil, errors.New("Failed to read source address")
	}
	srcAddr := NewAddr(socksSrcAddr.String(), "udp")
	n = copy(b, buf[len(socksSrcAddr):]) // Strip the SOCKS source address
	if len(b) < len(buf)-len(socksSrcAddr) {
		return n, srcAddr, io.ErrShortBuffer
	}
	return n, srcAddr, nil
}

type addr struct {
	address string
	network string
}

func (a *addr) String() string {
	return a.address
}

func (a *addr) Network() string {
	return a.network
}

// NewAddr returns a net.Addr that holds an address of the form `host:port` with a domain name or IP as host.
// Used for SOCKS addressing.
func NewAddr(address, network string) net.Addr {
	return &addr{address: address, network: network}
}

func newAeadCipher(cipher, password string) (shadowaead.Cipher, error) {
	ssCipher, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}
	aead, ok := ssCipher.(shadowaead.Cipher)
	if !ok {
		return nil, errors.New("Only AEAD ciphers supported")
	}
	return aead, nil
}
