package shadowsocks

import (
	"errors"
	"io"
	"net"
	"strconv"
	"sync"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Dialer is a dialer for Shadowsocks TCP and UDP connections.
type Dialer interface {
	// DialTCP connects to `raddr` over TCP though the Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil
	// `raddr` has the form `host:port`, where `host` can be a domain name or IP address.
	DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error)

	// DialUDP relays UDP packets to/from `raddr` though the Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil
	// `raddr` has the form `host:port`, where `host` can be a domain name or IP address.
	DialUDP(laddr *net.UDPAddr, raddr string) (onet.PacketConn, error)
}

type ssDialer struct {
	proxyIP   net.IP
	proxyPort int
	cipher    shadowaead.Cipher
}

// NewDialer creates a Dialer that routes connections to a Shadowsocks proxy listening at
// `host:port`, with authentication parameters `cipher` (AEAD) and `password`.
// TODO: add a dialer argument to support proxy chaining and transport changes.
func NewDialer(host string, port int, password, cipher string) (Dialer, error) {
	proxyIP, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, errors.New("Failed to resolve proxy address")
	}
	aead, err := newAeadCipher(cipher, password)
	if err != nil {
		return nil, err
	}
	d := ssDialer{proxyIP: proxyIP.IP, proxyPort: port, cipher: aead}
	return &d, nil
}

func (d *ssDialer) DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error) {
	socksTargetAddr := socks.ParseAddr(raddr)
	if socksTargetAddr == nil {
		return nil, errors.New("Failed to parse target address")
	}
	proxyAddr := &net.TCPAddr{IP: d.proxyIP, Port: d.proxyPort}
	proxyConn, err := net.DialTCP("tcp", laddr, proxyAddr)
	if err != nil {
		return nil, err
	}
	ssw := NewShadowsocksWriter(proxyConn, d.cipher)
	_, err = ssw.Write(socksTargetAddr)
	if err != nil {
		proxyConn.Close()
		return nil, errors.New("Failed to write target address")
	}
	ssr := NewShadowsocksReader(proxyConn, d.cipher)
	return onet.WrapConn(proxyConn, ssr, ssw), nil
}

// Clients can use the io.ReadWriter methods of onet.PacketConn to leverage the connection to `raddr`.
func (d *ssDialer) DialUDP(laddr *net.UDPAddr, raddr string) (onet.PacketConn, error) {
	targetHost, targetPort, err := SplitHostPortNumber(raddr)
	if err != nil {
		return nil, err
	}
	targetAddr := &packetConnAddr{Host: targetHost, Port: targetPort}
	proxyAddr := &net.UDPAddr{IP: d.proxyIP, Port: d.proxyPort}
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	conn := packetConn{
		PacketConn: pc, proxyAddr: proxyAddr, targetAddr: targetAddr,
		cipher: d.cipher, buf: make([]byte, udpBufSize)}
	return &conn, nil
}

type packetConn struct {
	net.PacketConn
	io.ReadWriter
	proxyAddr  *net.UDPAddr
	targetAddr net.Addr
	cipher     shadowaead.Cipher
	m          sync.Mutex
	buf        []byte // Write lock
}

// Write encrypts `b` and writes to the connected address through the proxy.
func (c *packetConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.targetAddr)
}

// WriteTo encrypts `b` and writes to `addr` through the proxy.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.m.Lock()
	defer c.m.Unlock()
	socksTargetAddr := socks.ParseAddr(addr.String())
	if socksTargetAddr == nil {
		return 0, errors.New("Failed to parse target address")
	}
	buf, err := shadowaead.Pack(c.buf, append(socksTargetAddr, b...), c.cipher)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, c.proxyAddr)
	return len(b), err
}

func (c *packetConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

// ReadFrom reads from the embedded PacketConn and decrypts into `b`.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(b) < c.cipher.SaltSize() {
		return 0, nil, shadowaead.ErrShortPacket
	}
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	} else if addr.String() != c.proxyAddr.String() {
		return n, addr, errors.New("Received a packet from an unassociated address")
	}
	// Avoid overlapping the destination and cipher buffers per https://golang.org/pkg/crypto/cipher/#AEAD.
	buf, err := shadowaead.Unpack(b[c.cipher.SaltSize():], b[:n], c.cipher)
	if err != nil {
		return n, nil, err
	}
	socksSrcAddr := socks.SplitAddr(buf[:n])
	if socksSrcAddr == nil {
		return n, nil, errors.New("Failed to read source address")
	}
	srcHost, srcPort, err := SplitHostPortNumber(socksSrcAddr.String())
	if err != nil {
		return len(buf), nil, errors.New("Failed to parse source address")
	}
	srcAddr := &packetConnAddr{Host: srcHost, Port: srcPort}
	copy(b, buf[len(socksSrcAddr):]) // Strip the SOCKS source address
	return len(buf) - len(socksSrcAddr), srcAddr, err

}

// Convenience struct to hold a domain name or IP address host. Used for SOCKS addressing.
type packetConnAddr struct {
	net.Addr
	Host string
	Port int
}

func (a *packetConnAddr) String() string {
	return net.JoinHostPort(a.Host, strconv.FormatInt(int64(a.Port), 10))
}

func (a *packetConnAddr) Network() string {
	return "udp"
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

// SplitHostPortNumber parses the host and port from `address`, which has the form `host:port`,
// validating that the port is a number.
func SplitHostPortNumber(address string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		err = errors.New("Failed to split host and port")
		return
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		err = errors.New("Invalid non-numeric port")
		return
	}
	return
}
