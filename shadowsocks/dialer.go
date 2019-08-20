package shadowsocks

import (
	"io"
	"errors"
	"net"
	"strconv"
	"sync"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Dialer is a dialer for Shadowsocks proxy connections.
type Dialer interface {
	// DialTCP connects to `address` over TCP though the Shadowsocks proxy.
	// `address` has the form `host:port`, where `host` can be a domain name or IP address.
	DialTCP(address string) (onet.DuplexConn, error)
	// DialUDP relays UDP packets to/from `address` though the Shadowsocks proxy.
	// `address` has the form `host:port`, where `host` can be a domain name or IP address.
	DialUDP(address string) (onet.PacketConn, error)
}

type ssDialer struct {
	proxyIP   net.IP
	proxyPort int
	cipher    shadowaead.Cipher
}

// NewDialer creates a Dialer that routes connections to a Shadowsocks proxy listening at
// `host:port`, with authentication parameters `cipher` (AEAD) and `password`.
func NewDialer(host, password, cipher string, port int) (Dialer, error) {
	proxyIP, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, errors.New("Failed to resolve proxy address")
	}
	aead, err := newAeadCipher(cipher, password)
	if err != nil {
		return nil, err
	}
	d := ssDialer{proxyIP: net.ParseIP(proxyIP.String()), proxyPort: port, cipher: aead}
	return &d, nil
}

func (d *ssDialer) DialTCP(address string) (onet.DuplexConn, error) {
	proxyAddr := &net.TCPAddr{IP: d.proxyIP, Port: d.proxyPort}
	conn, err := net.DialTCP("tcp", nil, proxyAddr)
	if err != nil {
		return nil, err
	}
	ssw := NewShadowsocksWriter(conn, d.cipher)
	socksTargetAddr := socks.ParseAddr(address)
	if socksTargetAddr == nil {
		return nil, errors.New("Invalid target address")
	}
	_, err = ssw.Write(socksTargetAddr)
	if err != nil {
		conn.Close()
		return nil, errors.New("Failed to write target address")
	}
	ssr := NewShadowsocksReader(conn, d.cipher)
	return onet.WrapConn(conn, ssr, ssw), nil
}

// Clients are encouraged to use io.ReadWriter methods of onet.PacketConn
// to leverage the association with the proxy.
func (d *ssDialer) DialUDP(address string) (onet.PacketConn, error) {
	proxyAddr := &net.UDPAddr{IP: d.proxyIP, Port: d.proxyPort}
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	targetHost, targetPortStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("Invalid target address")
	}
	// Ignore the error, it would have failed when splitting the address
	targetPort, _ := strconv.Atoi(targetPortStr)
	targetAddr := &packetConnAddr{Host: targetHost, Port: targetPort}
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

func (c *packetConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.proxyAddr)
}

// WriteTo encrypts b and write to addr using the embedded PacketConn.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.m.Lock()
	defer c.m.Unlock()
	socksTargetAddr := socks.ParseAddr(c.targetAddr.String())
	if socksTargetAddr == nil {
		return 0, errors.New("Invalid target address")
	}
	buf, err := shadowaead.Pack(c.buf, append(socksTargetAddr, b...), c.cipher)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

func (c *packetConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

// ReadFrom reads from the embedded PacketConn and decrypts into b.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, c.targetAddr, err
	}
	buf, err := shadowaead.Unpack(b[c.cipher.SaltSize():], b[:n], c.cipher)
	if err != nil {
		return n, c.targetAddr, err
	}
	socksSrcAddr := socks.SplitAddr(buf[:n])
	copy(b, buf[len(socksSrcAddr):]) // Remove the SOCKS source address

	return len(buf) - len(socksSrcAddr), c.targetAddr, err
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
