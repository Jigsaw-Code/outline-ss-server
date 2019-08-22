package shadowsocks

import (
	"errors"
	"net"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Client is a client for Shadowsocks TCP and UDP connections.
type Client interface {
	// DialTCP connects to `raddr` over TCP though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil
	// `raddr` has the form `host:port`, where `host` can be a domain name or IP address.
	DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error)

	// ListenUDP relays UDP packets though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil
	ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error)
}

type ssClient struct {
	proxyIP   net.IP
	proxyPort int
	cipher    shadowaead.Cipher
}

// NewClient creates a client that routes connections to a Shadowsocks proxy listening at
// `host:port`, with authentication parameters `cipher` (AEAD) and `password`.
// TODO: add a dialer argument to support proxy chaining and transport changes.
func NewClient(host string, port int, password, cipher string) (Client, error) {
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

func (d *ssClient) DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error) {
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

func (d *ssClient) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	proxyAddr := &net.UDPAddr{IP: d.proxyIP, Port: d.proxyPort}
	pc, err := net.DialUDP("udp", laddr, proxyAddr)
	if err != nil {
		return nil, err
	}
	conn := packetConn{UDPConn: pc, cipher: d.cipher}
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
	buf, err := shadowaead.Pack(cipherBuf, append(socksTargetAddr, b...), c.cipher)
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
		return n, nil, err
	}
	buf, err := shadowaead.Unpack(b, cipherBuf[:n], c.cipher)
	if err != nil {
		return n, nil, err
	}
	socksSrcAddr := socks.SplitAddr(buf[:n])
	if socksSrcAddr == nil {
		return n, nil, errors.New("Failed to read source address")
	}
	srcAddr := &addr{address: socksSrcAddr.String(), network: "udp"}
	copy(b, buf[len(socksSrcAddr):]) // Strip the SOCKS source address
	return len(buf) - len(socksSrcAddr), srcAddr, err

}

type addr struct {
	net.Addr
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
