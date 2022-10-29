package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/websocket"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type WebsocketOptions struct {
	// Addr is the address of the websocket server. It can either an IP address or a domain name.
	Addr string
	// Port is the destination port of the websocket connection.
	Port int
	// Host is the hostname to use in the Host header of HTTP request made to the websocket server.
	// If empty, the header will be set to `Addr` if it is a domain name.
	Host string
	// SNI is the hostname to use in the server name extension of the TLS handshake. If empty, it will be set to `Host`.
	SNI string
	// Path is the HTTP path to use when connecting to the websocket server.
	Path string
	// Password is the password to use for the shadowsocks connection tunnelled inside the websocket connection.
	Password string
	// Ciphter is the cipher to use for the shadowsocks connection tunnelled inside the websocket connection.
	Cipher string
}

// NewWebsocketClient creates a client that routes connections to a Shadowsocks proxy
// tunneled inside a websocket connection.
func NewWebsocketClient(opts WebsocketOptions) (Client, error) {
	proxy := opts.Addr
	if proxy == "" {
		proxy = opts.Host
	}
	if proxy == "" {
		return nil, fmt.Errorf("neither Addr or Host are defined")
	}

	ss, err := NewClient(proxy, opts.Port, opts.Password, opts.Cipher)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(opts.Path, "/") {
		opts.Path = opts.Path[1:]
	}

	addrIP := net.ParseIP(opts.Addr)
	if opts.Host == "" && addrIP == nil {
		opts.Host = opts.Addr
	}

	if opts.SNI == "" {
		opts.SNI = opts.Host
	}

	return &wsClient{
		ssClient: ss.(*ssClient),
		opts:     opts,
	}, nil
}

type wsClient struct {
	*ssClient
	opts WebsocketOptions
}

func (c *wsClient) DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error) {
	socksTargetAddr := socks.ParseAddr(raddr)
	if socksTargetAddr == nil {
		return nil, errors.New("Failed to parse target address")
	}

	h := make(http.Header)
	if c.opts.Host != "" {
		h.Set("Host", c.opts.Host)
	}
	d := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         c.opts.SNI,
		},
		HandshakeTimeout: websocket.DefaultHandshakeTimeout,
	}
	proxyConn, err := d.Dial(fmt.Sprintf("wss://%s:%d/%s", c.proxyIP, c.opts.Port, c.opts.Path), h)
	if err != nil {
		return nil, err
	}

	ssw := ss.NewShadowsocksWriter(proxyConn, c.cipher)
	_, err = ssw.LazyWrite(socksTargetAddr)
	if err != nil {
		proxyConn.Close()
		return nil, errors.New("Failed to write target address")
	}
	time.AfterFunc(helloWait, func() {
		ssw.Flush()
	})
	ssr := ss.NewShadowsocksReader(proxyConn, c.cipher)
	return onet.WrapConn(proxyConn, ssr, ssw), nil
}
