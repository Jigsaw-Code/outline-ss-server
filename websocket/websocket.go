package websocket

import (
	"fmt"
	"io"
	"net/http"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/gorilla/websocket"
)

var (
	DefaultHandshakeTimeout = 5 * time.Second
	defaultDialer           = Dialer{
		HandshakeTimeout: DefaultHandshakeTimeout,
	}
	defaultUpgrade = Upgrader{
		HandshakeTimeout: DefaultHandshakeTimeout,
	}
)

type Dialer websocket.Dialer

func Dial(u string, h http.Header) (onet.DuplexConn, error) {
	return defaultDialer.Dial(u, h)
}

func (d *Dialer) Dial(u string, h http.Header) (onet.DuplexConn, error) {
	wd := websocket.Dialer(*d)
	ws, _, err := wd.Dial(u, h)
	if err != nil {
		return nil, err
	}
	return wrapWS(ws), err
}

type Upgrader websocket.Upgrader

func Upgrade(w http.ResponseWriter, r *http.Request, h http.Header) (onet.DuplexConn, error) {
	return defaultUpgrade.Upgrade(w, r, h)
}

func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, h http.Header) (onet.DuplexConn, error) {
	wu := websocket.Upgrader(*u)
	c, err := wu.Upgrade(w, r, h)
	if err != nil {
		return nil, fmt.Errorf("upgrading websocket connection failed: %v", err)
	}
	return wrapWS(c), nil
}

type wsWrapper struct {
	*websocket.Conn
	r           io.Reader
	readClosed  bool
	writeClosed bool
}

func wrapWS(c *websocket.Conn) *wsWrapper {
	ws := &wsWrapper{Conn: c}
	c.SetCloseHandler(ws.closeHandler)
	return ws
}

func (c *wsWrapper) Write(p []byte) (int, error) {
	return len(p), c.WriteMessage(websocket.BinaryMessage, p)
}

func (c *wsWrapper) Read(p []byte) (n int, err error) {
	defer func() {
		if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			err = io.EOF
		}
	}()
	if c.r == nil {
		if c.readClosed {
			return 0, io.EOF
		}
		var err error
		_, c.r, err = c.Conn.NextReader()
		if err != nil {
			return 0, err
		}
	}
	n, err = c.r.Read(p)
	if err == io.EOF && !c.readClosed {
		c.r = nil
		return c.Read(p)
	}
	return n, err
}

func (c *wsWrapper) CloseRead() error {
	c.readClosed = true
	return nil
}

func (c *wsWrapper) closeHandler(code int, text string) error {
	return c.CloseRead()
}

func (c *wsWrapper) CloseWrite() error {
	c.writeClosed = true
	message := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	return c.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second))
}

func (c *wsWrapper) Close() error {
	return c.Conn.Close()
}

func (c *wsWrapper) SetDeadline(t time.Time) error {
	return c.Conn.UnderlyingConn().SetDeadline(t)
}
