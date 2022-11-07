package main

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Jigsaw-Code/outline-ss-server/websocket"
)

func RunWebsocketServer(ssServer *SSServer, port int, certPath, keyPath string) (*wsServer, error) {
	ws := &wsServer{ss: ssServer}
	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	logger.Infof("Websocket server listening on %s", l.Addr())
	ws.listener = l
	go func() {
		err = http.ServeTLS(l, http.HandlerFunc(ws.handleRequest), certPath, keyPath)
		if err != nil {
			logger.Errorf("Websocket server closed: %v", err)
		}
	}()
	return ws, nil
}

type wsServer struct {
	ss       *SSServer
	listener net.Listener
}

func (s *wsServer) Stop() error {
	return s.listener.Close()
}

func (s *wsServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Upgrade(w, r, nil)
	if err != nil {
		logger.Errorf(err.Error())
		return
	}
	defer c.Close()

	p, err := strconv.Atoi(strings.Trim(r.URL.Path, "/"))
	if err != nil {
		logger.Errorf("Invalid path %s", r.URL.Path)
		return
	}

	port, ok := s.ss.ports[p]
	if !ok {
		logger.Errorf("Port %d does not exist", p)
		return
	}

	port.tcpService.HandleConnection(p, c)
}
