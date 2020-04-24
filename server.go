package proxy

import (
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// **********************************************************************************
//                                ______________________________
//                               |                              |
// client --tcp/udp--> proxy --> |chain ...--tcp/udp-->... chain| --tcp/udp--> server
//                               |______________________________|
//
//   |----socks/http----| |----------------tun--------------| |-----any proto-----|
//
// API:
//                    (Listen)
//                        |----------------------DialContext----------------------|
//
//                                  |---Handshake/Forward---|
//
// **********************************************************************************
type Server struct {
	*Node
	handler Handler
}

func NewServer(localURL string, chainURL ...string) (*Server, error) {
	chain, err := NewProxyChain(chainURL...)
	if err != nil {
		return nil, err
	}

	var h Handler
	var n *Node

	if localURL == "" {
		// only support socks5 in reverse proxy
		h = NewRevSocksHandler(chain.DialContext)
	} else {
		n, err = ParseNode(localURL)
		if err != nil {
			return nil, err
		}
		user := n.URL.User
		switch n.URL.Scheme {
		case "http":
			h = NewHttpHandler(user, chain.DialContext)
		case "socks5":
			h = NewSocksHandler(user, chain.DialContext)
		case "ghost":
			fallthrough
		default:
			h = NewAutoHandler(user, chain.DialContext)
		}
	}

	return &Server{
		Node:    n,
		handler: h,
	}, nil
}

func (s *Server) Serve() error {
	// reverse proxy
	// ************************************************************************
	// server --> server end proxy ... tunnel ... client end proxy --> client
	// ************************************************************************
	if s.Node == nil {
		return s.handler.ServeConn(nil)
	}

	// now only support tcp
	ln, err := net.Listen("tcp", s.Node.URL.Host)
	if err != nil {
		return errors.WithStack(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.WithError(err).Error("[proxy] accept connection closed")
			return err
		}
		log.WithFields(logrus.Fields{
			"localAddr":  conn.LocalAddr(),
			"remoteAddr": conn.RemoteAddr(),
			"node":       *s.Node,
			"hooks":      s.Node.hooks,
		}).Debug("accept proxy request")

		go handleConn(conn, s.Node, s.handler)
	}
}

func handleConn(conn net.Conn, node *Node, h Handler) {
	// hook conn for data process
	c := WithInHooks(conn, node.hooks...)

	// serve conn
	err := h.ServeConn(c)
	if err != nil {
		log.WithError(err).Warn("proxy failed")
	}
}
