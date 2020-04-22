package proxy

import (
	"context"
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
	DialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewServer(localURL string, chainURL ...string) (*Server, error) {
	n, err := ParseNode(localURL)
	if err != nil {
		return nil, err
	}
	chain, err := NewProxyChain(chainURL...)
	if err != nil {
		return nil, err
	}
	var h Handler
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
	return &Server{
		Node:    n,
		handler: h,
		DialCtx: chain.DialContext,
	}, nil
}

func (s *Server) ListenAndServe() error {
	// now only support tcp
	ln, err := net.Listen("tcp", s.Node.URL.Host)
	if err != nil {
		return errors.WithStack(err)
	}
	defer ln.Close()

	return s.Serve(ln)
}

func (s *Server) Serve(ln net.Listener) error {
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
	defer conn.Close()

	// hook conn for data process
	c := WithInHooks(conn, node.hooks...)

	// serve conn
	err := h.ServeConn(c)
	if err != nil {
		log.WithError(err).Warn("proxy failed")
	}
}

func (s *Server) RevServe() error {
	cNode := s.Node
	user := cNode.URL.User
	switch cNode.URL.Scheme {
	case "socks5":
		err := NewRevSocksHandler(user, s.DialCtx).RevServeConn(cNode.URL)
		if err != nil {
			log.WithError(err).Warn("socks5 proxy failed")
		}
		return err
	case "http", "ghost":
		fallthrough
	default:
		return errors.New("reverse proxy not support protocol other than socks5")
	}
}
