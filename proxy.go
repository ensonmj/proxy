package proxy

import (
	"context"
	"io"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func init() {
	log = logrus.New()
	// log.SetLevel(logrus.DebugLevel)
}

const (
	socks5Version = 5
)

var (
	log *logrus.Logger
)

type Handler interface {
	ServeConn(io.ReadWriteCloser)
}

// ****************************************************************************
//                      ________________________________
//                     |                                |
// client --tcp/udp--> |proxy ... --tcp/udp--> ... proxy| --tcp/udp--> server
//                     |________________________________|
//
//    |----socks/http----||----------tun------------||-----any proto-----|
//
// ****************************************************************************
type Server struct {
	Node
	DialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewServer(n Node,
	dialCtx func(context.Context, string, string) (net.Conn, error)) *Server {
	return &Server{
		Node:    n,
		DialCtx: dialCtx,
	}
}

func (s *Server) Listen() error {
	// now only support tcp
	ln, err := net.Listen("tcp", s.Node.URL.Host)
	if err != nil {
		return errors.WithStack(err)
	}
	return s.Serve(ln)
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.WithError(err).Error("[proxy] accept connection closed")
			return err
		}

		go handleConn(&s.Node, conn, s.DialCtx)
	}
}

func handleConn(node *Node, conn net.Conn,
	dialCtx func(context.Context, string, string) (net.Conn, error)) {
	// http or socks5
	b := make([]byte, 1024)
	n, err := io.ReadAtLeast(conn, b, 2)
	if err != nil {
		log.WithError(err).Error("[proxy] failed to guess protocol")
		return
	}

	var h Handler
	if b[0] == socks5Version {
		// socks5
		h = NewSocksHandler(node, dialCtx)
	} else {
		// HTTP/1.x
		h = NewHttpHandler(node, dialCtx)
	}

	h.ServeConn(&connRWC{Conn: conn, b: b[:n]})
}

type connRWC struct {
	net.Conn
	b []byte
}

func (r *connRWC) Read(p []byte) (n int, err error) {
	if len(r.b) == 0 {
		return r.Conn.Read(p)
	}
	n = copy(p, r.b)
	r.b = r.b[n:]
	return
}
