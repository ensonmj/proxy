package proxy

import (
	"context"
	"io"
	"io/ioutil"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	socks5Version = 5
)

type Handler interface {
	ServeConn(io.ReadWriter) error
}

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
	return &Server{
		Node:    n,
		DialCtx: chain.DialContext,
	}, nil
}

func (s *Server) ListenAndServe() error {
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
		log.WithFields(logrus.Fields{
			"localAddr":  conn.LocalAddr(),
			"remoteAddr": conn.RemoteAddr(),
			"node":       *s.Node,
			"hooks":      s.Node.hooks,
		}).Debug("accept proxy request")

		go handleConn(s.Node, conn, s.DialCtx)
	}
}

func handleConn(node *Node, conn net.Conn,
	dialCtx func(context.Context, string, string) (net.Conn, error)) {
	defer conn.Close()

	// hook conn for data process
	c := WithInHooks(conn, node.hooks...)

	switch node.URL.Scheme {
	case "http":
		err := NewHttpHandler(node, dialCtx).ServeConn(c)
		if err != nil {
			log.WithError(err).Warn("http proxy failed")
		}
	case "socks5":
		err := NewSocksHandler(node, dialCtx).ServeConn(c)
		if err != nil {
			log.WithError(err).Warn("socks5 proxy failed")
		}
	case "ghost":
		fallthrough
	default:
		// select handler automatically
		// all handlers must not write data before proxy protocol verified
		sockR, sockW := io.Pipe()
		httpR, httpW := io.Pipe()
		go func() {
			defer sockW.Close()
			defer httpW.Close()

			mw := io.MultiWriter(sockW, httpW)

			io.Copy(mw, c)
		}()

		sockErrC := make(chan error)
		httpErrC := make(chan error)
		// socks5
		go func() {
			sockErrC <- NewSocksHandler(node, dialCtx).ServeConn(
				&wrapper{Reader: sockR, Writer: c})
			io.Copy(ioutil.Discard, sockR)
		}()
		// HTTP/1.x
		go func() {
			httpErrC <- NewHttpHandler(node, dialCtx).ServeConn(
				&wrapper{Reader: httpR, Writer: c})
			io.Copy(ioutil.Discard, httpR)
		}()

		var sockErr, httpErr error
		for {
			select {
			case sockErr = <-sockErrC:
				sockErrC = nil
			case httpErr = <-httpErrC:
				httpErrC = nil
			}
		}
		if sockErr != nil && httpErr != nil {
			log.WithFields(logrus.Fields{
				"http":  httpErr,
				"socks": sockErr,
			}).Error("http and socks5 all failed")
		}
	}
}

type wrapper struct {
	io.Reader
	io.Writer
}

func (c *wrapper) Read(b []byte) (n int, err error) {
	return c.Reader.Read(b)
}
func (c *wrapper) Write(b []byte) (n int, err error) {
	return c.Writer.Write(b)
}
