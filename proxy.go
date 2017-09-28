package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

func init() {
	log = logrus.New()
	tlsNextProto = make(map[string]func(*tls.Conn))
}

const (
	socks5Version = 5
)

var (
	log          *logrus.Logger
	tlsNextProto map[string]func(*tls.Conn, func(context.Context, string, string) (net.Conn, error))
)

type Handler interface {
	ServeConn(io.ReadWriteCloser)
}

type Server struct {
	DialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewServer(dialCtx func(context.Context, string, string) (net.Conn, error)) *Server {
	return &Server{
		DialCtx: dialCtx,
	}
}

func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.WithError(err).Error("[proxy] accept connection closed")
			return err
		}

		go handleConn(conn, s.DialCtx)
	}
}

func handleConn(conn net.Conn,
	dialCtx func(context.Context, string, string) (net.Conn, error)) {
	defer conn.Close()
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			log.WithError(err).Error("[proxy] tls handshake failed")
			return
		}

		if proto := tlsConn.ConnectionState().NegotiatedProtocol; validNPN(proto) {
			if fn := tlsNextProto[proto]; fn != nil {
				fn(tlsConn, dialCtx)
			}
			return
		}
	}

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
		h = &SocksHandler{dialCtx: dialCtx}
	} else {
		// HTTP/1.x
		h = NewHttpHandler(dialCtx)
	}

	h.ServeConn(&connRWC{Conn: conn, b: b[:n]})
}

func validNPN(proto string) bool {
	switch proto {
	case "", "http/1.1", "http/1.0":
		return false
	}
	return true
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
