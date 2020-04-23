package proxy

import (
	"context"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"time"

	"github.com/ensonmj/proxy/cred"
	"github.com/ensonmj/proxy/httpproxy"
	"github.com/ensonmj/proxy/socks5"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Handler interface {
	ServeConn(net.Conn) error
}

func NewHttpHandler(
	user *url.Userinfo,
	dialCtx func(context.Context, string, string) (net.Conn, error)) *httpproxy.Server {
	cfg := &httpproxy.Config{
		Dial: dialCtx,
	}
	if user != nil {
		username := user.Username()
		password, _ := user.Password()
		cfg.Credentials = cred.StaticCredentials{
			username: password,
		}
	}
	return httpproxy.New(cfg)
}

func NewSocksHandler(
	user *url.Userinfo,
	dialCtx func(context.Context, string, string) (net.Conn, error)) *socks5.Server {
	cfg := &socks5.Config{
		Dial: dialCtx,
	}
	if user != nil {
		username := user.Username()
		password, _ := user.Password()
		cfg.Credentials = cred.StaticCredentials{
			username: password,
		}
	}
	return socks5.New(cfg)
}

type AutoServer struct {
	hServer *httpproxy.Server
	sServer *socks5.Server
}

func NewAutoHandler(
	user *url.Userinfo,
	dialCtx func(context.Context, string, string) (net.Conn, error)) *AutoServer {
	hCfg := &httpproxy.Config{
		Dial: dialCtx,
	}
	if user != nil {
		username := user.Username()
		password, _ := user.Password()
		hCfg.Credentials = cred.StaticCredentials{
			username: password,
		}
	}
	hServer := httpproxy.New(hCfg)
	sCfg := &socks5.Config{
		Dial: dialCtx,
	}
	if user != nil {
		username := user.Username()
		password, _ := user.Password()
		sCfg.Credentials = cred.StaticCredentials{
			username: password,
		}
	}
	sServer := socks5.New(sCfg)

	return &AutoServer{
		hServer: hServer,
		sServer: sServer,
	}
}

// ServeConn select handler automatically
// all handlers must not write data before proxy protocol verified
func (s *AutoServer) ServeConn(conn net.Conn) error {
	defer conn.Close()

	httpR, httpW := io.Pipe()
	sockR, sockW := io.Pipe()
	go func() {
		defer httpW.Close()
		defer sockW.Close()

		mw := io.MultiWriter(httpW, sockW)

		io.Copy(mw, conn)
	}()

	// HTTP/1.x
	httpErrC := make(chan error)
	go func() {
		httpErrC <- s.hServer.ServeConn(
			&wrapper{Reader: httpR, Writer: conn})
		io.Copy(ioutil.Discard, httpR)
	}()
	// socks5
	sockErrC := make(chan error)
	go func() {
		sockErrC <- s.sServer.ServeConn(
			&wrapper{Reader: sockR, Writer: conn})
		io.Copy(ioutil.Discard, sockR)
	}()

	var httpErr, sockErr error
	for {
		select {
		case httpErr = <-httpErrC:
			httpErrC = nil
		case sockErr = <-sockErrC:
			sockErrC = nil
		}
		if httpErrC == nil && sockErrC == nil {
			break
		}
	}
	if httpErr != nil && sockErr != nil {
		log.WithFields(logrus.Fields{
			"http":  httpErr,
			"socks": sockErr,
		}).Warn("http and socks5 all failed")
		return errors.New("http and socks5 all failed")
	}
	return nil
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
func (c *wrapper) Close() error                       { return nil }
func (c *wrapper) LocalAddr() net.Addr                { return c }
func (c *wrapper) RemoteAddr() net.Addr               { return c }
func (c *wrapper) SetDeadline(t time.Time) error      { return nil }
func (c *wrapper) SetReadDeadline(t time.Time) error  { return nil }
func (c *wrapper) SetWriteDeadline(t time.Time) error { return nil }
func (c *wrapper) Network() string                    { return "warpper" }
func (c *wrapper) String() string                     { return "warpper" }

func NewRevSocksHandler(
	dialCtx func(context.Context, string, string) (net.Conn, error)) *socks5.RevServer {
	cfg := &socks5.Config{
		Dial: dialCtx,
	}
	// reverse proxy not support authentication
	return socks5.NewRev(cfg)
}
