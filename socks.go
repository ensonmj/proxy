package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"

	"github.com/ensonmj/proxy/socks5"
	"github.com/pkg/errors"
)

type SocksHandler struct {
	node    *Node
	dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
	cfg     *socks5.Config
}

func NewSocksHandler(
	n *Node,
	dialCtx func(context.Context, string, string) (net.Conn, error)) *SocksHandler {
	if dialCtx == nil {
		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}
	cfg := &socks5.Config{
		Dial: dialCtx,
	}
	if n != nil && n.URL.User != nil {
		user := n.URL.User.Username()
		pass, _ := n.URL.User.Password()
		cred := socks5.StaticCredentials{
			user: pass,
		}
		cator := socks5.UserPassAuthenticator{Credentials: cred}
		cfg.AuthMethods = []socks5.Authenticator{cator}
	}
	return &SocksHandler{
		node:    n,
		dialCtx: dialCtx,
		cfg:     cfg,
	}
}

func (h *SocksHandler) ServeConn(rwc io.ReadWriteCloser) {
	handler := socks5.New(h.cfg)
	handler.ServeConn(rwc.(net.Conn))
}
