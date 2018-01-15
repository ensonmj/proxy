package proxy

import (
	"context"
	"net"
	"net/url"

	"github.com/ensonmj/proxy/cred"
	"github.com/ensonmj/proxy/httpproxy"
	"github.com/ensonmj/proxy/socks5"
)

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
