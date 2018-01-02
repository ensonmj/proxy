package proxy

import (
	"context"
	"io"
	"net"
	"net/url"
	"strconv"

	"github.com/ensonmj/gosocks5"
	"github.com/ensonmj/proxy/socks5"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// *********************************** proxy **********************************
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

func (h *SocksHandler) ServeConn(rw io.ReadWriter) error {
	handler := socks5.New(h.cfg)
	return handler.ServeConn(rw)
}

// *********************************** chain **********************************
type Socks5ChainNode struct {
	*Node
}

func NewSocks5ChainNode(n *Node) *Socks5ChainNode {
	return &Socks5ChainNode{
		Node: n,
	}
}

func (n *Socks5ChainNode) URL() *url.URL {
	return &n.Node.URL
}

func (n *Socks5ChainNode) Connect() (net.Conn, error) {
	conn, err := net.Dial("tcp", n.URL().Host)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return conn, err
}

func (n *Socks5ChainNode) RegisterHook(c net.Conn) net.Conn {
	return WithOutHooks(c, n.Node.hooks...)
}

func (n *Socks5ChainNode) Handshake(c net.Conn) error {
	conn := gosocks5.ClientConn(c, gosocks5.NewAuthenticator([]*url.Userinfo{n.Node.URL.User}))
	if err := conn.Handleshake(); err != nil {
		return errors.Wrap(err, "handleshake")
	}

	return nil
}

func (n *Socks5ChainNode) ForwardRequest(c net.Conn, url *url.URL) error {
	log.WithFields(logrus.Fields{
		"chainnode": *n.Node,
		"hop":       url.Host,
	}).Debugf("forward request to next hop by SOCKS5")
	addr, err := parseAddr(url.Host)
	if err != nil {
		return err
	}
	req := gosocks5.NewRequest(gosocks5.CmdConnect, addr)

	if err := req.Write(c); err != nil {
		return errors.Wrap(err, "forward request")
	}

	resp, err := gosocks5.ReadReply(c)
	if err != nil {
		return errors.Wrap(err, "read socks reply")
	}
	if resp.Rep != gosocks5.Succeeded {
		return errors.New("proxy refused connection")
	}

	return nil
}

func parseAddr(addr string) (*gosocks5.Addr, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var typ uint8
	if ip := net.ParseIP(host); ip == nil {
		typ = gosocks5.AddrDomain
	} else {
		if ip4 := ip.To4(); ip4 != nil {
			typ = gosocks5.AddrIPv4
		} else {
			typ = gosocks5.AddrIPv6
		}
	}

	p, _ := strconv.Atoi(port)

	return &gosocks5.Addr{
		Type: typ,
		Host: host,
		Port: uint16(p),
	}, nil
}
