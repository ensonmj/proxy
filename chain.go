package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ensonmj/proxy/socks5"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const DialTimeout = 1 * time.Second

type ChainNode interface {
	// URL return the url.URL of current node
	URL() *url.URL
	// Connect only used for first node of the chain
	// this net.Conn not used for hook
	Connect() (net.Conn, error)
	// RegisterHook register hook before Handshake for data process
	RegisterHook(net.Conn) net.Conn
	// Handshake complete authentication with node
	Handshake(net.Conn) error
	// ForwardRequest ask node to connect to next hop(proxy server or target server)
	ForwardRequest(net.Conn, *url.URL) error
}

// Proxy chain holds a list of proxy nodes
type ProxyChain struct {
	Nodes []ChainNode
}

func NewProxyChain(urls ...string) (*ProxyChain, error) {
	chain := &ProxyChain{}
	for _, url := range urls {
		n, err := ParseNode(url)
		if err != nil {
			return nil, err
		}
		var cn ChainNode
		switch n.URL.Scheme {
		case "http", "ghost":
			cn = NewHttpChainNode(n)
		case "socks5":
			cn = NewSocks5ChainNode(n)
		default:
			return nil, errors.Errorf("unknown scheme:%s", n.URL.Scheme)
		}
		chain.Nodes = append(chain.Nodes, cn)
	}
	return chain, nil
}

func (pc *ProxyChain) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	log.WithFields(logrus.Fields{
		"network": network,
		"target":  addr,
		"chain":   pc,
	}).Debug("connecting to target with chain")
	if len(pc.Nodes) == 0 {
		return net.DialTimeout(network, addr, DialTimeout)
	}

	headNode := pc.Nodes[0]
	conn, err := headNode.Connect()
	if err != nil {
		return nil, err
	}

	lastIdx := len(pc.Nodes) - 1
	for i, n := range pc.Nodes {
		//regitster hook
		conn = n.RegisterHook(conn)

		// handshake with current hop
		n.Handshake(conn)

		// ask connect to next hop or target server
		var url *url.URL
		if i < lastIdx {
			// next chain hop
			url = pc.Nodes[i+1].URL()
		} else {
			// the target server
			if !strings.Contains(addr, "://") {
				addr = "http://" + addr
			}
			url, err = url.Parse(addr)
			if err != nil {
				return nil, errors.WithStack(err)
			}
		}
		if err := n.ForwardRequest(conn, url); err != nil {
			return nil, err
		}
	}

	return conn, nil
}

type HttpChainNode struct {
	*Node
}

func NewHttpChainNode(n *Node) *HttpChainNode {
	return &HttpChainNode{
		Node: n,
	}
}

func (n *HttpChainNode) URL() *url.URL {
	return &n.Node.URL
}

func (n *HttpChainNode) Connect() (net.Conn, error) {
	log.WithField("chainnode", *n.Node).Debug("connect to chain")
	conn, err := net.Dial("tcp", n.URL().Host)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return conn, err
}

func (n *HttpChainNode) RegisterHook(c net.Conn) net.Conn {
	return WithOutHooks(c, n.Node.hooks...)
}

func (n *HttpChainNode) Handshake(c net.Conn) error {
	log.WithField("chainnode", *n.Node).Debug("handshake with http chain node")
	return nil
}

func (n *HttpChainNode) ForwardRequest(c net.Conn, uri *url.URL) error {
	log.WithFields(logrus.Fields{
		"chainnode": *n.Node,
		"hop":       uri.Host,
	}).Debugf("forward request to next hop by HTTP")
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Opaque: uri.Host},
		Host:       uri.Host,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	req.Header.Set("Proxy-Connection", "keep-alive")
	if uri.User != nil {
		user := uri.User.Username()
		pass, _ := uri.User.Password()
		req.Header.Set("Proxy-Authorization", basicAuth(user, pass))
	}
	if err := req.Write(c); err != nil {
		return errors.Wrap(err, "forward request")
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return errors.Wrap(err, "forward request read response")
	}
	if resp.StatusCode != http.StatusOK {
		resp, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "forward request clear body")
		}
		return errors.New("proxy refused connection: " + string(resp))
	}

	return nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

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
	var username, password string
	user := n.Node.URL.User
	if user != nil {
		username = user.Username()
		password, _ = user.Password()
	}
	return socks5.Handshake(c, username, password)
}

func (n *Socks5ChainNode) ForwardRequest(c net.Conn, url *url.URL) error {
	log.WithFields(logrus.Fields{
		"chainnode": *n.Node,
		"hop":       url.Host,
	}).Debugf("forward request to next hop by SOCKS5")
	host, port, err := net.SplitHostPort(url.Host)
	if err != nil {
		return errors.WithStack(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := socks5.SendRequest(c, socks5.CmdConnect, host, uint16(p)); err != nil {
		return err
	}
	_, err = socks5.ReadReply(c)
	return err
}
