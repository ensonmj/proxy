package proxy

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"

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
	// Handshake complete authentication with node
	Handshake(net.Conn) error
	// ForwardRequest ask node to connect to next hop(proxy server or target server)
	// return an wrapper net.Conn used for hook
	ForwardRequest(net.Conn, *url.URL) (net.Conn, error)
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
		case "http":
			cn = NewHttpChainNode(*n)
		case "socks5":
			cn = NewSocks5ChainNode(*n)
		default:
			return nil, errors.Errorf("unknown scheme:%s", n.URL.Scheme)
		}
		chain.Nodes = append(chain.Nodes, cn)
	}
	return chain, nil
}

func (pc *ProxyChain) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	log.WithFields(logrus.Fields{
		"chain":   pc,
		"network": network,
		"addr":    addr,
	}).Debug("connect to server with chain")
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
		conn, err = n.ForwardRequest(conn, url)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}
