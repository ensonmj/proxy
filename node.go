package proxy

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type Node struct {
	URL url.URL
}

func (n Node) String() string {
	return n.URL.String()
}

func (n Node) Addr() string {
	return n.URL.Scheme + "://" + n.URL.Host
}

// [scheme:][//[userinfo@]host][/]path[?query][#fragment]
func ParseNode(rawurl string) (*Node, error) {
	if !strings.Contains(rawurl, "://") {
		rawurl = "http://" + rawurl
	}

	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse node")
	}

	// http/https/http2/socks5/tcp/udp/rtcp/rudp/ss/ws/wss
	switch url.Scheme {
	case "http", "socks5":
	case "socks":
		url.Scheme = "socks5"
	default:
		return nil, errors.Errorf("scheme:%s not support\n", url.Scheme)
	}

	log.Printf("success to parse node: %s\n", url.String())
	return &Node{
		URL: *url,
	}, nil
}
