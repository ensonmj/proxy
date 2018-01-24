package proxy

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type Node struct {
	URL          url.URL
	hooks        []Hook
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (n Node) String() string {
	return fmt.Sprintf(`{Addr:"%s", Hooks:%v, RT:%d, WT:%d}`,
		n.URL.String(), n.hooks, n.ReadTimeout, n.WriteTimeout)
}

func (n Node) Addr() string {
	return n.URL.Scheme + "://" + n.URL.Host
}

// [scheme:][//[userinfo@]host][/]path[?query][#fragment]
func ParseNode(rawurl string) (*Node, error) {
	if !strings.Contains(rawurl, "://") {
		rawurl = "ghost://" + rawurl
	}

	url, err := url.Parse(rawurl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse node")
	}

	// ghost/http/https/socks5
	switch url.Scheme {
	case "ghost", "http", "socks5":
	case "https":
		url.Scheme = "http"
	case "socks":
		url.Scheme = "socks5"
	default:
		return nil, errors.Errorf("scheme:%s not support\n", url.Scheme)
	}

	n := &Node{
		URL: *url,
	}

	// rto := 5 * time.Minute
	// wto := 5 * time.Minute
	// if r := url.Query().Get("rto"); r != "" {
	// 	if rt, err := strconv.Atoi(r); err == nil {
	// 		rto = time.Duration(rt) * time.Second
	// 	}
	// }
	// if w := url.Query().Get("wto"); w != "" {
	// 	if wt, err := strconv.Atoi(w); err == nil {
	// 		wto = time.Duration(wt) * time.Second
	// 	}
	// }
	// n.hooks = []Hook{NewTimeoutHook(rto, wto)}

	switch url.Query().Get("obfs") {
	case "http-simple":
		n.hooks = append(n.hooks, NewHttpSimpleObfsHook())
	}

	return n, nil
}
