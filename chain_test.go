package proxy

import (
	"testing"
)

func TestNewProxyChain(t *testing.T) {
	nodes := []string{
		"socks://127.0.0.1:8080",
		"http://127.0.0.1",
	}
	chain, err := NewProxyChain(nodes...)
	if err != nil {
		t.Error(err)
	}
	if len(chain.Nodes) != 2 {
		t.Errorf("expect %d nodes, but got %d\n", 2, len(chain.Nodes))
	}
}

func TestChainProxy(t *testing.T) {
	data := [][]string{
		[]string{"http"},
		[]string{"socks5"},
		[]string{"http", "http"},
		[]string{"http", "socks5"},
		[]string{"socks5", "socks5"},
		[]string{"socks5", "http"},
		[]string{"http", "socks5", "http"},
		[]string{"socks5", "http", "socks5"},
	}

	for _, schemes := range data {
		// chained proxy server
		dialCtx, release := setupChainServers(t, schemes...)

		// local proxy server
		ln := setupProxyServer(t, nil, dialCtx)

		ts := setupHttpServer(t, false)
		tc := setupHttpClient(t, ts, "http", ln.Addr().String())

		// test action
		doTestProxy(t, ts, tc, nil)

		ln.Close()
		release()
	}
}
