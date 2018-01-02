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
		[]string{
			"http://0:0",
		},
		[]string{
			"socks5://0:0",
		},
		[]string{
			"http://0:0",
			"http://0:0",
		},
		[]string{
			"http://0:0",
			"socks5://0:0",
		},
		[]string{
			"socks5://0:0",
			"socks5://0:0",
		},
		[]string{
			"socks5://0:0",
			"http://0:0",
		},
		[]string{
			"http://0:0",
			"socks5://0:0",
			"http://0:0",
		},
		[]string{
			"socks5://0:0",
			"http://0:0",
			"socks5://0:0",
		},
	}

	for _, urls := range data {
		t.Logf("test %#v chain server", urls)
		// chained proxy server
		dialCtx, release := setupChainServers(t, urls...)

		// node for both client and proxy server
		n := setupNode(t, "ghost://0:0")

		// local proxy server
		ln := setupProxyServer(t, n, dialCtx)

		ts := setupHttpServer(t, false)
		tc := setupHttpClient(t, ts, "http", ln.Addr().String())

		// test action
		doTestProxy(t, ts, tc, n)

		ln.Close()
		release()
	}
}
