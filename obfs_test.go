package proxy

import (
	"testing"
)

func TestChainProxyWithSimpleObfs(t *testing.T) {
	data := [][]string{
		[]string{
			"http://0:0/?obfs=http-simple",
		},
		[]string{
			"socks5://0:0/?obfs=http-simple",
		},
		[]string{
			"http://0:0/?obfs=http-simple",
			"http://0:0/?obfs=http-simple",
		},
		[]string{
			"http://0:0/?obfs=http-simple",
			"socks5://0:0/?obfs=http-simple",
		},
		[]string{
			"socks5://0:0/?obfs=http-simple",
			"socks5://0:0/?obfs=http-simple",
		},
		[]string{
			"socks5://0:0/?obfs=http-simple",
			"http://0:0/?obfs=http-simple",
		},
		[]string{
			"http://0:0/?obfs=http-simple",
			"socks5://0:0/?obfs=http-simple",
			"http://0:0/?obfs=http-simple",
		},
		[]string{
			"socks5://0:0/?obfs=http-simple",
			"http://0:0/?obfs=http-simple",
			"socks5://0:0/?obfs=http-simple",
		},
	}

	for _, urls := range data {
		t.Logf("test %#v chain server", urls)
		// chained proxy server
		dialCtx, release := setupChainServers(t, urls...)

		// node for both client and proxy server
		n := setupNode(t, "http://0:0")

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
