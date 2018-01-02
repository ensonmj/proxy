package proxy

import (
	"testing"
)

// client -> http proxy -> http server
func TestHttpServer(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "http://0:0")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}

func TestHttpServerWithAuth(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "http://user:password@0:0")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}

// client(CONNECT) -> http proxy -> https server
func TestHttpsServer(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "http://0:0")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, true)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}
