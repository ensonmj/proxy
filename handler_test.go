package proxy

import "testing"

// client -> http proxy -> http server
func TestHttpHandler(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "http://0:0")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}

func TestHttpHandlerWithAuth(t *testing.T) {
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
func TestHttpsHandler(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "http://0:0")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, true)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}

func TestSocks5Handler(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "socks5://0:0")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "socks5", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}

func TestSocks5HandlerWithAuth(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "socks5://user:password@0:0/?rto=5")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "socks5", "user:password@"+ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}
