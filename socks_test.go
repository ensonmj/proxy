package proxy

import (
	"testing"
)

func TestSocks5Server(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "socks5://0:0")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "socks5", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}

func TestSocks5ServerWithAuth(t *testing.T) {
	// node for both client and proxy server
	n := setupNode(t, "socks5://user:password@0:0/?rto=5")

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "socks5", "user:password@"+ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}
