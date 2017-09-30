package proxy

import (
	"testing"
)

// client -> http proxy -> http server
func TestConnectHttpServer(t *testing.T) {
	ln := setupProxyServer(t, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc)
}

// client(CONNECT) -> http proxy -> https server
func TestConnectHttpsServer(t *testing.T) {
	ln := setupProxyServer(t, nil)
	defer ln.Close()

	ts := setupHttpServer(t, true)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc)
}
