package proxy

import (
	"testing"
)

// client -> http proxy -> http server
func TestConnectHttpServer(t *testing.T) {
	ln := setupProxyServer(t, nil, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, nil)
}

func TestConnectHttpServerWithAuth(t *testing.T) {
	n, err := ParseNode("http://user:password@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ln := setupProxyServer(t, n, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}

// client(CONNECT) -> http proxy -> https server
func TestConnectHttpsServer(t *testing.T) {
	ln := setupProxyServer(t, nil, nil)
	defer ln.Close()

	ts := setupHttpServer(t, true)
	tc := setupHttpClient(t, ts, "http", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, nil)
}
