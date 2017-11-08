package proxy

import (
	"testing"
)

func TestSocks5Server(t *testing.T) {
	ln := setupProxyServer(t, nil, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "socks5", ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, nil)
}

func TestSocks5ServerWithAuth(t *testing.T) {
	n, err := ParseNode("http://user:password@127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ln := setupProxyServer(t, nil, nil)
	defer ln.Close()

	ts := setupHttpServer(t, false)
	tc := setupHttpClient(t, ts, "socks5", "user:password@"+ln.Addr().String())

	// test action
	doTestProxy(t, ts, tc, n)
}
