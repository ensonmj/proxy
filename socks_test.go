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

// func TestSocks5Auth(t *testing.T) {
// 	// socks5 proxy server
// 	n, _ := ParseProxyNode("socks://test:test@127.0.0.1:8080")
// 	defer setupSocks5Server(n, nil).Close()

// 	// http client transport
// 	dialer, err := proxy.FromURL(&n.URL, proxy.Direct)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	err = setupSrvAndClient(&http.Transport{Dial: dialer.Dial})
// 	if err != nil {
// 		t.Error(err)
// 	}
// }
