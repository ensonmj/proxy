package proxy

import (
	"testing"
)

func TestSocks5Server(t *testing.T) {
	// socks5 proxy server
	ln := setupProxyServer(t)
	defer ln.Close()

	// test action
	doTestProxy(t, getProxyTransport(t, "socks5", ln.Addr().String()))
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
