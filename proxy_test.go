package proxy

import (
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/net/proxy"
)

func doTestProxy(t *testing.T, tr *http.Transport) {
	t.Helper()

	// http server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "success")
	}))
	defer srv.Close()

	// http client with proxy
	client := &http.Client{Transport: tr}

	// do http request with proxy
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	txt, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("got %d:%s\n", resp.StatusCode, txt)
	}
	if string(txt) != "success" {
		t.Fatalf("expect success, but got %s\n", txt)
	}
	t.Log("proxy test success")
}

func setupProxyServer(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		handleConn(conn, nil)
	}()

	t.Logf("proxy server listen at:%s", ln.Addr().String())
	return ln
}

func getProxyTransport(t *testing.T, scheme string, addr string) *http.Transport {
	t.Helper()

	proxyAddr := scheme + "://" + addr
	proxyURL, err := url.Parse(proxyAddr)
	t.Logf("proxy scheme:%s", scheme)
	if err != nil {
		t.Fatal(err)
	}

	switch scheme {
	case "http":
		return &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	case "socks5":
		dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			t.Error(err)
		}
		return &http.Transport{Dial: dialer.Dial}
	default:
		t.Fatalf("unknown scheme[%s]", scheme)
		return nil
	}
}
