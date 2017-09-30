package proxy

import (
	"context"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/net/proxy"
)

func setupProxyServer(t *testing.T, dialCtx func(context.Context, string, string) (net.Conn, error)) net.Listener {
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
		handleConn(conn, dialCtx)
	}()

	t.Logf("proxy server listen at:%s", ln.Addr().String())
	return ln
}

func setupHttpServer(t *testing.T, useTLS bool) *httptest.Server {
	if useTLS {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "success")
		}))
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "success")
	}))
}

func setupHttpClient(t *testing.T, ts *httptest.Server, scheme string, addr string) *http.Client {
	t.Helper()

	proxyAddr := scheme + "://" + addr
	t.Logf("use proxy:%s", proxyAddr)

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	tc := ts.Client()

	switch scheme {
	case "http":
		if tr, ok := tc.Transport.(*http.Transport); ok {
			// tr.DisableKeepAlives = true
			// tr.TLSClientConfig.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}
			tr.Proxy = http.ProxyURL(proxyURL)
			return tc
		}
		t.Fatal("failed to type assert http.Transport")
	case "socks5":
		if tr, ok := tc.Transport.(*http.Transport); ok {
			dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
			if err != nil {
				t.Error(err)
			}

			// tr.DisableKeepAlives = true
			// tr.TLSClientConfig.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}
			tr.Dial = dialer.Dial

			return tc
		}
		t.Fatal("failed to type assert http.Transport")
	default:
		t.Fatalf("unknown scheme[%s]", scheme)
	}

	return nil
}

func doTestProxy(t *testing.T, ts *httptest.Server, tc *http.Client) {
	t.Helper()

	defer ts.Close()

	// do http request with proxy
	resp, err := tc.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	txt, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
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
