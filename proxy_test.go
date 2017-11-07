package proxy

import (
	"context"
	"flag"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/sirupsen/logrus"

	"golang.org/x/net/proxy"
)

func TestMain(m *testing.M) {
	setup()
	ret := m.Run()
	teardown()
	os.Exit(ret)
}

func setup() {
	flag.Parse()
	if testing.Verbose() {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.PanicLevel)
		log.Out = ioutil.Discard
	}
}

func teardown() {}

func setupProxyServer(t *testing.T,
	n *Node,
	dialCtx func(context.Context, string, string) (net.Conn, error)) net.Listener {
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
		handleConn(n, conn, dialCtx)
	}()

	t.Logf("proxy server listen at %s", ln.Addr().String())
	return ln
}

func setupHttpServer(t *testing.T, useTLS bool) *httptest.Server {
	if useTLS {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("get http request from %s", r.RemoteAddr)
			io.WriteString(w, "success")
		}))
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("get http request from %s", r.RemoteAddr)
		io.WriteString(w, "success")
	}))
}

func setupHttpClient(t *testing.T, ts *httptest.Server, scheme string, addr string) *http.Client {
	t.Helper()

	proxyAddr := scheme + "://" + addr
	t.Logf("use proxy[%s] to connect http server[%s]", proxyAddr, ts.Listener.Addr().String())

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	tc := ts.Client()

	switch scheme {
	case "http":
		if tr, ok := tc.Transport.(*http.Transport); ok {
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

			tr.Dial = dialer.Dial

			return tc
		}
		t.Fatal("failed to type assert http.Transport")
	default:
		t.Fatalf("unknown scheme[%s]", scheme)
	}

	return nil
}

func doTestProxy(t *testing.T, ts *httptest.Server, tc *http.Client, n *Node) {
	t.Helper()

	defer ts.Close()

	// do http request with proxy
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != nil && n.URL.User != nil {
		user := n.URL.User.Username()
		pass, _ := n.URL.User.Password()
		t.Logf("http request with username:%s, password:%s", user, pass)
		req.Header.Set("Proxy-Authorization", basicAuth(user, pass))
	}
	// buf, _ := dumpRequest(req, false)
	// fmt.Println(string(buf))

	resp, err := tc.Do(req)
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
