package proxy

import (
	"testing"
)

func TestHttpHandler(t *testing.T) {
	// proxy server
	ln := setupProxyServer(t)
	defer ln.Close()

	doTestProxy(t, getProxyTransport(t, "http", ln.Addr().String()))
}
