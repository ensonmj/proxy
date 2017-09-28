package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
)

type HttpHandler struct {
	hasPort *regexp.Regexp
	dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewHttpHandler(dialCtx func(context.Context, string, string) (net.Conn, error)) *HttpHandler {
	return &HttpHandler{
		hasPort: regexp.MustCompile(`:\d+$`),
		dialCtx: dialCtx,
	}
}

func (h *HttpHandler) ServeConn(rwc io.ReadWriteCloser) {
	for {
		req, err := http.ReadRequest(bufio.NewReader(rwc))
		if err != nil {
			if err != io.EOF {
				log.WithError(err).Error("[http] read http request")
			}
			return
		}
		// buf, _ := dumpRequest(req, false)
		// fmt.Println(string(buf))
		tr := &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: 1000,
			DisableKeepAlives:   true,
			DialContext:         h.dialCtx,
		}

		if req.Method == "CONNECT" {
			host := req.URL.Host
			if !h.hasPort.MatchString(host) {
				host += ":80"
			}
			targetSiteCon, err := tr.Dial("tcp", host)
			if err != nil {
				httpResp(rwc, req, 500, err.Error())
				return
			}
			httpResp(rwc, req, 200, "")

			go copyAndClose(targetSiteCon, rwc)
			go copyAndClose(rwc, targetSiteCon)

			return
		}

		if !req.URL.IsAbs() {
			httpResp(rwc, req, 500,
				"This is a proxy server. Does not respond to non-proxy requests.")
			return
		}

		removeProxyHeaders(req)
		resp, _ := tr.RoundTrip(req)
		resp.Write(rwc)
	}
}

func httpResp(w io.Writer, req *http.Request, code int, body string) {
	resp := &http.Response{
		Request:       req,
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header, 0),
		ContentLength: int64(len(body)),
	}
	if len(body) > 0 {
		resp.Body = ioutil.NopCloser(bytes.NewBufferString(body))

	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("X-Content-Type-Options", "nosniff")

	resp.Write(w)
}

func removeProxyHeaders(req *http.Request) {
	// this must be reset when serving a request with the client
	req.RequestURI = ""

	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	req.Header.Del("Accept-Encoding")

	// curl can add that, see
	// https://jdebp.eu./FGA/web-proxy-connection-header.html
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")

	// Connection, Authenticate and Authorization are single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.
	req.Header.Del("Connection")
}

func copyAndClose(dst io.WriteCloser, src io.ReadCloser) {
	if _, err := io.Copy(dst, src); err != nil {
		log.WithError(err).Error("[http] copy content")
	}

	dst.Close()
	src.Close()
}
