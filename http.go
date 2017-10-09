package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"sync"
)

type HttpHandler struct {
	hasPort *regexp.Regexp
	dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewHttpHandler(dialCtx func(context.Context, string, string) (net.Conn, error)) *HttpHandler {
	if dialCtx == nil {
		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}
	return &HttpHandler{
		hasPort: regexp.MustCompile(`:\d+$`),
		dialCtx: dialCtx,
	}
}

func (h *HttpHandler) ServeConn(rwc io.ReadWriteCloser) {
	defer rwc.Close()

	bufReader := bufio.NewReader(rwc)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		if err != io.EOF {
			log.WithError(err).Error("[http] read http request")
		}
		return
	}
	// buf, _ := dumpRequest(req, false)
	// fmt.Println(string(buf))

	if req.Method == "CONNECT" {
		host := req.URL.Host
		if !h.hasPort.MatchString(host) {
			host += ":80"
		}
		targetConn, err := h.dialCtx(req.Context(), "tcp", host)
		if err != nil {
			httpResp(rwc, req, 500, err.Error())
			return
		}
		defer targetConn.Close()
		httpResp(rwc, req, 200, "")
		log.WithField("host", host).Debug("[http] success dial server")

		connIO(targetConn, rwc)

		return
	}

	for {
		if !req.URL.IsAbs() {
			httpResp(rwc, req, 500,
				"This is a proxy server. Does not respond to non-proxy requests.")
			return
		}

		removeProxyHeaders(req)

		tr := &http.Transport{
			DialContext: h.dialCtx,
		}
		resp, _ := tr.RoundTrip(req)
		resp.Write(rwc)

		req, err = http.ReadRequest(bufReader)
		if err != nil {
			if err != io.EOF {
				log.WithError(err).Error("[http] read http request")
			}
			return
		}
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

func connIO(dst, src io.ReadWriter) {
	var wg sync.WaitGroup
	wg.Add(2)

	go copyData(dst, src, &wg)
	go copyData(src, dst, &wg)

	wg.Wait()
}

func copyData(dst io.Writer, src io.Reader, wg *sync.WaitGroup) {
	if _, err := io.Copy(dst, src); err != nil && err != io.EOF {
		log.WithError(err).Error("[http] copy connection content")
	}

	wg.Done()
}