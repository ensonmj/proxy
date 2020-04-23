package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/ensonmj/proxy/cred"
	"github.com/ensonmj/proxy/util"
	"github.com/pkg/errors"
)

// Config is used to setup and configure a Server
type Config struct {
	// If provided, username/password authentication is enabled,
	Credentials cred.CredentialStore

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config  *Config
	hasPort *regexp.Regexp
	client  http.Client
}

func New(conf *Config) *Server {
	// Ensure we have a dialer
	if conf.Dial == nil {
		conf.Dial = func(_ context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	server := &Server{
		config:  conf,
		hasPort: regexp.MustCompile(`:\d+$`),
		client: http.Client{
			Transport: &http.Transport{
				DialContext: conf.Dial,
			},
		},
	}

	return server
}

func (h *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()

	bufReader := bufio.NewReader(conn)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return errors.WithStack(err)
	}

	// need auth
	if h.config.Credentials != nil {
		reqUser, reqPass, ok := getBasicAuth(req)
		if !ok {
			return errors.New("[http] auth failed")
		}

		// Verify the password
		if !h.config.Credentials.Valid(reqUser, reqPass) {
			return errors.New("[http] auth failed")
		}
	}

	if req.Method == "CONNECT" {
		host := req.Host
		if !h.hasPort.MatchString(host) {
			host += ":80"
		}
		targetConn, err := h.config.Dial(req.Context(), "tcp", host)
		if err != nil {
			httpResp(conn, req, 500, err.Error())
			return errors.WithStack(err)
		}
		defer targetConn.Close()

		httpResp(conn, req, 200, "")

		return util.ConnIO(targetConn, conn, bufReader)
	}

	for {
		if !req.URL.IsAbs() {
			httpResp(conn, req, 500, "[http] proxy requset url is not absolute")
			return errors.New("[http] proxy requset url is not absolute")
		}
		removeProxyHeaders(req)

		resp, err := h.client.Do(req)
		if err != nil {
			httpResp(conn, req, 500, err.Error())
			return errors.WithStack(err)
		}
		resp.Write(conn)

		req, err = http.ReadRequest(bufReader)
		if err != nil {
			if err != io.EOF {
				return errors.WithStack(err)
			}
			return nil
		}
	}
}

func getBasicAuth(req *http.Request) (username, password string, ok bool) {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
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
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")

	// cache all bytes to only write once
	buf := bytes.NewBuffer(nil)
	resp.Write(buf)
	w.Write(buf.Bytes())
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
