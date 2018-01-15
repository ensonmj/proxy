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
	config *Config
	// authMethods map[uint8]Authenticator
	hasPort *regexp.Regexp
	client  http.Client
}

func New(conf *Config) *Server {
	// Ensure we have a dialer
	if conf.Dial == nil {
		conf.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
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

func (h *Server) ServeConn(rw io.ReadWriter) error {
	bufReader := bufio.NewReader(rw)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return errors.WithStack(err)
	}

	// need auth
	if h.config.Credentials != nil {
		// 	log.WithField("node", h.node).Debug("[http] need auth")
		reqUser, reqPass, ok := getBasicAuth(req)
		if !ok {
			// log.WithFields(logrus.Fields{
			// 	"username": reqUser,
			// 	"password": reqPass,
			// 	"ok":       ok,
			// }).Warn("[http] auth failed")
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
			httpResp(rw, req, 500, err.Error())
			return errors.WithStack(err)
		}
		defer targetConn.Close()

		httpResp(rw, req, 200, "")
		// log.WithField("server", host).Debug("[http] success connect to server")

		return connIO(targetConn, rw)
	}

	for {
		if !req.URL.IsAbs() {
			httpResp(rw, req, 500, "[http] proxy requset url is not absolute")
			return errors.New("[http] proxy requset url is not absolute")
		}
		removeProxyHeaders(req)

		resp, err := h.client.Do(req)
		if err != nil {
			httpResp(rw, req, 500, err.Error())
			return errors.WithStack(err)
		}
		resp.Write(rw)

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
	// log.WithFields(logrus.Fields{
	// 	"status": code,
	// 	"body":   body,
	// }).Debug("[http] send response")

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

func connIO(dst, src io.ReadWriter) error {
	srcToDstC := make(chan error)
	dstToSrcC := make(chan error)
	go func() {
		_, err := io.Copy(dst, src)
		srcToDstC <- err
	}()
	go func() {
		_, err := io.Copy(src, dst)
		dstToSrcC <- err
	}()

	var srcToDstErr, dstToSrcErr error
	for {
		select {
		case srcToDstErr = <-srcToDstC:
			srcToDstC = nil
		case dstToSrcErr = <-dstToSrcC:
			dstToSrcC = nil
		}
		if srcToDstC == nil && dstToSrcC == nil {
			break
		}
	}
	if srcToDstErr != nil || dstToSrcC != nil {
		return errors.Errorf("[http] connIO err[%s <=> %s]", dstToSrcErr, srcToDstErr)
	}

	return nil
}