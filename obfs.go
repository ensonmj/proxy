package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/pkg/errors"
)

type HttpSimpleObfsHook struct {
	net.Conn
	HookType int
}

func NewHttpSimpleObfsHook() *HttpSimpleObfsHook {
	return &HttpSimpleObfsHook{}
}

func (h *HttpSimpleObfsHook) String() string {
	return fmt.Sprintf("HttpSimpleObfsHook<%p>", h)
}

// attr will not be changed
func (h *HttpSimpleObfsHook) HookConn(c net.Conn, hookType int) net.Conn {
	h.Conn = c
	h.HookType = hookType
	return h
}

func (h *HttpSimpleObfsHook) Read(b []byte) (n int, err error) {
	switch h.HookType {
	case InHook:
		bufReader := bufio.NewReader(h.Conn)
		req, err := http.ReadRequest(bufReader)
		if err != nil {
			return 0, errors.WithStack(err)
		}
		defer req.Body.Close()

		n, _ = req.Body.Read(b)
		return n, nil
	case OutHook:
		bufReader := bufio.NewReader(h.Conn)
		resp, err := http.ReadResponse(bufReader, nil)
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				return 0, io.EOF
			}
			log.WithError(err).Error("read resp")
			return 0, errors.WithStack(err)
		}
		defer resp.Body.Close()

		n, _ = resp.Body.Read(b)
		return n, nil
	default:
		return 0, errors.Errorf("not support hooktype:%d", h.HookType)
	}
}

func (h *HttpSimpleObfsHook) Write(b []byte) (n int, err error) {
	switch h.HookType {
	case InHook:
		resp := &http.Response{
			// Request:       req,
			StatusCode:    http.StatusOK,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header, 0),
			ContentLength: int64(len(b)),
			Body:          ioutil.NopCloser(bytes.NewBuffer(b)),
		}
		resp.Header.Set("Connection", "keep-alive")

		buf := bytes.NewBuffer(nil)
		resp.Write(buf)
		_, err = h.Conn.Write(buf.Bytes())
		// Write must return n equal len(b)
		return len(b), err
	case OutHook:
		req, err := http.NewRequest("GET", "http://"+h.RemoteAddr().String(), bytes.NewBuffer(b))
		if err != nil {
			return 0, errors.WithStack(err)
		}
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Content-Type", "application/grpc")

		buf := bytes.NewBuffer(nil)
		req.Write(buf)
		_, err = h.Conn.Write(buf.Bytes())
		// Write must return n equal len(b)
		return len(b), err
	default:
		return 0, errors.Errorf("not support hooktype:%d", h.HookType)
	}
}
