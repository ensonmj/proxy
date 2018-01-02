package proxy

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// hook type
const (
	InHook = iota
	OutHook
)

// ****************************************************************************
// hook is an net.Conn wrapper actually
// outer wrapper's Write() will call before inner
// outer wrapper's Read() will calll after inner
//
//                write  read
//                  +     ^
//                  |     |
//   +----------------------------------+
//   |hook          |     |             |
//   |     +-----------------------+    |
//   |     |hook    |     |        |    |
//   |     |    +---v-----+---+    |    |
//   |     |    |conn         |    |    |
//   |     |    |             |    |    |
//   |     |    +-------------+    |    |
//   |     |                       |    |
//   |     +-----------------------+    |
//   |                                  |
//   +----------------------------------+
//
// ****************************************************************************
type Hook interface {
	String() string
	// HookConn return an instance with modified Read/Write method wrap the orignal.
	// You *must* return the *cloned* instance in case of attr of the instance
	// will be changed according to every connection.
	// You *can* return the original instance in case of nothing will be changed.
	HookConn(net.Conn, int) net.Conn
	net.Conn
}

func WithInHooks(c net.Conn, hooks ...Hook) net.Conn {
	return WithHooks(c, InHook, hooks...)
}

func WithOutHooks(c net.Conn, hooks ...Hook) net.Conn {
	return WithHooks(c, OutHook, hooks...)
}

func WithHooks(c net.Conn, hookType int, hooks ...Hook) net.Conn {
	for _, h := range hooks {
		c = h.HookConn(c, hookType)
	}
	return c
}

type TimeoutHook struct {
	net.Conn
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func NewTimeoutHook(params map[string]string) *TimeoutHook {
	rto := 5 * time.Minute
	wto := 5 * time.Minute
	if rtoStr, ok := params["rto"]; ok {
		if rt, err := strconv.Atoi(rtoStr); err == nil {
			rto = time.Duration(rt) * time.Second
		}
	}
	if wtoStr, ok := params["wto"]; ok {
		if wt, err := strconv.Atoi(wtoStr); err == nil {
			wto = time.Duration(wt) * time.Second
		}
	}
	return &TimeoutHook{
		ReadTimeout:  rto,
		WriteTimeout: wto,
	}
}

func (h *TimeoutHook) String() string {
	return fmt.Sprintf("TimeoutHook<%p>", h)
}

// attr will not be changed
func (h *TimeoutHook) HookConn(c net.Conn, hookType int) net.Conn {
	h.Conn = c
	return h
}

func (h *TimeoutHook) Read(b []byte) (n int, err error) {
	h.Conn.SetReadDeadline(time.Now().Add(h.ReadTimeout))
	return h.Conn.Read(b)
}

func (h *TimeoutHook) Write(b []byte) (n int, err error) {
	h.Conn.SetWriteDeadline(time.Now().Add(h.WriteTimeout))
	return h.Conn.Write(b)
}
