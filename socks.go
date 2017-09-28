package proxy

import (
	"context"
	"io"
	"net"

	"github.com/ensonmj/proxy/socks5"
)

type SocksHandler struct {
	dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (h *SocksHandler) ServeConn(rwc io.ReadWriteCloser) {
	handler := socks5.New(&socks5.Config{
		Dial: h.dialCtx,
	})
	handler.ServeConn(rwc.(net.Conn))
}
