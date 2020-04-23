package socks5

import (
	"bufio"
	"context"
	"fmt"
	"net"

	"github.com/ensonmj/proxy/util"
	"github.com/pkg/errors"
)

// RevServer is reponsible for build control tunnel connections and handling
// the details of the SOCKS5 protocol
type RevServer struct {
	config *Config
}

// NewRev creates a new RevServer
func NewRev(conf *Config) *RevServer {
	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	return &RevServer{
		config: conf,
	}
}

func (s *RevServer) ServeConn(_ net.Conn) error {
	ctx := context.Background()

	// connect to client end proxy
	ctrlConn, err := s.config.Dial(ctx, "", "")
	if err != nil {
		return errors.WithStack(err)
	}
	// handshake with client end proxy without auth
	Handshake(ctrlConn, "", "")
	// send CmdRevCtrl to client end proxy, host and port not used
	if err := SendRequest(ctrlConn, CmdRevCtrl, "0", 0); err != nil {
		return errors.WithStack(err)
	}
	// receive CmdRevCtrl reply
	if _, err := ReadReply(ctrlConn); err != nil {
		return errors.WithStack(err)
	}

	for {
		// receive reverse proxy request
		bufReader := bufio.NewReader(ctrlConn)
		req, err := ReadRequest(bufReader)
		if err != nil {
			if err == ErrBadAddrType {
				if err := sendReply(ctrlConn, AddrUnsupported, nil); err != nil {
					return errors.Wrap(err, "[SOCKS5] failed to send reply")
				}
			}
			return errors.Wrap(err, "[SOCKS5] failed to read destination address")
		}

		// Apply any address rewrites
		req.realDestAddr = req.DestAddr
		if s.config.Rewriter != nil {
			ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
		}

		// Resolve the address if we have a FQDN
		if req.realDestAddr.FQDN != "" {
			newCtx, addr, err := s.config.Resolver.Resolve(ctx, req.realDestAddr.FQDN)
			if err != nil {
				if err := sendReply(ctrlConn, HostUnreachable, nil); err != nil {
					return fmt.Errorf("Failed to send reply: %v", err)
				}
				return fmt.Errorf("Failed to resolve destination '%v': %v", req.realDestAddr.FQDN, err)
			}
			ctx = newCtx
			req.realDestAddr.IP = addr
		}

		// Switch on the command
		switch req.Command {
		case CmdConnect:
			// dial target
			target, err := net.Dial("tcp", req.realDestAddr.Address())
			if err != nil {
				resp := netErr2SockErr(err)
				if err := sendReply(ctrlConn, resp, nil); err != nil {
					return fmt.Errorf("Failed to send reply: %v", err)
				}
				return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
			}
			defer target.Close()

			// Send success
			local := target.LocalAddr().(*net.TCPAddr)
			bind := AddrSpec{IP: local.IP, Port: local.Port}
			if err := sendReply(ctrlConn, Succeeded, &bind); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}

			// dial client
			dataConn, err := s.config.Dial(ctx, "", "")
			if err != nil {
				return errors.WithStack(err)
			}
			Handshake(dataConn, "", "")

			// CmdRevData host and port not used
			if err := SendRequest(dataConn, CmdRevData, "0", 0); err != nil {
				return errors.WithStack(err)
			}

			// receive CmdRevData reply
			if _, err := ReadReply(dataConn); err != nil {
				return errors.WithStack(err)
			}

			// Start proxying
			go func() {
				util.ConnIO(target, dataConn, dataConn)
				dataConn.Close()
				target.Close()
			}()
		default:
			if err := sendReply(ctrlConn, CmdUnsupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Unsupported command: %v", req.Command)
		}
	}
}
