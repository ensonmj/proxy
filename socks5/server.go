package socks5

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/ensonmj/proxy/cred"
	"github.com/ensonmj/proxy/util"
	"github.com/pkg/errors"
)

var (
	gRevConnLocker sync.Mutex
	gRevConns      []net.Conn
)

// A Request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	// AddrSpec of the actual destination (might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials cred.CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

// New creates a new Server
func New(conf *Config) *Server {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a dialer
	if conf.Dial == nil {
		conf.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	server := &Server{
		config:      conf,
		authMethods: make(map[uint8]Authenticator),
	}

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(rw io.ReadWriter) error {
	bufReader := bufio.NewReader(rw)

	// Read the version byte
	version := []byte{0}
	if _, err := bufReader.Read(version); err != nil {
		return errors.Wrap(err, "[SOCKS5] failed to get version byte")
	}

	// Ensure we are compatible
	if version[0] != SocksVer5 {
		return errors.Errorf("[SOCKS5] unsupported SOCKS version[%v]", version)
	}

	// Authenticate the connection
	authContext, err := s.authenticate(rw, bufReader)
	if err != nil {
		return errors.Wrap(err, "[SOCKS5] failed to authenticate")
	}

	request, err := ReadRequest(bufReader)
	if err != nil {
		if err == ErrBadAddrType {
			if err := sendReply(rw, AddrUnsupported, nil); err != nil {
				return errors.Wrap(err, "[SOCKS5] failed to send reply")
			}
		}
		return errors.Wrap(err, "[SOCKS5] failed to read destination address")
	}
	request.AuthContext = authContext

	// Process the client request
	if err := s.handleRequest(request, rw); err != nil {
		return errors.Wrap(err, "[SOCKS5] failed to handle request")
	}

	return nil
}

// authenticate is used to handle connection authentication
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader) (*AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return nil, err
	}

	// Select a usable method
	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			return cator.Authenticate(bufConn, conn)
		}
	}

	// No usable method found
	return nil, noAcceptableAuth(conn)
}

// ReadRequest creates a new Request from the tcp connection
func ReadRequest(bufConn io.Reader) (*Request, error) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return nil, ErrBadFormat
	}

	// Ensure we are compatible
	if header[0] != SocksVer5 {
		return nil, ErrBadVersion
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  SocksVer5,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}

	return request, nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(req *Request, conn io.Writer) error {
	ctx := context.Background()

	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}

	// Resolve the address if we have a FQDN
	dest := req.realDestAddr
	if dest.FQDN != "" {
		newCtx, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, HostUnreachable, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		ctx = newCtx
		req.realDestAddr.IP = addr
	}

	// Switch on the command
	switch req.Command {
	case CmdConnect:
		return s.handleConnect(ctx, conn, req)
	case CmdBind:
		return s.handleBind(ctx, conn, req)
	case CmdAssociate:
		return s.handleAssociate(ctx, conn, req)
	case CmdListen:
		return s.handleListen(ctx, conn, req)
	case CmdRevConn:
		return s.handleRevConn(ctx, conn, req)
	default:
		if err := sendReply(conn, CmdUnsupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn io.Writer, req *Request) error {
	// Attempt to connect
	dial := s.config.Dial
	target, err := dial(ctx, "tcp", req.realDestAddr.Address())
	if err != nil {
		resp := netErr2SockErr(err)
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, Succeeded, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	return util.ConnIO(target, conn, req.bufConn)
}

// handleBind is used to handle a bind command
func (s *Server) handleBind(ctx context.Context, conn io.Writer, req *Request) error {
	// TODO: Support bind
	if err := sendReply(conn, CmdUnsupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a associate command
func (s *Server) handleAssociate(ctx context.Context, conn io.Writer, req *Request) error {
	// TODO: Support associate
	if err := sendReply(conn, CmdUnsupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// handleListen is used to handle a listen command in client end proxy
func (s *Server) handleListen(ctx context.Context, conn io.Writer, req *Request) error {
	ln, err := net.Listen("tcp", req.realDestAddr.Address())
	if err != nil {
		if err := sendReply(conn, Failure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return errors.WithStack(err)
	}
	defer ln.Close()

	// Send success
	if err := sendReply(conn, Succeeded, req.DestAddr); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	for {
		client, err := ln.Accept()
		if err != nil {
			return err
		}

		bufReader := bufio.NewReader(client)

		// Read the version byte
		version := []byte{0}
		if _, err := bufReader.Read(version); err != nil {
			return errors.Wrap(err, "[SOCKS5] failed to get version byte")
		}

		// Ensure we are compatible
		if version[0] != SocksVer5 {
			return errors.Errorf("[SOCKS5] unsupported SOCKS version[%v]", version)
		}

		// Authenticate the connection
		authContext, err := s.authenticate(client, bufReader)
		if err != nil {
			return errors.Wrap(err, "[SOCKS5] failed to authenticate")
		}

		request, err := ReadRequest(bufReader)
		if err != nil {
			if err == ErrBadAddrType {
				if err := sendReply(client, AddrUnsupported, nil); err != nil {
					return errors.Wrap(err, "[SOCKS5] failed to send reply")
				}
			}
			return errors.Wrap(err, "[SOCKS5] failed to read destination address")
		}
		request.AuthContext = authContext

		// request to build reverse connection
		host := request.DestAddr.Hostname()
		p := request.DestAddr.Port
		if err := SendRequest(conn, CmdConnect, host, uint16(p)); err != nil {
			return errors.WithStack(err)
		}

		// TODO: make sure multi connections keep order?
		gRevConnLocker.Lock()
		gRevConns = append(gRevConns, client)
		gRevConnLocker.Unlock()
	}
}

// handleListen is used to handle a listen command in client end proxy
func (s *Server) handleRevConn(ctx context.Context, conn io.Writer, req *Request) error {
	// TODO: make sure multi connections keep order?
	gRevConnLocker.Lock()
	client := gRevConns[0]
	gRevConns = gRevConns[1:]
	gRevConnLocker.Unlock()

	// Send success
	local := client.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, Succeeded, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// local := client.LocalAddr().(*net.TCPAddr)
	// bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(client, Succeeded, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	return util.ConnIO(client, conn, req.bufConn)
}

// RevServeConn is used to dispatch reverse connection.
func (s *Server) RevServeConn(url url.URL) error {
	ctx := context.Background()

	// connect to client end proxy
	ctrlConn, err := s.config.Dial(ctx, "", "")
	if err != nil {
		return errors.WithStack(err)
	}
	// handshake with client end proxy without auth
	Handshake(ctrlConn, "", "")
	// send CmdListen to client end proxy
	host := url.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}
	p, err := strconv.Atoi(url.Port())
	if err != nil {
		return errors.WithStack(err)
	}
	if err := SendRequest(ctrlConn, CmdListen, host, uint16(p)); err != nil {
		return errors.WithStack(err)
	}
	// receive CmdListen reply
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
		dest := req.realDestAddr
		if dest.FQDN != "" {
			newCtx, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
			if err != nil {
				if err := sendReply(ctrlConn, HostUnreachable, nil); err != nil {
					return fmt.Errorf("Failed to send reply: %v", err)
				}
				return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
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

			if err := SendRequest(dataConn, CmdRevConn, req.DestAddr.Hostname(), uint16(req.DestAddr.Port)); err != nil {
				return errors.WithStack(err)
			}

			// receive CmdListen reply
			if _, err := ReadReply(dataConn); err != nil {
				return errors.WithStack(err)
			}

			// Start proxying
			go util.ConnIO(target, dataConn, dataConn)
		default:
			if err := sendReply(ctrlConn, CmdUnsupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Unsupported command: %v", req.Command)
		}
	}
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = AddrIPv4
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = AddrDomain
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = AddrIPv4
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = AddrIPv6
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = SocksVer5
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

func netErr2SockErr(err error) uint8 {
	msg := err.Error()
	resp := HostUnreachable
	if strings.Contains(msg, "refused") {
		resp = ConnRefused
	} else if strings.Contains(msg, "network is unreachable") {
		resp = NetUnreachable
	}
	return resp
}
