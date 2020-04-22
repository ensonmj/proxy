// SOCKS Protocol Version 5
// http://tools.ietf.org/html/rfc1928
// http://tools.ietf.org/html/rfc1929
package socks5

import (
	"sync"

	"github.com/pkg/errors"
)

// Ver
const (
	SocksVer5   uint8 = 5
	UserPassVer       = 1
)

// METHOD
const (
	MethodNoAuth uint8 = iota
	MethodGSSAPI
	MethodUserPass
	// X'03' to X'7F' IANA ASSIGNED
	// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	MethodNoAcceptable = 0xFF
)

// CMD
const (
	CmdConnect uint8 = iota + 1
	CmdBind
	CmdAssociate // for udp
	CmdListen    // expand for reverse proxy
	CmdRevConn   // expand for reverse proxy
)

// ATYP
const (
	AddrIPv4   uint8 = 1
	AddrDomain       = 3
	AddrIPv6         = 4
)

// REP
const (
	Succeeded uint8 = iota
	Failure
	NotAllowed
	NetUnreachable
	HostUnreachable
	ConnRefused
	TTLExpired
	CmdUnsupported
	AddrUnsupported
)

// Err
var (
	ErrBadVersion  = errors.New("Bad version")
	ErrBadFormat   = errors.New("Bad format")
	ErrBadAddrType = errors.New("Bad address type")
	ErrShortBuffer = errors.New("Short buffer")
	ErrBadMethod   = errors.New("Bad method")
	ErrAuthFailure = errors.New("Auth failure")
	ErrNoUserPass  = errors.New("No user/password")
)

// buffer pools
var (
	// small buff pool
	sPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 576)
		},
	}

	// large buff pool for udp
	lPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 64*1024+262)
		},
	}
)
