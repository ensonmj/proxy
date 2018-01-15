package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

/*
Address
 +------+----------+----------+
 | ATYP |   ADDR   |   PORT   |
 +------+----------+----------+
 |  1   | Variable |    2     |
 +------+----------+----------+
*/
type Addr struct {
	Type uint8
	Host string
	Port uint16
}

func NewAddr(host string, port uint16) *Addr {
	var typ uint8
	if ip := net.ParseIP(host); ip == nil {
		typ = AddrDomain
	} else {
		if ip4 := ip.To4(); ip4 != nil {
			typ = AddrIPv4
		} else {
			typ = AddrIPv6
		}
	}

	return &Addr{
		Type: typ,
		Host: host,
		Port: port,
	}
}

func (addr *Addr) Decode(b []byte) error {
	addr.Type = b[0]
	pos := 1
	switch addr.Type {
	case AddrIPv4:
		addr.Host = net.IP(b[pos : pos+net.IPv4len]).String()
		pos += net.IPv4len
	case AddrIPv6:
		addr.Host = net.IP(b[pos : pos+net.IPv6len]).String()
		pos += net.IPv6len
	case AddrDomain:
		addrlen := int(b[pos])
		pos++
		addr.Host = string(b[pos : pos+addrlen])
		pos += addrlen
	default:
		return ErrBadAddrType
	}

	addr.Port = binary.BigEndian.Uint16(b[pos:])

	return nil
}

func (addr *Addr) Encode(b []byte) (int, error) {
	b[0] = addr.Type
	pos := 1
	switch addr.Type {
	case AddrIPv4:
		ip4 := net.ParseIP(addr.Host).To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		pos += copy(b[pos:], ip4)
	case AddrDomain:
		b[pos] = byte(len(addr.Host))
		pos++
		pos += copy(b[pos:], []byte(addr.Host))
	case AddrIPv6:
		ip16 := net.ParseIP(addr.Host).To16()
		if ip16 == nil {
			ip16 = net.IPv6zero.To16()
		}
		pos += copy(b[pos:], ip16)
	default:
		b[0] = AddrIPv4
		copy(b[pos:pos+4], net.IPv4zero.To4())
		pos += 4
	}
	binary.BigEndian.PutUint16(b[pos:], addr.Port)
	pos += 2

	return pos, nil
}

func (addr *Addr) Length() (n int) {
	switch addr.Type {
	case AddrIPv4:
		n = 10
	case AddrIPv6:
		n = 22
	case AddrDomain:
		n = 7 + len(addr.Host)
	default:
		n = 10
	}
	return
}

func (addr *Addr) String() string {
	return net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port)))
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}
