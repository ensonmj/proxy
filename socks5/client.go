package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
)

/*
Method selection
 +----+----------+----------+
 |VER | NMETHODS | METHODS  |
 +----+----------+----------+
 | 1  |    1     | 1 to 255 |
 +----+----------+----------+
*/
func Handshake(rw io.ReadWriter, username, password string) error {
	methods := []uint8{
		MethodNoAuth,
	}
	if username != "" {
		methods = append(methods, MethodUserPass)
	}
	nm := len(methods)

	// request
	b := make([]byte, 2+nm)
	b[0] = SocksVer5
	b[1] = uint8(nm)
	copy(b[2:], methods)
	if _, err := rw.Write(b); err != nil {
		return errors.WithStack(err)
	}

	// response
	if _, err := io.ReadFull(rw, b[:2]); err != nil {
		return errors.WithStack(err)
	}
	if b[0] != SocksVer5 {
		return ErrBadVersion
	}

	// authenticate
	switch b[1] {
	case MethodNoAuth:
		return nil
	case MethodUserPass:
		if username == "" {
			return ErrNoUserPass
		}
		return sendUserPass(rw, username, password)
	case MethodNoAcceptable:
		return ErrBadMethod
	default:
		return ErrBadMethod
	}

	return nil
}

/*
 Username/Password authentication request
  +----+------+----------+------+----------+
  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
  +----+------+----------+------+----------+
  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
  +----+------+----------+------+----------+
*/
func sendUserPass(rw io.ReadWriter, username, password string) error {
	b := sPool.Get().([]byte)
	defer sPool.Put(b)

	b[0] = UserPassVer
	ulen := len(username)
	b[1] = byte(ulen)
	length := 2 + ulen
	copy(b[2:length], username)

	plen := len(password)
	b[length] = byte(plen)
	length++
	copy(b[length:length+plen], password)
	length += plen

	_, err := rw.Write(b[:length])
	if err != nil {
		return errors.WithStack(err)
	}

	if _, err := io.ReadFull(rw, b[:2]); err != nil {
		return err
	}

	if b[0] != UserPassVer {
		return ErrBadVersion
	}

	if b[1] != Succeeded {
		return ErrAuthFailure
	}

	return nil
}

/*
   The SOCKSv5 request
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*/
func SendRequest(rw io.ReadWriter, cmd uint8, host string, port uint16) error {
	b := sPool.Get().([]byte)
	defer sPool.Put(b)

	b[0] = SocksVer5
	b[1] = cmd
	b[2] = 0 //rsv

	addr := NewAddr(host, port)
	n, _ := addr.Encode(b[3:])
	length := 3 + n

	_, err := rw.Write(b[:length])
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type Reply struct {
	Rep  uint8
	Addr *Addr
}

/*
   The SOCKSv5 reply
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*/
func ReadReply(r io.Reader) (*Reply, error) {
	b := sPool.Get().([]byte)
	defer sPool.Put(b)

	n, err := io.ReadAtLeast(r, b, 5)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if b[0] != SocksVer5 {
		return nil, ErrBadVersion
	}

	if b[1] != Succeeded {
		return nil, errors.New("proxy refused connection")
	}

	length := 0
	atype := b[3]
	switch atype {
	case AddrIPv4:
		length = 10
	case AddrIPv6:
		length = 22
	case AddrDomain:
		length = 7 + int(b[4])
	default:
		return nil, ErrBadAddrType
	}

	if n < length {
		if _, err := io.ReadFull(r, b[n:length]); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	reply := &Reply{
		Rep:  b[1],
		Addr: new(Addr),
	}
	if err := reply.Addr.Decode(b[3:length]); err != nil {
		return nil, err
	}

	return reply, nil
}

/*
UDP request
 +----+------+------+----------+----------+----------+
 |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 +----+------+------+----------+----------+----------+
 | 2  |  1   |  1   | Variable |    2     | Variable |
 +----+------+------+----------+----------+----------+
*/
type UDPHeader struct {
	Rsv  uint16
	Frag uint8
	Addr *Addr
}

func NewUDPHeader(rsv uint16, frag uint8, addr *Addr) *UDPHeader {
	return &UDPHeader{
		Rsv:  rsv,
		Frag: frag,
		Addr: addr,
	}
}

func (h *UDPHeader) Write(w io.Writer) error {
	b := sPool.Get().([]byte)
	defer sPool.Put(b)

	binary.BigEndian.PutUint16(b[:2], h.Rsv)
	b[2] = h.Frag

	addr := h.Addr
	if addr == nil {
		addr = &Addr{}
	}
	length, _ := addr.Encode(b[3:])

	_, err := w.Write(b[:3+length])
	return err
}

func (h *UDPHeader) String() string {
	return fmt.Sprintf("%d %d %d %s",
		h.Rsv, h.Frag, h.Addr.Type, h.Addr.String())
}

type UDPDatagram struct {
	Header *UDPHeader
	Data   []byte
}

func NewUDPDatagram(header *UDPHeader, data []byte) *UDPDatagram {
	return &UDPDatagram{
		Header: header,
		Data:   data,
	}
}

func ReadUDPDatagram(r io.Reader) (*UDPDatagram, error) {
	b := lPool.Get().([]byte)
	defer lPool.Put(b)

	// when r is a streaming (such as TCP connection), we may read more than the required data,
	// but we don't know how to handle it. So we use io.ReadFull to instead of io.ReadAtLeast
	// to make sure that no redundant data will be discarded.
	n, err := io.ReadFull(r, b[:5])
	if err != nil {
		return nil, err
	}

	header := &UDPHeader{
		Rsv:  binary.BigEndian.Uint16(b[:2]),
		Frag: b[2],
	}

	atype := b[3]
	hlen := 0
	switch atype {
	case AddrIPv4:
		hlen = 10
	case AddrIPv6:
		hlen = 22
	case AddrDomain:
		hlen = 7 + int(b[4])
	default:
		return nil, ErrBadAddrType
	}

	dlen := int(header.Rsv)
	if dlen == 0 { // standard SOCKS5 UDP datagram
		extra, err := ioutil.ReadAll(r) // we assume no redundant data
		if err != nil {
			return nil, err
		}
		copy(b[n:], extra)
		n += len(extra) // total length
		dlen = n - hlen // data length
	} else { // extended feature, for UDP over TCP, using reserved field as data length
		if _, err := io.ReadFull(r, b[n:hlen+dlen]); err != nil {
			return nil, err
		}
		n = hlen + dlen
	}

	header.Addr = new(Addr)
	if err := header.Addr.Decode(b[3:hlen]); err != nil {
		return nil, err
	}

	data := make([]byte, dlen)
	copy(data, b[hlen:n])

	d := &UDPDatagram{
		Header: header,
		Data:   data,
	}

	return d, nil
}

func (d *UDPDatagram) Write(w io.Writer) error {
	h := d.Header
	if h == nil {
		h = &UDPHeader{}
	}
	if err := h.Write(w); err != nil {
		return err
	}
	_, err := w.Write(d.Data)

	return err
}
