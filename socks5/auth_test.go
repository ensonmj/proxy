package socks5

import (
	"bytes"
	"testing"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, MethodNoAuth})
	var resp bytes.Buffer

	s := New(&Config{})
	ctx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != MethodNoAuth {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{SocksVer5, MethodNoAuth}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, MethodNoAuth, MethodUserPass})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}

	cator := UserPassAuthenticator{Credentials: cred}

	s := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != MethodUserPass {
		t.Fatal("Invalid Context Method")
	}

	val, ok := ctx.Payload["Username"]
	if !ok {
		t.Fatal("Missing key Username in auth context's payload")
	}

	if val != "foo" {
		t.Fatal("Invalid Username in auth context's payload")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{SocksVer5, MethodUserPass, 1, authSuccess}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, MethodNoAuth, MethodUserPass})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != ErrAuthFailure {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{SocksVer5, MethodUserPass, 1, authFailure}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestNoSupportedAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, MethodNoAuth})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}

	s := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != ErrBadMethod {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{SocksVer5, noAcceptable}) {
		t.Fatalf("bad: %v", out)
	}
}
