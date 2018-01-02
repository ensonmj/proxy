package proxy

import "testing"

func TestParseNode(t *testing.T) {
	var data = []struct {
		in  string
		out string
	}{
		{"127.0.0.1:8080", "ghost://127.0.0.1:8080"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"https://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"socks5://127.0.0.1:8080", "socks5://127.0.0.1:8080"},
		{"socks://127.0.0.1:8080", "socks5://127.0.0.1:8080"},
	}
	for _, d := range data {
		n, err := ParseNode(d.in)
		if err != nil {
			t.Error(err)
		}
		if n.Addr() != d.out {
			t.Errorf("expect %v, but got %v\n", d.out, n.Addr())
		}
	}
}
