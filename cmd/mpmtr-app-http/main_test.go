package main

import "testing"

func TestParse(t *testing.T) {
	for _, c := range []struct {
		args []string
		want options
		bad  bool
	}{
		{nil, options{path: "/", agent: "mpmtr"}, false},
		{[]string{"--get"}, options{get: true, path: "/", agent: "mpmtr"}, false},
		{[]string{"--get", "--verify"}, options{get: true, verify: true, path: "/", agent: "mpmtr"}, false},
		{[]string{"--get", "/index.php?a=1"}, options{get: true, path: "/index.php?a=1", agent: "mpmtr"}, false},
		{[]string{"--verify", "--get", "example.com/index.php"}, options{get: true, verify: true, host: "example.com", path: "/index.php", agent: "mpmtr"}, false},
		{[]string{"--get", "example.com"}, options{get: true, host: "example.com", path: "/", agent: "mpmtr"}, false},
		{[]string{"--get", "https://example.com:8443/x"}, options{get: true, tls: true, host: "example.com", path: "/x", agent: "mpmtr"}, false},
		{[]string{"--get", "http://example.com/x", "--host", "other.example"}, options{get: true, plain: true, host: "other.example", path: "/x", agent: "mpmtr"}, false},
		{[]string{"--tls", "--get", "http://example.com/"}, options{get: true, tls: true, host: "example.com", path: "/", agent: "mpmtr"}, false},
		{[]string{"--user-agent", "Mozilla/5.0 (X11; Linux x86_64)", "--get"}, options{get: true, path: "/", agent: "Mozilla/5.0 (X11; Linux x86_64)"}, false},
		{[]string{"--get", "ftp://example.com/"}, options{}, true},
		{[]string{"--tls", "--plain"}, options{}, true},
		{[]string{"stray"}, options{}, true},
	} {
		got, err := parse(c.args)
		if c.bad {
			if err == nil {
				t.Errorf("%v: accepted", c.args)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%v: %+v %v, want %+v", c.args, got, err, c.want)
		}
	}
}
