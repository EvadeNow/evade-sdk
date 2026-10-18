package proxy

import (
	"errors"
	"strings"
	"testing"
)

func TestParseCallerAccepts(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://user:secret@203.0.113.7:8080", "http://user:secret@203.0.113.7:8080"},
		{" HTTPS://user:secret@proxy.example.com:443 ", "https://user:secret@proxy.example.com:443"},
		{"socks4://proxy.example.com:1080", "socks4://proxy.example.com:1080"},
		{"socks4a://proxy.example.com:1080", "socks4a://proxy.example.com:1080"},
		{"socks5://user:secret@proxy.example.com:1080", "socks5://user:secret@proxy.example.com:1080"},
		{"socks5h://user:secret@proxy.example.com:1080", "socks5h://user:secret@proxy.example.com:1080"},
		{"http://proxy.example.com", "http://proxy.example.com"},
		{"gate.example.com:7000:user:secret", "http://user:secret@gate.example.com:7000"},
		{"gate.example.com:7000:user:se:cret", "http://user:se%3Acret@gate.example.com:7000"},
		{"gate.example.com:7000:us%40er:secret", "http://us%40er:secret@gate.example.com:7000"},
		{"socks5://gate.example.com:7000:user:secret", "socks5://user:secret@gate.example.com:7000"},
	}
	for _, tc := range cases {
		lease, err := ParseCaller(tc.in)
		if err != nil {
			t.Errorf("ParseCaller(%q): %v", tc.in, err)
			continue
		}
		want := Lease{URL: tc.want, RTC: RTCPolicyProxyOnly}
		if lease != want {
			t.Errorf("ParseCaller(%q) = %+v, want %+v", tc.in, lease, want)
		}
	}
}

func TestParseCallerRejects(t *testing.T) {
	cases := []struct {
		in, part string
	}{
		{"", "url"},
		{"proxy.example.com:8080", "scheme"},
		{"user:secret@proxy.example.com:8080", "scheme"},
		{"ftp://proxy.example.com:21", "scheme"},
		{"http://proxy.example.com:0", "port"},
		{"http://proxy.example.com:70000", "port"},
		{"http://user:secret@proxy.example.com:abc", "port"},
		{"gate.example.com:0:user:secret", "port"},
		{"gate.example.com:70000:user:secret", "port"},
		{"http://:8080", "host"},
		{":7000:user:secret", "host"},
		{"http://user@proxy.example.com:8080", "userinfo"},
		{"http://user:@proxy.example.com:8080", "userinfo"},
		{"gate.example.com:7000::secret", "userinfo"},
		{"gate.example.com:7000:user:%zz", "userinfo"},
		{"http://proxy.example.com:8080/path", "url"},
		{"http://proxy.example.com:8080?x=1", "url"},
	}
	for _, tc := range cases {
		_, err := ParseCaller(tc.in)
		callerErr, ok := errors.AsType[*CallerError](err)
		if !ok {
			t.Errorf("ParseCaller(%q): err = %v, want *CallerError", tc.in, err)
			continue
		}
		if callerErr.Part != tc.part {
			t.Errorf("ParseCaller(%q): part = %q (%v), want %q", tc.in, callerErr.Part, err, tc.part)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("ParseCaller(%q): error leaks the password: %v", tc.in, err)
		}
	}
}
