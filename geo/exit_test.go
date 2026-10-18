package geo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
)

type serverDoer struct {
	target    *url.URL
	requested string
}

func (d *serverDoer) Do(r *fhttp.Request) (*fhttp.Response, error) {
	d.requested = r.URL.String()
	r.URL.Scheme, r.URL.Host = d.target.Scheme, d.target.Host
	return (&fhttp.Client{}).Do(r)
}

func exitServer(t *testing.T, status int, body string) *serverDoer {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RawQuery != "format=json" ||
			r.Header.Get("Accept") != "application/json" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("unexpected request %s %s accept=%q accept-encoding=%q",
				r.Method, r.URL, r.Header.Get("Accept"), r.Header.Get("Accept-Encoding"))
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &serverDoer{target: target}
}

func TestExitIPAccepts(t *testing.T) {
	padded := `{"ip":"8.8.8.8"}`
	padded += strings.Repeat(" ", maxExitBody-len(padded))
	cases := []struct {
		name, body string
		want       netip.Addr
	}{
		{"ipv4", `{"ip":"8.8.8.8"}`, netip.MustParseAddr("8.8.8.8")},
		{"ipv6", `{"ip":"2001:4860:4860::8888"}`, netip.MustParseAddr("2001:4860:4860::8888")},
		{"ipv4-mapped ipv6 is unmapped", `{"ip":"::ffff:8.8.4.4"}`, netip.MustParseAddr("8.8.4.4")},
		{"body of exactly 1 KiB", padded, netip.MustParseAddr("8.8.8.8")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doer := exitServer(t, http.StatusOK, tc.body)
			got, err := ExitIP(context.Background(), doer)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("ExitIP = %s, want %s", got, tc.want)
			}
			if doer.requested != exitIPURL {
				t.Errorf("requested %q, want %q", doer.requested, exitIPURL)
			}
		})
	}
}

func TestExitIPRejects(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   ExitReason
	}{
		{"non-200", http.StatusServiceUnavailable, `{"ip":"8.8.8.8"}`, ExitStatus},
		{"oversized", http.StatusOK, `{"ip":"8.8.8.8"}` + strings.Repeat(" ", maxExitBody), ExitOversized},
		{"not json", http.StatusOK, `8.8.8.8`, ExitMalformed},
		{"not an address", http.StatusOK, `{"ip":"example.com"}`, ExitMalformed},
		{"empty ip", http.StatusOK, `{"ip":""}`, ExitEmpty},
		{"missing ip", http.StatusOK, `{}`, ExitEmpty},
		{"private 10/8", http.StatusOK, `{"ip":"10.1.2.3"}`, ExitNotPublic},
		{"private 192.168/16", http.StatusOK, `{"ip":"192.168.1.10"}`, ExitNotPublic},
		{"loopback", http.StatusOK, `{"ip":"127.0.0.1"}`, ExitNotPublic},
		{"ipv6 loopback", http.StatusOK, `{"ip":"::1"}`, ExitNotPublic},
		{"ipv6 link-local", http.StatusOK, `{"ip":"fe80::1"}`, ExitNotPublic},
		{"ipv6 unique-local", http.StatusOK, `{"ip":"fd00::1"}`, ExitNotPublic},
		{"unspecified", http.StatusOK, `{"ip":"0.0.0.0"}`, ExitNotPublic},
		{"mapped private", http.StatusOK, `{"ip":"::ffff:10.0.0.1"}`, ExitNotPublic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExitIP(context.Background(), exitServer(t, tc.status, tc.body))
			exitErr, ok := errors.AsType[*ExitError](err)
			if !ok || exitErr.Reason != tc.want {
				t.Fatalf("err = %v, want ExitError reason %q", err, tc.want)
			}
			if tc.want == ExitStatus && exitErr.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", exitErr.StatusCode, tc.status)
			}
		})
	}
}

type failingDoer struct{ err error }

func (d failingDoer) Do(*fhttp.Request) (*fhttp.Response, error) { return nil, d.err }

func TestExitIPTransportError(t *testing.T) {
	cause := errors.New("proxy refused CONNECT")
	_, err := ExitIP(context.Background(), failingDoer{err: cause})
	exitErr, ok := errors.AsType[*ExitError](err)
	if !ok || exitErr.Reason != ExitTransport || !errors.Is(err, cause) {
		t.Fatalf("err = %v, want ExitTransport wrapping the cause", err)
	}
}
