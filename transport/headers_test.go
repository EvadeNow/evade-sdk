package transport

import (
	"errors"
	"slices"
	"testing"

	"github.com/EvadeNow/evade-sdk/tlsprofile"
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/tls-client/profiles"
)

func newRequest(t *testing.T) *fhttp.Request {
	t.Helper()
	req, err := fhttp.NewRequest(fhttp.MethodGet, "https://target.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestApplyPinsOrderWithLowercaseKeys(t *testing.T) {
	profile := chromeProfile(tlsprofile.Behavior{})
	headers := Headers{}.
		With("Sec-Ch-Ua-Platform", `"Windows"`).
		With("user-agent", "UA/1").
		With("sec-ch-ua", `"Chromium";v="152"`).
		With("accept", "*/*").
		With("cookie", "").
		With("priority", "u=1, i")
	req := newRequest(t)
	req.Header.Set("X-Stale", "dropped")
	if err := Apply(req, headers, profile); err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "accept", "cookie", "priority"}
	if got := req.Header[fhttp.HeaderOrderKey]; !slices.Equal(got, wantOrder) {
		t.Fatalf("header order = %q, want %q", got, wantOrder)
	}
	if got, want := req.Header[fhttp.PHeaderOrderKey], profiles.MappedTLSClients["chrome_152"].GetPseudoHeaderOrder(); !slices.Equal(got, want) {
		t.Fatalf("pseudo order = %q, want the profile's %q", got, want)
	}
	wantValues := map[string]string{
		"sec-ch-ua-platform": `"Windows"`,
		"user-agent":         "UA/1",
		"sec-ch-ua":          `"Chromium";v="152"`,
		"accept":             "*/*",
		"priority":           "u=1, i",
	}
	for key, values := range req.Header {
		if key == fhttp.HeaderOrderKey || key == fhttp.PHeaderOrderKey {
			continue
		}
		want, ok := wantValues[key]
		if !ok || len(values) != 1 || values[0] != want {
			t.Errorf("header %q = %q; want only the lowercase keys of h", key, values)
		}
	}
	if len(req.Header) != len(wantValues)+2 {
		t.Fatalf("header map has %d keys, want %d", len(req.Header), len(wantValues)+2)
	}
	if _, written := req.Header["cookie"]; written {
		t.Fatal("empty cookie slot was written as a header")
	}
}

func TestApplyKeepsFirstPositionOfRepeatedName(t *testing.T) {
	req := newRequest(t)
	headers := Headers{{"accept", "a"}, {"cookie", "x=1"}, {"accept", "b"}}
	if err := Apply(req, headers, chromeProfile(tlsprofile.Behavior{})); err != nil {
		t.Fatal(err)
	}
	if got := req.Header[fhttp.HeaderOrderKey]; !slices.Equal(got, []string{"accept", "cookie"}) {
		t.Fatalf("order = %q", got)
	}
	if got := req.Header["accept"]; !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("accept values = %q", got)
	}
}

func TestApplyRejectsProfileWithoutPseudoOrder(t *testing.T) {
	req := newRequest(t)
	req.Header.Set("X-Kept", "1")
	err := Apply(req, Headers{{"accept", "*/*"}}, tlsprofile.Profile{Name: "bare"})
	var pseudoErr *NoPseudoOrderError
	if !errors.As(err, &pseudoErr) || pseudoErr.Profile != "bare" {
		t.Fatalf("error = %v, want *NoPseudoOrderError for bare", err)
	}
	if req.Header.Get("X-Kept") != "1" || len(req.Header) != 1 {
		t.Fatalf("failed Apply modified the request: %v", req.Header)
	}
}

func TestInsertBefore(t *testing.T) {
	base := Headers{{"user-agent", "UA"}, {"accept", "*/*"}, {"referer", "r"}}
	got, err := base.InsertBefore("referer", Header{"x-a", "1"}, Header{"x-b", "2"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"user-agent", "accept", "x-a", "x-b", "referer"}; !slices.Equal(got.Names(), want) {
		t.Fatalf("names = %q, want %q", got.Names(), want)
	}
	if want := []string{"user-agent", "accept", "referer"}; !slices.Equal(base.Names(), want) {
		t.Fatalf("InsertBefore modified its receiver: %q", base.Names())
	}
	first, err := base.InsertBefore("user-agent", Header{"x-first", "1"})
	if err != nil || first[0].Name != "x-first" || len(first) != 4 {
		t.Fatalf("insert at head = %v, %v", first, err)
	}
	_, err = base.InsertBefore("origin", Header{"x-a", "1"})
	var anchorErr *AnchorError
	if !errors.As(err, &anchorErr) || anchorErr.Anchor != "origin" {
		t.Fatalf("error = %v, want *AnchorError naming origin", err)
	}
}

func TestNamesPreservesDuplicates(t *testing.T) {
	headers := Headers{{"cookie", "a=1"}, {"accept", "*/*"}, {"cookie", "b=2"}}
	if want := []string{"cookie", "accept", "cookie"}; !slices.Equal(headers.Names(), want) {
		t.Fatalf("names = %q, want %q", headers.Names(), want)
	}
}
