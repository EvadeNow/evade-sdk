package transport

import (
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/EvadeNow/evade-sdk/tlsprofile"
	"github.com/EvadeNow/evade-sdk/wireorder"
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

func TestApplyWireOrderInstallsBothOrders(t *testing.T) {
	// target_register_android-chrome151_1_0831#120's Chrome 151 image load.
	wire, err := OrderUniversal(OrderRequest{UserAgent: chrome151, Class: ClassImage, Method: "GET", HTTP2: true,
		Added: wireorder.Added{ClientHints: lowEntropyHints, Referer: true, Cookie: true, Priority: true}})
	if err != nil {
		t.Fatal(err)
	}
	req := newRequest(t)
	for _, name := range wire.Header {
		switch name {
		case "cookie": // the client's jar writes it
		case "priority":
			req.Header[name] = []string{"u=2, i"}
		default:
			req.Header.Set(name, "v-"+name)
		}
	}
	values := req.Header.Clone()
	req.Header[fhttp.HeaderOrderKey] = []string{"stale"}
	req.Header[fhttp.PHeaderOrderKey] = []string{":path"}
	if err := ApplyWireOrder(req, wire); err != nil {
		t.Fatal(err)
	}
	if got := req.Header[fhttp.HeaderOrderKey]; !slices.Equal(got, wire.Header) {
		t.Fatalf("header order = %q, want the wire's %q", got, wire.Header)
	}
	if got := req.Header[fhttp.PHeaderOrderKey]; !slices.Equal(got, chromiumPseudo) || !slices.Equal(got, wire.Pseudo) {
		t.Fatalf("pseudo order = %q, want the wire's %q", got, wire.Pseudo)
	}
	for key, want := range values {
		if got := req.Header[key]; !slices.Equal(got, want) {
			t.Errorf("%s = %q, want it untouched %q", key, got, want)
		}
	}
	if len(req.Header) != len(values)+2 {
		t.Fatalf("header map has %d keys, want %d", len(req.Header), len(values)+2)
	}
	wire.Header[0], wire.Pseudo[0] = "mutated", "mutated"
	if req.Header[fhttp.HeaderOrderKey][0] == "mutated" || req.Header[fhttp.PHeaderOrderKey][0] == "mutated" {
		t.Fatal("the installed orders share the wire's backing arrays")
	}
}

func TestApplyWireOrderNeverFallsBackToAPseudoOrder(t *testing.T) {
	// rg-ios-safari#2's Safari 18.7.5 HTTP/1.1 navigation: host and connection framed, no pseudo-headers.
	wire, err := OrderUniversal(OrderRequest{UserAgent: safariUA, Class: ClassNavigation, Method: "GET",
		Added: wireorder.Added{Referer: true, Priority: true}})
	if err != nil {
		t.Fatal(err)
	}
	if wire.Pseudo != nil || !slices.Contains(wire.Header, "host") {
		t.Fatalf("test wire %q %q is not an HTTP/1.1 WebKit wire", wire.Header, wire.Pseudo)
	}
	req := newRequest(t)
	for _, name := range wire.Header {
		if name != "host" { // the stack writes it from the URL
			req.Header.Set(name, "v")
		}
	}
	if err := ApplyWireOrder(req, wire); err != nil {
		t.Fatal(err)
	}
	if pseudo, ok := req.Header[fhttp.PHeaderOrderKey]; !ok || len(pseudo) != 0 {
		t.Fatalf("pseudo order %q (installed %v), want an installed empty order the transport cannot replace", pseudo, ok)
	}
}

func TestApplyWireOrderRefusesAnotherHeaderSet(t *testing.T) {
	wire := wireorder.Wire{Header: []string{"user-agent", "accept", "accept-language", "priority", "priority", "cookie"}, Pseudo: chromiumPseudo}
	req := newRequest(t)
	req.Header.Set("User-Agent", "UA")
	req.Header.Set("Accept", "*/*")
	req.Header["accept"] = []string{"*/*"}
	req.Header["priority"] = []string{"u=0, i"}
	req.Header["sec-fetch-dest"] = []string{} // suppressed: never sent, so not extra
	req.Header.Set("X-Extra", "1")
	before := req.Header.Clone()
	err := ApplyWireOrder(req, wire)
	want := &WireOrderError{Extra: []string{"x-extra"}, Missing: []string{"accept-language"}, Repeated: []string{"accept", "priority"}}
	var orderErr *WireOrderError
	if !errors.As(err, &orderErr) || !reflect.DeepEqual(orderErr, want) {
		t.Fatalf("error = %#v, want %#v", err, want)
	}
	if !reflect.DeepEqual(req.Header, before) {
		t.Fatalf("a refused request changed: %q", req.Header)
	}

	suppressed := newRequest(t)
	suppressed.Header.Set("User-Agent", "UA")
	suppressed.Header["accept-encoding"] = []string{}
	err = ApplyWireOrder(suppressed, wireorder.Wire{Header: []string{"user-agent", "accept-encoding"}, Pseudo: chromiumPseudo})
	if !errors.As(err, &orderErr) || !reflect.DeepEqual(orderErr, &WireOrderError{Missing: []string{"accept-encoding"}}) {
		t.Fatalf("a header with no value: %v, want it missing", err)
	}
}

// content-length is sent when the request sets it explicitly or fhttp writes it (a known positive body, or a
// known-empty POST, PUT or PATCH); the wire must agree.
func TestApplyWireOrderMatchesSentContentLength(t *testing.T) {
	without := []string{"user-agent", "content-type"}
	with := []string{"user-agent", "content-type", "content-length"}
	extra := &WireOrderError{Extra: []string{"content-length"}}
	missing := &WireOrderError{Missing: []string{"content-length"}}
	for _, tc := range []struct {
		name     string
		method   string
		body     io.Reader
		explicit string // an explicit content-length value; empty sets none
		wire     []string
		want     *WireOrderError
	}{
		{"POST without a body, wire with", "POST", nil, "", with, nil},
		{"POST without a body, wire without", "POST", nil, "", without, extra},
		{"POST known-empty body, wire without", "POST", strings.NewReader(""), "", without, extra},
		{"POST body, wire with", "POST", strings.NewReader("a=1"), "", with, nil},
		{"POST body, wire without", "POST", strings.NewReader("a=1"), "", without, extra},
		{"POST body and explicit, wire with", "POST", strings.NewReader("a=1"), "3", with, nil},
		{"POST body and explicit, wire without", "POST", strings.NewReader("a=1"), "3", without, extra},
		{"POST unknown-length body, wire with", "POST", io.MultiReader(strings.NewReader("a=1")), "", with, missing},
		{"POST unknown-length body, wire without", "POST", io.MultiReader(strings.NewReader("a=1")), "", without, nil},
		{"GET, wire with", "GET", nil, "", with, missing},
		{"GET, wire without", "GET", nil, "", without, nil},
		{"empty OPTIONS, wire with", "OPTIONS", nil, "", with, missing},
		{"empty OPTIONS with explicit 0, wire with", "OPTIONS", nil, "0", with, nil},
		{"empty OPTIONS with explicit 0, wire without", "OPTIONS", nil, "0", without, extra},
	} {
		req, err := fhttp.NewRequest(tc.method, "https://target.example/", tc.body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("User-Agent", "UA")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.explicit != "" {
			req.Header["content-length"] = []string{tc.explicit}
		}
		err = ApplyWireOrder(req, wireorder.Wire{Header: tc.wire, Pseudo: chromiumPseudo})
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			} else if got := req.Header[fhttp.HeaderOrderKey]; !slices.Equal(got, tc.wire) {
				t.Errorf("%s: header order %q, want %q", tc.name, got, tc.wire)
			}
			continue
		}
		var orderErr *WireOrderError
		if !errors.As(err, &orderErr) || !reflect.DeepEqual(orderErr, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if _, installed := req.Header[fhttp.HeaderOrderKey]; installed {
			t.Errorf("%s: a refused request got an order", tc.name)
		}
	}
}

// morerewards_login_iphone-safari18.7_2_1020#127's Safari 18.7 preflight sends content-length: 0, which fhttp never writes for an
// empty OPTIONS: the caller sets it explicitly, and without it the wire's content-length is missing.
func TestApplyWireOrderAppliesWebKitPreflight(t *testing.T) {
	wire, err := OrderUniversal(OrderRequest{UserAgent: safariUA, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true,
		Added: wireorder.Added{Origin: true, Priority: true, RequestHeaders: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(wire.Header, "content-length") {
		t.Fatalf("test wire %q carries no content-length", wire.Header)
	}
	preflight := func() *fhttp.Request {
		req, err := fhttp.NewRequest("OPTIONS", "https://login.morerewards.ca/authenticate", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range wire.Header {
			if name != "content-length" {
				req.Header[name] = []string{"v"}
			}
		}
		return req
	}
	req := preflight()
	req.Header["content-length"] = []string{"0"}
	if err := ApplyWireOrder(req, wire); err != nil {
		t.Fatalf("preflight with explicit content-length: %v", err)
	}
	if got := req.Header[fhttp.HeaderOrderKey]; !slices.Equal(got, wire.Header) {
		t.Fatalf("header order %q, want %q", got, wire.Header)
	}
	if got := req.Header[fhttp.PHeaderOrderKey]; !slices.Equal(got, webkitPseudo) {
		t.Fatalf("pseudo order %q, want %q", got, webkitPseudo)
	}
	err = ApplyWireOrder(preflight(), wire)
	var orderErr *WireOrderError
	if !errors.As(err, &orderErr) || !reflect.DeepEqual(orderErr, &WireOrderError{Missing: []string{"content-length"}}) {
		t.Fatalf("preflight without content-length: %v, want it missing", err)
	}
}
