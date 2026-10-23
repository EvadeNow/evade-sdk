package wireorder

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var lowEntropyHints = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}

var browserWitnesses = []struct {
	source string
	r      Request
	wire   string
}{
	{"compat-http tls-layer2 www.wikipedia.org/ (Chrome 154, first hop)",
		Request{Engine: Engine{Kind: Chromium, Major: 154}, Class: ClassNavigation, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, FetchUser: true, Priority: true}},
		"sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests user-agent accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest accept-encoding accept-language priority"},
	{"compat-http tls-layer2 www.mozilla.org/en-US/ (Chrome 154, hop after mozilla.org's 302)",
		Request{Engine: Engine{Kind: Chromium, Major: 154}, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true,
			Added: Added{ClientHints: lowEntropyHints, FetchUser: true, Priority: true}},
		"upgrade-insecure-requests user-agent accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform accept-encoding accept-language priority"},
	{"target_register_android-chrome151_1_0831#217 www.target.com/login (Chrome 151, hop after gsp.target.com's 302)",
		Request{Engine: Engine{Kind: Chromium, Major: 151}, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true,
			Added: Added{ClientHints: lowEntropyHints, FetchUser: true, Referer: true, Cookie: true, Priority: true}},
		"upgrade-insecure-requests user-agent accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform referer accept-encoding accept-language cookie priority"},
	{"pkc#28 www.pokemoncenter.com/ (Chrome 153, HTTP/1.1 first hop)",
		Request{Engine: Engine{Kind: Chromium, Major: 153}, Class: ClassNavigation, Method: "GET",
			Added: Added{ClientHints: lowEntropyHints, FetchUser: true}},
		"host connection sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests user-agent accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest accept-encoding accept-language"},
	{"bandai-login15#55 p-bandai.com seeded VM (Chrome 151 script)",
		Request{Engine: Engine{Kind: Chromium, Major: 151}, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Referer: true, Cookie: true}},
		"sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest referer accept-encoding accept-language cookie"},
	{"target_register_android-chrome151_1_0831#227 assets.targetimg1.com/ssx/ssx.mod.js?async (Chrome 151 loader)",
		Request{Engine: Engine{Kind: Chromium, Major: 151}, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Referer: true, StorageAccess: true, Priority: true}},
		"sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest sec-fetch-storage-access referer accept-encoding accept-language priority"},
	{"chase_login_windows-chrome151_1_0830#133 www.chase.com channela.js?async&seed= (Chrome 151, Accept-CH hints)",
		Request{Engine: Engine{Kind: Chromium, Major: 151}, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform",
				"sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-full-version-list", "sec-ch-ua-bitness", "sec-ch-ua-wow64"},
				Referer: true, Cookie: true}},
		"sec-ch-ua-full-version-list sec-ch-ua-platform sec-ch-ua sec-ch-ua-bitness sec-ch-ua-model sec-ch-ua-mobile sec-ch-ua-wow64 sec-ch-ua-arch user-agent sec-ch-ua-platform-version accept sec-fetch-site sec-fetch-mode sec-fetch-dest referer accept-encoding accept-language cookie"},
}

func TestBrowserClassesReproduceWitnesses(t *testing.T) {
	for _, w := range browserWitnesses {
		got, err := Order(w.r)
		if err != nil {
			t.Errorf("%s: %v", w.source, err)
			continue
		}
		want := strings.Fields(w.wire)
		if !slices.Equal(got.Header, want) {
			t.Errorf("%s:\n got %v\nwant %v", w.source, got.Header, want)
		}
		if !slices.Equal(got.Pseudo, []string{":method", ":authority", ":scheme", ":path"}) {
			t.Errorf("%s: pseudo %v", w.source, got.Pseudo)
		}
		if sorted := slices.Sorted(slices.Values(want)); slices.Equal(got.Header, sorted) {
			t.Errorf("%s: the order is the sorted name list", w.source)
		}
	}
}

func TestBrowserConditionalHeadersKeepTheirPlace(t *testing.T) {
	for _, w := range browserWitnesses {
		full := strings.Fields(w.wire)
		for name, drop := range map[string]func(*Added){
			"referer":                  func(a *Added) { a.Referer = false },
			"cookie":                   func(a *Added) { a.Cookie = false },
			"priority":                 func(a *Added) { a.Priority = false },
			"sec-fetch-user":           func(a *Added) { a.FetchUser = false },
			"sec-fetch-storage-access": func(a *Added) { a.StorageAccess = false },
		} {
			if !slices.Contains(full, name) {
				continue
			}
			r := w.r
			drop(&r.Added)
			got, err := Order(r)
			if err != nil {
				t.Fatalf("%s without %s: %v", w.source, name, err)
			}
			want := slices.DeleteFunc(slices.Clone(full), func(n string) bool { return n == name })
			if !slices.Equal(got.Header, want) {
				t.Errorf("%s without %s:\n got %v\nwant %v", w.source, name, got.Header, want)
			}
		}
	}
}

func TestBrowserClassesFailClosed(t *testing.T) {
	nav := func(mutate func(*Request)) Request {
		r := Request{Engine: Engine{Kind: Chromium, Major: 154}, Class: ClassNavigation, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, FetchUser: true, Priority: true}}
		mutate(&r)
		return r
	}
	script := func(mutate func(*Request)) Request {
		r := Request{Engine: Engine{Kind: Chromium, Major: 151}, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Referer: true}}
		mutate(&r)
		return r
	}
	unwitnessed := map[string]Request{
		"webkit navigation": nav(func(r *Request) { r.Engine = Engine{Kind: WebKit, Major: 18, Minor: 7}; r.Added.ClientHints = nil }),
		"webkit script":     script(func(r *Request) { r.Engine = Engine{Kind: WebKit, Major: 26, Minor: 6}; r.Added.ClientHints = nil }),
		"unknown engine": nav(func(r *Request) {
			r.Engine = EngineFromUserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")
		}),
		"chromium 140":         nav(func(r *Request) { r.Engine.Major = 140 }),
		"chromium 156":         script(func(r *Request) { r.Engine.Major = 156 }),
		"POST navigation":      nav(func(r *Request) { r.Method = "POST" }),
		"Accept-CH navigation": nav(func(r *Request) { r.Added.ClientHints = append(r.Added.ClientHints, "sec-ch-ua-model") }),
		"storage-access nav":   nav(func(r *Request) { r.Added.StorageAccess = true }),
		"full-version hint":    script(func(r *Request) { r.Added.ClientHints = append(r.Added.ClientHints, "sec-ch-ua-full-version") }),
		"form":                 nav(func(r *Request) { r.Class = ClassForm }),
		"no-cors fetch":        script(func(r *Request) { r.Class = ClassNoCORS }),
		"unknown class":        script(func(r *Request) { r.Class = ClassUnknown }),
		"safari 17 inserted": script(func(r *Request) {
			r.Engine = Engine{Kind: WebKit, Major: 17}
			r.Added.ClientHints = nil
			r.Inserted = true
		}),
		"safari h1 inserted": script(func(r *Request) {
			r.Engine = Engine{Kind: WebKit, Major: 18, Minor: 7}
			r.Added.ClientHints = nil
			r.Inserted = true
			r.HTTP2 = false
		}),
	}
	for name, r := range unwitnessed {
		if _, err := Order(r); !errors.As(err, new(*UnwitnessedError)) {
			t.Errorf("%s: want UnwitnessedError, got %v", name, err)
		}
	}
	// HYPOTHESIS(webkit_early_falls_back_to_late): an early build's inserted script is ordered as late.
	for name, e := range map[string]Engine{
		"safari 18.0 inserted":  {Kind: WebKit, Major: 18},
		"webview 18.6 inserted": {Kind: WebKit, Major: 18, Minor: 6, WebView: true},
	} {
		wantLateOrder(t, name, script(func(r *Request) {
			r.Engine = e
			r.Added.ClientHints = nil
			r.Added.Priority = true
			r.Inserted = true
		}))
	}
	impossible := map[string]Request{
		"script with calls":     script(func(r *Request) { r.Calls = []string{"x-a"} }),
		"script with origin":    script(func(r *Request) { r.Added.Origin = true }),
		"navigation with body":  nav(func(r *Request) { r.Added.Body = true }),
		"navigation with pins":  nav(func(r *Request) { r.Pins = []*Pin{testInstall} }),
		"redirected script":     script(func(r *Request) { r.Redirected = true }),
		"script sec-fetch-user": script(func(r *Request) { r.Added.FetchUser = true }),
		"xhr sec-fetch-user":    func() Request { r := chromeXHR(151, "content-type"); r.Added.FetchUser = true; return r }(),
		"redirected xhr":        func() Request { r := chromeXHR(151, "content-type"); r.Redirected = true; return r }(),
		"safari inserted hints": script(func(r *Request) { r.Engine = Engine{Kind: WebKit, Major: 18, Minor: 7}; r.Inserted = true }),
		"safari inserted origin": script(func(r *Request) {
			r.Engine = Engine{Kind: WebKit, Major: 18, Minor: 7}
			r.Added.ClientHints = nil
			r.Inserted = true
			r.Added.Origin = true
		}),
	}
	for name, r := range impossible {
		if _, err := Order(r); !errors.As(err, new(*InputError)) {
			t.Errorf("%s: want InputError, got %v", name, err)
		}
	}
}

func TestWebKitInsertedScriptWitnesses(t *testing.T) {
	for _, w := range []struct {
		source string
		added  Added
		wire   string
	}{
		{"target_cart_iphone-safari18.7_1_0930#129", Added{Referer: true, Priority: true},
			"sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding"},
		{"starbucks_login_iphone-safari18.7_1_0910#143", Added{Priority: true},
			"sec-fetch-dest user-agent accept sec-fetch-site sec-fetch-mode accept-language priority accept-encoding"},
	} {
		got, err := Order(Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 7}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true, Added: w.added})
		if err != nil {
			t.Fatalf("%s: %v", w.source, err)
		}
		want := strings.Fields(w.wire)
		if !slices.Equal(got.Header, want) {
			t.Errorf("%s:\n got %v\nwant %v", w.source, got.Header, want)
		}
		if sorted := slices.Sorted(slices.Values(want)); slices.Equal(got.Header, sorted) {
			t.Errorf("%s: the order is a sort", w.source)
		}
	}
}

// strictVerdict is what strict Order answers for a universal witness.
type strictVerdict uint8

const (
	strictRefuses strictVerdict = iota // an UnwitnessedError: no strict law for the class
	strictLate                         // late's order, not the capture: HYPOTHESIS(webkit_early_falls_back_to_late)
)

var (
	chromiumPseudo = []string{":method", ":authority", ":scheme", ":path"}
	webkitPseudo   = []string{":method", ":scheme", ":authority", ":path"}
	safari187      = Engine{Kind: WebKit, Major: 18, Minor: 7}
	chrome151      = Engine{Kind: Chromium, Major: 151}
)

// universalWitnesses are real browser requests (capture#entry, header names in received order) of the classes
// OrderUniversal frames by engine mechanism; no site, page or captured order selects any of them.
var universalWitnesses = []struct {
	source string
	strict strictVerdict
	r      Request
	wire   string
}{
	// Chromium forms: the browser process's navigation list with the form's body, cache-control, content-type and Origin.
	{"bandai-jp_product_windows-chrome151_1_0809#54 p-bandai.jp/login_chk/ (Chrome 151 login form)", strictRefuses,
		Request{Engine: chrome151, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Origin: true, Body: true, Referer: true, Cookie: true, Priority: true, FetchUser: true}},
		"content-length cache-control sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests content-type user-agent origin accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest referer accept-encoding accept-language cookie priority"},
	{"bandai-login13#182 www.facebook.com/tr/ (Chrome 151 cross-site form)", strictRefuses,
		Request{Engine: chrome151, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Origin: true, Body: true, Referer: true, Priority: true, FetchUser: true, StorageAccess: true}},
		"content-length cache-control sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests content-type user-agent origin accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest sec-fetch-storage-access referer accept-encoding accept-language priority"},
	{"chess-login#174 www.chess.com/login_check (Chrome 154 login form)", strictRefuses,
		Request{Engine: Engine{Kind: Chromium, Major: 154}, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Origin: true, Body: true, Referer: true, Cookie: true, Priority: true, FetchUser: true}},
		"content-length cache-control sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests content-type user-agent origin accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest referer accept-encoding accept-language cookie priority"},
	{"xfinity_login_android-chrome141_1_0907#372 login.xfinity.com/login (Chrome 141 login form, origin first)", strictRefuses,
		Request{Engine: Engine{Kind: Chromium, Major: 141}, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Origin: true, Body: true, Referer: true, Cookie: true, Priority: true, FetchUser: true}},
		"content-length cache-control sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform origin content-type upgrade-insecure-requests user-agent accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest referer accept-encoding accept-language cookie priority"},
	// Chromium preflights: the network service's fixed sequence.
	{"target_register_android-chrome151_1_0831#265 gsp.target.com passwordless_preauthentications (Chrome 151 preflight)", strictRefuses,
		Request{Engine: chrome151, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true,
			Added: Added{Origin: true, Referer: true, Priority: true, RequestHeaders: true}},
		"accept access-control-request-method access-control-request-headers origin user-agent sec-fetch-mode sec-fetch-site sec-fetch-dest referer accept-encoding accept-language priority"},
	{"bandai-login12#8 ogads-pa.clients6.google.com (Chrome 151 preflight without a referrer)", strictRefuses,
		Request{Engine: chrome151, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true,
			Added: Added{Origin: true, Priority: true, RequestHeaders: true}},
		"accept access-control-request-method access-control-request-headers origin user-agent sec-fetch-mode sec-fetch-site sec-fetch-dest accept-encoding accept-language priority"},
	{"sky_login_android-chrome151_1_0901#60 skyport.sky.com (Chrome 151 HTTP/1.1 preflight)", strictRefuses,
		Request{Engine: chrome151, Class: ClassPreflight, Method: "OPTIONS",
			Added: Added{Origin: true, Referer: true, RequestHeaders: true}},
		"host connection accept access-control-request-method access-control-request-headers origin user-agent sec-fetch-mode sec-fetch-site sec-fetch-dest referer accept-encoding accept-language"},
	// Chromium no-cors element loads: a call-less Blink map.
	{"target_register_android-chrome151_1_0831#120 www.target.com bullseye image (Chrome 151 no-cors)", strictRefuses,
		Request{Engine: chrome151, Class: ClassNoCORS, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Referer: true, Cookie: true, Priority: true}},
		"sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest referer accept-encoding accept-language cookie priority"},
	{"bandai-login15#7 gem-bandai.global-e.com stylesheet (Chrome 151 no-cors)", strictRefuses,
		Request{Engine: chrome151, Class: ClassNoCORS, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Referer: true, Priority: true, StorageAccess: true}},
		"sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest sec-fetch-storage-access referer accept-encoding accept-language priority"},
	// WebKit late and law generations.
	{"bandai-jp_login_iphone-safari18.7_1_1020#543 p-bandai.jp/login_chk/ (Safari 18.7.5 login form)", strictRefuses,
		Request{Engine: safari187, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: Added{Origin: true, Body: true, Referer: true, Cookie: true, Priority: true}},
		"accept content-type origin sec-fetch-site sec-fetch-mode user-agent referer sec-fetch-dest content-length accept-language priority accept-encoding cookie"},
	{"target_login_iphone15-safari26.5_1_0909#394 gsp.target.com passwordless_preauthentications (Safari 26.5 preflight)", strictRefuses,
		Request{Engine: Engine{Kind: WebKit, Major: 26, Minor: 5}, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true,
			Added: Added{Origin: true, Referer: true, Priority: true, RequestHeaders: true}},
		"origin sec-fetch-site access-control-request-method access-control-request-headers sec-fetch-mode user-agent referer sec-fetch-dest content-length accept accept-language priority accept-encoding"},
	{"morerewards_login_iphone-safari18.7_2_1020#127 login.morerewards.ca authenticate (Safari 18.7 preflight without a referrer)", strictRefuses,
		Request{Engine: safari187, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true,
			Added: Added{Origin: true, Priority: true, RequestHeaders: true}},
		"sec-fetch-site origin access-control-request-method access-control-request-headers sec-fetch-mode user-agent content-length sec-fetch-dest accept accept-language priority accept-encoding"},
	{"starbucks_login_iphone-safari18.7_1_0910#139 auth.starbucks.com vendor2.js (Safari 18.7.5 parser script)", strictRefuses,
		Request{Engine: safari187, Class: ClassScript, Method: "GET", HTTP2: true, Added: Added{Referer: true, Cookie: true, Priority: true}},
		"sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding cookie"},
	{"morerewards_login_iphone-safari26.6_1_1019#29 www.morerewards.ca arrow image (Safari 26.6 no-cors)", strictRefuses,
		Request{Engine: Engine{Kind: WebKit, Major: 26, Minor: 6}, Class: ClassNoCORS, Method: "GET", HTTP2: true,
			Added: Added{Referer: true, Cookie: true, Priority: true}},
		"sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding cookie"},
	{"target_login_iphone12-safari18.7_1_0910#38 target.com typed (Safari 18.7.5 navigation)", strictRefuses,
		Request{Engine: safari187, Class: ClassNavigation, Method: "GET", HTTP2: true, Added: Added{UpgradeInsecureRequests: true, Priority: true}},
		"sec-fetch-dest user-agent upgrade-insecure-requests accept sec-fetch-site sec-fetch-mode accept-language priority accept-encoding"},
	{"target_login_iphone12-safari18.7_1_0910#39 www.target.com, #38's redirect hop", strictRefuses,
		Request{Engine: safari187, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true,
			Added: Added{UpgradeInsecureRequests: true, Priority: true}},
		"accept sec-fetch-site upgrade-insecure-requests sec-fetch-mode user-agent accept-language sec-fetch-dest priority accept-encoding"},
	{"target_login_iphone12-safari18.7_1_0910#403 target.com typed without upgrade-insecure-requests", strictRefuses,
		Request{Engine: safari187, Class: ClassNavigation, Method: "GET", HTTP2: true, Added: Added{Priority: true}},
		"sec-fetch-dest user-agent accept sec-fetch-site sec-fetch-mode accept-language priority accept-encoding"},
	{"target_login_iphone12-safari18.7_1_0910#404 www.target.com, #403's redirect hop (the capture law.WebKit.Counterwitness reads as a dictionary without priority)", strictRefuses,
		Request{Engine: safari187, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true, Added: Added{Priority: true}},
		"accept sec-fetch-site sec-fetch-mode user-agent accept-language sec-fetch-dest priority accept-encoding"},
	{"target_login_iphone12-safari18.7_1_0910#317 gsp.target.com auth_codes (Safari 18.7.5 link navigation)", strictRefuses,
		Request{Engine: safari187, Class: ClassNavigation, Method: "GET", HTTP2: true, Added: Added{Referer: true, Cookie: true, Priority: true}},
		"sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding cookie"},
	{"target_login_iphone12-safari18.7_1_0910#320 www.target.com/login, a redirect hop with a referrer", strictRefuses,
		Request{Engine: safari187, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true,
			Added: Added{Referer: true, Cookie: true, Priority: true}},
		"accept sec-fetch-site priority sec-fetch-mode user-agent accept-language sec-fetch-dest referer accept-encoding cookie"},
	{"rg-ios-safari#2 (Safari 18.7.5 HTTP/1.1 navigation)", strictRefuses,
		Request{Engine: safari187, Class: ClassNavigation, Method: "GET", Added: Added{Referer: true, Priority: true}},
		"host sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding connection"},
	{"probe-safari-16e#4 appium.io typed (Safari 18.3, law generation)", strictRefuses,
		Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 3}, Class: ClassNavigation, Method: "GET", HTTP2: true,
			Added: Added{UpgradeInsecureRequests: true, Priority: true}},
		"sec-fetch-dest user-agent upgrade-insecure-requests accept sec-fetch-site sec-fetch-mode accept-language priority accept-encoding"},
	{"probe-safari-16e#6 appium.io/docs/en/latest/ redirect hop (Safari 18.3)", strictRefuses,
		Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 3}, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true,
			Added: Added{Referer: true, Priority: true}},
		"accept sec-fetch-site priority sec-fetch-mode user-agent accept-language sec-fetch-dest referer accept-encoding"},
	// Early generations keep their captured browser-owned GET order and send no priority (s-live testdata/webkit_generation_witness.json).
	{"ios18-safari-14#30 example.com (Safari 18.0 navigation)", strictRefuses,
		Request{Engine: Engine{Kind: WebKit, Major: 18}, Class: ClassNavigation, Method: "GET", HTTP2: true, Added: Added{Referer: true, Cookie: true}},
		"accept sec-fetch-site sec-fetch-dest accept-language sec-fetch-mode user-agent referer accept-encoding cookie"},
	{"probe-safari-13#26 example.com/s.js (Safari 18.0 parser script)", strictRefuses,
		Request{Engine: Engine{Kind: WebKit, Major: 18}, Class: ClassScript, Method: "GET", HTTP2: true, Added: Added{Referer: true}},
		"accept sec-fetch-site sec-fetch-dest accept-language sec-fetch-mode user-agent referer accept-encoding"},
	{"ios18-safari-14#27 lodash (Safari 18.0 inserted script)", strictLate,
		Request{Engine: Engine{Kind: WebKit, Major: 18}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true, Added: Added{Referer: true}},
		"accept sec-fetch-site sec-fetch-dest accept-language sec-fetch-mode user-agent referer accept-encoding"},
	{"ios18-crios-16#21 lodash (Chrome for iOS 18.6, early-webview inserted script)", strictLate,
		Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 6, WebView: true}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true,
			Added: Added{Referer: true}},
		"accept sec-fetch-site sec-fetch-dest accept-language sec-fetch-mode user-agent referer accept-encoding"},
}

func TestOrderUniversalReproducesBrowserClassWitnesses(t *testing.T) {
	for _, w := range universalWitnesses {
		want := strings.Fields(w.wire)
		got, err := OrderUniversal(w.r)
		if err != nil || !slices.Equal(got.Header, want) {
			t.Errorf("%s:\n got %v (%v)\nwant %v", w.source, got.Header, err, want)
			continue
		}
		again, err := OrderUniversal(w.r)
		if err != nil || !reflect.DeepEqual(again, got) {
			t.Errorf("%s: a second call answers %v (%v)", w.source, again, err)
		}
		pseudo := chromiumPseudo
		switch {
		case w.r.Engine.Kind == WebKit && w.r.HTTP2:
			pseudo = webkitPseudo
		case w.r.Engine.Kind == WebKit:
			pseudo = nil
		}
		if !slices.Equal(got.Pseudo, pseudo) {
			t.Errorf("%s: pseudo %v, want %v", w.source, got.Pseudo, pseudo)
		}
		strict, err := Order(w.r)
		switch w.strict {
		case strictRefuses:
			if !errors.As(err, new(*UnwitnessedError)) {
				t.Errorf("%s: strict Order = %v (%v), want unwitnessed", w.source, strict.Header, err)
			}
		case strictLate:
			if err != nil || slices.Equal(strict.Header, want) {
				t.Errorf("%s: strict Order = %v (%v), want late's order, not the capture", w.source, strict.Header, err)
			}
		}
	}
}

// The Bandai and Starbucks Safari 18.7.5 login forms send one name set in two orders. Both are outcomes of the
// fetch/XHR law over the form's content-type and the loader's names, so strict XHR Order is ambiguous on it;
// OrderUniversal frames the form with the law's one canonical outcome, Bandai's.
func TestOrderUniversalWebKitFormIsItsXHRDictionary(t *testing.T) {
	bandai := strings.Fields("accept content-type origin sec-fetch-site sec-fetch-mode user-agent referer sec-fetch-dest content-length accept-language priority accept-encoding cookie")
	starbucks := strings.Fields("accept content-type sec-fetch-site origin sec-fetch-mode user-agent referer sec-fetch-dest content-length accept-language priority accept-encoding cookie")
	form := Request{Engine: safari187, Class: ClassForm, Method: "POST", HTTP2: true,
		Added: Added{Origin: true, Body: true, Referer: true, Cookie: true, Priority: true}}
	xhr := form
	xhr.Class, xhr.Calls = ClassXHR, []string{"content-type"}
	_, err := Order(xhr)
	wantErr[*AmbiguousError](t, err)
	outcomes, err := Outcomes(xhr)
	if err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string][]string{"bandai-jp_login_iphone-safari18.7_1_1020#543": bandai, "starbucks_login_iphone-safari18.7_1_0910#161 and starbucks_login_iphone-safari18.7_2_0919#136": starbucks} {
		if !containsOrder(outcomes, o) {
			t.Errorf("%s %v is no outcome of the XHR law %v", name, o, outcomes)
		}
	}
	_, err = Order(form)
	wantErr[*UnwitnessedError](t, err)
	got, err := OrderUniversal(form)
	if err != nil || !slices.Equal(got.Header, bandai) {
		t.Fatalf("universal form %v (%v), want the canonical outcome %v", got.Header, err, bandai)
	}
	if asXHR, err := OrderUniversal(xhr); err != nil || !slices.Equal(asXHR.Header, got.Header) {
		t.Errorf("universal XHR of the form's names %v (%v), form %v", asXHR.Header, err, got.Header)
	}
}

// Known counterexamples: captures no mechanism input expresses are not reproduced; those an input does express
// stay typed failures.
func TestOrderUniversalBrowserClassCounterexamples(t *testing.T) {
	// bandai-jp-login-evidence-20261020c#275 (Chrome 155) and the 39 Starbucks Chrome submits behind s-live's
	// flow_starbucks.go: an automation Accept-Language override sets accept-language before accept.
	override := strings.Fields("content-length cache-control sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests content-type user-agent origin accept-language accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest referer accept-encoding cookie priority")
	form, err := OrderUniversal(Request{Engine: Engine{Kind: Chromium, Major: 155}, Class: ClassForm, Method: "POST", HTTP2: true,
		Added: Added{ClientHints: lowEntropyHints, Origin: true, Body: true, Referer: true, Cookie: true, Priority: true, FetchUser: true}})
	if err != nil {
		t.Fatal(err)
	}
	moved := slices.DeleteFunc(slices.Clone(override), func(n string) bool { return n == "accept-language" })
	moved = slices.Insert(moved, slices.Index(moved, "accept-encoding")+1, "accept-language")
	if slices.Equal(form.Header, override) || !slices.Equal(form.Header, moved) {
		t.Errorf("Chrome 155 form %v: want the network stack's accept-language slot %v, not the override's %v", form.Header, moved, override)
	}
	// target_cart_iphone17-safari26.6_1_1006#7 (Safari 26.6.1): the early-load burst puts user-agent first.
	burst := strings.Fields("user-agent sec-fetch-dest accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding")
	script, err := OrderUniversal(Request{Engine: Engine{Kind: WebKit, Major: 26, Minor: 6}, Class: ClassScript, Method: "GET", HTTP2: true,
		Added: Added{Referer: true, Priority: true}})
	if err != nil {
		t.Fatal(err)
	}
	swapped := slices.Concat([]string{burst[1], burst[0]}, burst[2:])
	if !slices.Equal(script.Header, swapped) {
		t.Errorf("Safari 26.6 parser script %v, want %v (the burst capture is %v)", script.Header, swapped, burst)
	}
	unwitnessed := map[string]Request{
		// axs-3#19: Accept-CH hints on a Cloudflare challenge form.
		"axs-3#19 Accept-CH form": {Engine: Engine{Kind: Chromium, Major: 153}, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-ua-platform-version",
				"sec-ch-ua-model", "sec-ch-ua-bitness", "sec-ch-ua-full-version-list"}, Origin: true, Body: true, Referer: true, Cookie: true, Priority: true}},
		// HintCounterwitness axs-2#14 holds on a call-less Blink map.
		"full-version no-cors": {Engine: Engine{Kind: Chromium, Major: 154}, Class: ClassNoCORS, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: append(slices.Clone(lowEntropyHints), "sec-ch-ua-full-version"), Referer: true}},
	}
	for name, r := range unwitnessed {
		if _, err := OrderUniversal(r); !errors.As(err, new(*UnwitnessedError)) {
			t.Errorf("%s: want UnwitnessedError, got %v", name, err)
		}
	}
	// The 62 captured redirected element loads: only a navigation hop is framed as a redirect.
	redirected := Request{Engine: safari187, Class: ClassNoCORS, Method: "GET", HTTP2: true, Redirected: true, Added: Added{Referer: true, Priority: true}}
	_, err = OrderUniversal(redirected)
	wantErr[*InputError](t, err)
}

func TestOrderUniversalBrowserClassesFailClosed(t *testing.T) {
	form := func(e Engine, mutate func(*Request)) Request {
		r := Request{Engine: e, Class: ClassForm, Method: "POST", HTTP2: true, Added: Added{Origin: true, Body: true, Referer: true, Priority: true}}
		if e.Kind == Chromium {
			r.Added.ClientHints = lowEntropyHints
		}
		mutate(&r)
		return r
	}
	preflight := func(e Engine, mutate func(*Request)) Request {
		r := Request{Engine: e, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true, Added: Added{Origin: true, Referer: true, Priority: true, RequestHeaders: true}}
		mutate(&r)
		return r
	}
	get := func(e Engine, class Class, mutate func(*Request)) Request {
		r := Request{Engine: e, Class: class, Method: "GET", HTTP2: true, Added: Added{Referer: true, Priority: true}}
		mutate(&r)
		return r
	}
	early := Engine{Kind: WebKit, Major: 18}
	input := map[string]Request{
		"GET form":                      form(chrome151, func(r *Request) { r.Method = "GET"; r.Added.Origin, r.Added.Body = false, false }),
		"form without a body":           form(safari187, func(r *Request) { r.Added.Body = false }),
		"form without origin":           form(chrome151, func(r *Request) { r.Added.Origin = false }),
		"form with page calls":          form(safari187, func(r *Request) { r.Calls = []string{"content-type"} }),
		"redirected form":               form(chrome151, func(r *Request) { r.Redirected = true }),
		"webkit form sec-fetch-user":    form(safari187, func(r *Request) { r.Added.FetchUser = true }),
		"POST preflight":                preflight(chrome151, func(r *Request) { r.Method = "POST" }),
		"preflight without origin":      preflight(safari187, func(r *Request) { r.Added.Origin = false }),
		"preflight with cookie":         preflight(chrome151, func(r *Request) { r.Added.Cookie = true }),
		"preflight with a body":         preflight(safari187, func(r *Request) { r.Added.Body = true }),
		"preflight with client hints":   preflight(chrome151, func(r *Request) { r.Added.ClientHints = lowEntropyHints }),
		"preflight sec-fetch-user":      preflight(chrome151, func(r *Request) { r.Added.FetchUser = true }),
		"preflight with page calls":     preflight(safari187, func(r *Request) { r.Calls = []string{"x-api-key"} }),
		"early preflight with priority": preflight(early, func(*Request) {}),
		"POST no-cors":                  get(chrome151, ClassNoCORS, func(r *Request) { r.Method = "POST"; r.Added.Origin, r.Added.Body = true, true }),
		"no-cors with origin":           get(safari187, ClassNoCORS, func(r *Request) { r.Added.Origin = true }),
		"no-cors sec-fetch-user":        get(chrome151, ClassNoCORS, func(r *Request) { r.Added.FetchUser = true }),
		"no-cors with pins":             get(safari187, ClassNoCORS, func(r *Request) { r.Pins = []*Pin{testInstall} }),
		"script upgrade-insecure":       get(safari187, ClassScript, func(r *Request) { r.Added.UpgradeInsecureRequests = true }),
		"redirected script":             get(safari187, ClassScript, func(r *Request) { r.Redirected = true }),
		"POST webkit navigation":        get(safari187, ClassNavigation, func(r *Request) { r.Method = "POST" }),
		"webkit navigation fetch-user":  get(safari187, ClassNavigation, func(r *Request) { r.Added.FetchUser = true }),
		"early navigation priority":     get(early, ClassNavigation, func(*Request) {}),
		"navigation request headers":    get(safari187, ClassNavigation, func(r *Request) { r.Added.RequestHeaders = true }),
		"xhr request headers":           func() Request { r := chromeXHR(151, "content-type"); r.Added.RequestHeaders = true; return r }(),
		"xhr upgrade-insecure":          func() Request { r := targetSafari(); r.Added.UpgradeInsecureRequests = true; return r }(),
	}
	for name, r := range input {
		if _, err := OrderUniversal(r); !errors.As(err, new(*InputError)) {
			t.Errorf("%s: want InputError, got %v", name, err)
		}
	}
	unwitnessed := map[string]Request{
		"chromium 156 form":             form(Engine{Kind: Chromium, Major: 156}, func(*Request) {}),
		"chromium 140 preflight":        preflight(Engine{Kind: Chromium, Major: 140}, func(*Request) {}),
		"chromium 140 no-cors":          get(Engine{Kind: Chromium, Major: 140}, ClassNoCORS, func(*Request) {}),
		"storage-access preflight":      preflight(chrome151, func(r *Request) { r.Added.StorageAccess = true }),
		"webkit form upgrade-insecure":  form(safari187, func(r *Request) { r.Added.UpgradeInsecureRequests = true }),
		"webkit navigation hints":       get(safari187, ClassNavigation, func(r *Request) { r.Added.ClientHints = lowEntropyHints }),
		"webkit no-cors storage-access": get(safari187, ClassNoCORS, func(r *Request) { r.Added.StorageAccess = true }),
		"early navigation upgrade-insecure": get(early, ClassNavigation, func(r *Request) {
			r.Added.Priority, r.Added.UpgradeInsecureRequests = false, true
		}),
		"unknown engine form": form(Engine{}, func(*Request) {}),
		"unknown class":       get(safari187, ClassUnknown, func(*Request) {}),
	}
	for name, r := range unwitnessed {
		if _, err := OrderUniversal(r); !errors.As(err, new(*UnwitnessedError)) {
			t.Errorf("%s: want UnwitnessedError, got %v", name, err)
		}
	}
}

// An early build keeps its own priority and table facts on every class; a build outside every witnessed range is
// framed as late under HYPOTHESIS(webkit-uncovered-generation-late).
func TestOrderUniversalBrowserClassGenerations(t *testing.T) {
	early := Engine{Kind: WebKit, Major: 18}
	nav := Request{Engine: early, Class: ClassNavigation, Method: "GET", HTTP2: true, Added: Added{Referer: true, Cookie: true}}
	plain, err := OrderUniversal(nav)
	if err != nil {
		t.Fatal(err)
	}
	hop := nav
	hop.Redirected = true
	// HYPOTHESIS(webkit-early-browser-get): an early redirect hop keeps the captured order.
	if got, err := OrderUniversal(hop); err != nil || !slices.Equal(got.Header, plain.Header) {
		t.Errorf("early redirect hop %v (%v), want %v", got.Header, err, plain.Header)
	}
	webview := nav
	webview.Engine = Engine{Kind: WebKit, Major: 18, Minor: 5, WebView: true}
	if got, err := OrderUniversal(webview); err != nil || !slices.Equal(got.Header, plain.Header) {
		t.Errorf("early-webview navigation %v (%v), want cookie last as %v", got.Header, err, plain.Header)
	}
	pf := Request{Engine: early, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true, Added: Added{Origin: true, Referer: true, RequestHeaders: true}}
	got, err := OrderUniversal(pf)
	if err != nil {
		t.Fatal(err)
	}
	accept := slices.Index(got.Header, "accept")
	if accept != len(got.Header)-1 || slices.Index(got.Header, "accept-language") > accept || slices.Index(got.Header, "accept-encoding") > accept ||
		slices.Contains(got.Header, "priority") {
		t.Errorf("early preflight %v: want accept-language and accept-encoding inside the dictionary, accept last, no priority", got.Header)
	}
	form := Request{Engine: early, Class: ClassForm, Method: "POST", HTTP2: true, Added: Added{Origin: true, Body: true, Referer: true, Cookie: true}}
	if got, err := OrderUniversal(form); err != nil || got.Header[len(got.Header)-1] != "cookie" || slices.Contains(got.Header, "priority") {
		t.Errorf("early form %v (%v): want early's cookie tail and no priority", got.Header, err)
	}
	for _, e := range []Engine{{Kind: WebKit, Major: 18, Minor: 2}, {Kind: WebKit, Major: 25}, {Kind: WebKit, Major: 26, WebView: true}} {
		if facts, err := WebKitFactsUniversal(e); err != nil || facts.Hypothesis != HypothesisUncoveredGenerationLate {
			t.Fatalf("%s: facts %+v (%v), want the uncovered-late hypothesis", e, facts, err)
		}
		for _, w := range universalWitnesses {
			if w.r.Engine != safari187 {
				continue
			}
			r := w.r
			r.Engine = e
			got, err := OrderUniversal(r)
			if err != nil || !slices.Equal(got.Header, strings.Fields(w.wire)) {
				t.Errorf("%s as %s: %v (%v), want late's %s", w.source, e, got.Header, err, w.wire)
			}
		}
	}
}

// HYPOTHESIS(chromium-form-next-run): Chrome 142-149 forms send Chrome 150-155's set; Chrome 141's differs.
func TestChromiumFormMajorsBetweenWitnessedRuns(t *testing.T) {
	form := func(major int, h2 bool) Request {
		return Request{Engine: Engine{Kind: Chromium, Major: major}, Class: ClassForm, Method: "POST", HTTP2: h2,
			Added: Added{ClientHints: lowEntropyHints, Origin: true, Body: true, Referer: true, Cookie: true, Priority: true, FetchUser: true}}
	}
	order := func(r Request) []string {
		t.Helper()
		w, err := OrderUniversal(r)
		if err != nil {
			t.Fatal(err)
		}
		return w.Header
	}
	if gap, next := order(form(147, true)), order(form(150, true)); !slices.Equal(gap, next) {
		t.Errorf("Chrome 147 form %v, want Chrome 150's %v", gap, next)
	}
	if old, next := order(form(141, true)), order(form(150, true)); slices.Equal(old, next) {
		t.Errorf("Chrome 141 form %v equals Chrome 150's", old)
	}
	h1 := order(form(151, false))
	if want := slices.Concat([]string{"host", "connection"}, slices.DeleteFunc(order(form(151, true)), func(n string) bool { return n == "priority" })); !slices.Equal(h1, want) {
		t.Errorf("HTTP/1.1 form %v, want %v", h1, want)
	}
}

// A Chromium no-cors element load is the call-less Blink map a script is.
func TestChromiumNoCORSIsTheScriptMap(t *testing.T) {
	for _, w := range browserWitnesses {
		if w.r.Class != ClassScript {
			continue
		}
		script, err := Order(w.r)
		if err != nil {
			t.Fatal(err)
		}
		r := w.r
		r.Class = ClassNoCORS
		got, err := OrderUniversal(r)
		if err != nil || !reflect.DeepEqual(got, script) {
			t.Errorf("%s as no-cors: %v (%v), script %v", w.source, got, err, script)
		}
	}
}
