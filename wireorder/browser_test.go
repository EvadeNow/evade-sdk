package wireorder

import (
	"errors"
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
	{"t_register#217 www.target.com/login (Chrome 151, hop after gsp.target.com's 302)",
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
	{"t_register#227 assets.targetimg1.com/ssx/ssx.mod.js?async (Chrome 151 loader)",
		Request{Engine: Engine{Kind: Chromium, Major: 151}, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: Added{ClientHints: lowEntropyHints, Referer: true, StorageAccess: true, Priority: true}},
		"sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest sec-fetch-storage-access referer accept-encoding accept-language priority"},
	{"newlogin#133 www.chase.com channela.js?async&seed= (Chrome 151, Accept-CH hints)",
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
		{"demand-item#129", Added{Referer: true, Priority: true},
			"sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding"},
		{"starbucks-ios#143", Added{Priority: true},
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
