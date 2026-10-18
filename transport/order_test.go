package transport

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/EvadeNow/evade-sdk/useragent"
	"github.com/EvadeNow/evade-sdk/wireorder"
)

const (
	chromeUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
	chrome120 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	safariUA  = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1"
	criosUA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1"
	webViewUA = "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7103.60 Mobile Safari/537.36"
	edgeUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.2.2903.86"
	operaUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0"
	firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
)

var lowEntropyHints = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}

func TestOrderIsTheLawForLawClasses(t *testing.T) {
	chromium := wireorder.Engine{Kind: wireorder.Chromium, Major: 152}
	safari := wireorder.Engine{Kind: wireorder.WebKit, Major: 18, Minor: 7}
	crios := wireorder.Engine{Kind: wireorder.WebKit, Major: 26, Minor: 6, WebView: true}
	xhrAdded := func(hints []string) wireorder.Added {
		return wireorder.Added{ClientHints: hints, Origin: true, Referer: true, Cookie: true, Body: true, Priority: true}
	}
	cases := []struct {
		name     string
		r        OrderRequest
		engine   wireorder.Engine
		class    wireorder.Class
		resolves bool
	}{
		{"chrome navigation", OrderRequest{UserAgent: chromeUA, Class: ClassNavigation, Method: "GET", HTTP2: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, FetchUser: true, Priority: true}},
			chromium, wireorder.ClassNavigation, true},
		{"chrome redirected navigation", OrderRequest{UserAgent: chromeUA, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, FetchUser: true, Referer: true, Cookie: true, Priority: true}},
			chromium, wireorder.ClassNavigation, true},
		{"chrome script", OrderRequest{UserAgent: chromeUA, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, Referer: true, Cookie: true}},
			chromium, wireorder.ClassScript, true},
		{"chrome xhr", OrderRequest{UserAgent: chromeUA, Class: ClassXHR, Method: "POST", HTTP2: true,
			Calls: []string{"content-type"}, Added: xhrAdded(lowEntropyHints)},
			chromium, wireorder.ClassXHR, true},
		{"chrome http/1.1 fetch", OrderRequest{UserAgent: chromeUA, Class: ClassFetch, Method: "POST",
			Calls: []string{"x-b", "content-type", "x-a"}, Added: xhrAdded(lowEntropyHints)},
			chromium, wireorder.ClassFetch, true},
		{"safari inserted script", OrderRequest{UserAgent: safariUA, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true,
			Added: wireorder.Added{Referer: true, Priority: true}},
			safari, wireorder.ClassScript, true},
		{"safari xhr", OrderRequest{UserAgent: safariUA, Class: ClassXHR, Method: "POST", HTTP2: true,
			Calls: []string{"content-type"}, Added: xhrAdded(nil)},
			safari, wireorder.ClassXHR, false},
		{"safari fetch", OrderRequest{UserAgent: safariUA, Class: ClassFetch, Method: "GET", HTTP2: true,
			Calls: []string{"x-alpha", "x-beta"}, Added: wireorder.Added{Referer: true, Cookie: true, Priority: true}},
			safari, wireorder.ClassFetch, false},
		{"crios inserted script", OrderRequest{UserAgent: criosUA, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true,
			Added: wireorder.Added{Referer: true, Cookie: true, Priority: true}},
			crios, wireorder.ClassScript, true},
	}
	for _, tc := range cases {
		got, err := Order(tc.r)
		want, wantErr := wireorder.Order(wireorder.Request{
			Engine: tc.engine, Class: tc.class, Method: tc.r.Method, HTTP2: tc.r.HTTP2, Calls: tc.r.Calls,
			Added: tc.r.Added, Redirected: tc.r.Redirected, Inserted: tc.r.Inserted,
		})
		if tc.resolves && wantErr != nil {
			t.Fatalf("%s: the law refuses the test request: %v", tc.name, wantErr)
		}
		if !reflect.DeepEqual(err, wantErr) {
			t.Errorf("%s: error %v, the law's %v", tc.name, err, wantErr)
			continue
		}
		if wantErr == nil && !slices.Equal(got, want.Header) {
			t.Errorf("%s:\n got %q\nlaw %q", tc.name, got, want.Header)
		}
		if wantErr != nil && got != nil {
			t.Errorf("%s: returned an order with its error", tc.name)
		}
	}
}

func TestOrderSurfacesLawRefusals(t *testing.T) {
	cases := map[string]OrderRequest{
		"safari navigation": {UserAgent: safariUA, Class: ClassNavigation, Method: "GET", HTTP2: true,
			Added: wireorder.Added{FetchUser: true, Priority: true}},
		"safari parser script": {UserAgent: safariUA, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: wireorder.Added{Referer: true, Priority: true}},
		"chrome 120 xhr": {UserAgent: chrome120, Class: ClassXHR, Method: "POST", HTTP2: true,
			Calls: []string{"content-type"}, Added: wireorder.Added{ClientHints: lowEntropyHints, Origin: true, Body: true}},
	}
	for name, r := range cases {
		got, err := Order(r)
		var unwitnessed *wireorder.UnwitnessedError
		if !errors.As(err, &unwitnessed) {
			t.Errorf("%s: %q, %v; want the law's UnwitnessedError", name, got, err)
		}
	}
	_, err := Order(OrderRequest{UserAgent: chromeUA, Class: ClassXHR, Method: "POST", HTTP2: true,
		Added: wireorder.Added{ClientHints: lowEntropyHints}})
	var input *wireorder.InputError
	if !errors.As(err, &input) {
		t.Errorf("POST without Origin: %v, want the law's InputError", err)
	}
}

func TestOrderServesCapturedRowsOutsideTheLaw(t *testing.T) {
	cases := []struct {
		ua    string
		class RequestClass
		want  []string
	}{
		{chromeUA, ClassReload, chromeOrder(ClassReload)},
		{chromeUA, ClassImage, chromeOrder(ClassImage)},
		{safariUA, ClassReload, safariIOSOrder(ClassReload)},
		{webViewUA, ClassNavigation, androidWebViewOrder(ClassNavigation)},
		{webViewUA, ClassReload, androidWebViewOrder(ClassReload)},
		{webViewUA, ClassXHR, androidWebViewOrder(ClassXHR)},
		{webViewUA, ClassScript, androidWebViewOrder(ClassScript)},
	}
	for _, tc := range cases {
		if tc.want == nil {
			t.Fatalf("%s %s: no captured row", tc.ua, tc.class)
		}
		got, err := Order(OrderRequest{UserAgent: tc.ua, Class: tc.class, Method: "GET", HTTP2: true})
		if err != nil {
			t.Fatalf("%s %s: %v", tc.ua, tc.class, err)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s %s = %q, want %q", tc.ua, tc.class, got, tc.want)
		}
	}
	nav, err := Order(OrderRequest{UserAgent: webViewUA, Class: ClassNavigation, Method: "GET", HTTP2: true})
	if err != nil || !slices.Contains(nav, "x-requested-with") {
		t.Fatalf("android webview navigation %q, %v: not WebView's captured row", nav, err)
	}
}

func TestOrderFailsClosed(t *testing.T) {
	cases := []struct {
		ua    string
		class RequestClass
		want  NoOrderError
		text  string
	}{
		{firefoxUA, ClassNavigation, NoOrderError{Family: useragent.FamilyFirefox}, "transport: no wire-order law or captured header order for firefox"},
		{edgeUA, ClassNavigation, NoOrderError{Family: useragent.FamilyEdge}, "transport: no wire-order law or captured header order for edge"},
		{edgeUA, ClassReload, NoOrderError{Family: useragent.FamilyEdge}, "transport: no wire-order law or captured header order for edge"},
		{operaUA, ClassXHR, NoOrderError{Family: useragent.FamilyOpera}, "transport: no wire-order law or captured header order for opera"},
		{webViewUA, ClassFetch, NoOrderError{Family: useragent.FamilyAndroidWebView, Class: ClassFetch}, "transport: no wire-order law or captured header order for android-webview fetch requests"},
		{webViewUA, ClassImage, NoOrderError{Family: useragent.FamilyAndroidWebView, Class: ClassImage}, "transport: no wire-order law or captured header order for android-webview image requests"},
		{safariUA, ClassImage, NoOrderError{Family: useragent.FamilySafariIOS, Class: ClassImage}, "transport: no wire-order law or captured header order for safari-ios image requests"},
		{chromeUA, ClassForm, NoOrderError{Family: useragent.FamilyChrome, Class: ClassForm}, "transport: no wire-order law or captured header order for chrome form requests"},
	}
	for _, tc := range cases {
		got, err := Order(OrderRequest{UserAgent: tc.ua, Class: tc.class, Method: "GET", HTTP2: true})
		var orderErr *NoOrderError
		if !errors.As(err, &orderErr) || *orderErr != tc.want || err.Error() != tc.text {
			t.Errorf("Order(%s, %s) = %q, %v; want %q", tc.want.Family, tc.class, got, err, tc.text)
		}
		if got != nil {
			t.Errorf("Order(%s, %s) returned an order with its error", tc.want.Family, tc.class)
		}
	}
	for _, r := range []OrderRequest{
		{UserAgent: "", Class: ClassNavigation},
		{UserAgent: criosUA, Class: ClassReload},
	} {
		if _, err := Order(r); !errors.As(err, new(*useragent.UnsupportedError)) {
			t.Errorf("%q %s: %v, want useragent.UnsupportedError", r.UserAgent, r.Class, err)
		}
	}
}

func TestCapturedRowsAreLowercaseAndUnique(t *testing.T) {
	rows := 0
	for _, class := range []RequestClass{ClassNavigation, ClassReload, ClassXHR, ClassFetch, ClassScript, ClassImage, ClassForm} {
		for family, row := range map[useragent.Family][]string{
			useragent.FamilyChrome:         chromeOrder(class),
			useragent.FamilyAndroidWebView: androidWebViewOrder(class),
			useragent.FamilySafariIOS:      safariIOSOrder(class),
		} {
			if row == nil {
				continue
			}
			rows++
			seen := map[string]bool{}
			for _, name := range row {
				if name != strings.ToLower(name) || strings.TrimSpace(name) != name || name == "" {
					t.Errorf("%s %s: header %q is not a lowercase name", family, class, name)
				}
				if seen[name] {
					t.Errorf("%s %s: header %q appears twice", family, class, name)
				}
				seen[name] = true
			}
		}
	}
	if rows != 7 {
		t.Fatalf("captured rows = %d, want 7", rows)
	}
}

func TestOrderReturnsCallerOwnedSlice(t *testing.T) {
	r := OrderRequest{UserAgent: chromeUA, Class: ClassReload}
	first, err := Order(r)
	if err != nil {
		t.Fatal(err)
	}
	first[0] = "mutated"
	second, _ := Order(r)
	if second[0] != "cache-control" {
		t.Fatalf("editing one Order result changed the next: %q", second[0])
	}
}

func TestArrangeFollowsTheOrder(t *testing.T) {
	headers := Headers{{"accept", "*/*"}, {"cookie", "a=1"}, {"User-Agent", "UA"}, {"cookie", "b=2"}, {"content-length", ""}}
	got, err := headers.Arrange([]string{"user-agent", "content-length", "cookie", "accept"})
	if err != nil {
		t.Fatal(err)
	}
	want := Headers{{"User-Agent", "UA"}, {"content-length", ""}, {"cookie", "a=1"}, {"cookie", "b=2"}, {"accept", "*/*"}}
	if !slices.Equal(got, want) {
		t.Fatalf("arranged %q, want %q", got, want)
	}
	if headers[0].Name != "accept" {
		t.Fatal("Arrange reordered its receiver")
	}
}

func TestArrangeRefusesAnotherHeaderSet(t *testing.T) {
	_, err := Headers{{"accept", "*/*"}, {"x-extra", "1"}}.Arrange([]string{"accept", "referer"})
	var arrangeErr *ArrangeError
	if !errors.As(err, &arrangeErr) {
		t.Fatalf("err = %v, want ArrangeError", err)
	}
	if !slices.Equal(arrangeErr.Extra, []string{"x-extra"}) || !slices.Equal(arrangeErr.Missing, []string{"referer"}) {
		t.Fatalf("ArrangeError = %+v", arrangeErr)
	}
}
