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
	chromeUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
	chrome120   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	chrome151   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	safariUA    = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1"
	safari266   = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1"
	macSafariUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15"
	criosUA     = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1"
	webViewUA   = "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7103.60 Mobile Safari/537.36"
	edgeUA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.2.2903.86"
	operaUA     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0"
	firefoxUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
)

const (
	// useragent/parse_test.go's "edge android": no Edg/ token, so the raw-UA engine reader sees Chromium.
	edgeAndroidUA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.0.0"
	samsungUA     = "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36"
	noVersionUA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1"
)

var (
	chromiumPseudo = []string{":method", ":authority", ":scheme", ":path"}
	webkitPseudo   = []string{":method", ":scheme", ":authority", ":path"}
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
		{chromeUA, ClassPreflight, NoOrderError{Family: useragent.FamilyChrome, Class: ClassPreflight}, "transport: no wire-order law or captured header order for chrome preflight requests"},
		{safariUA, ClassNoCORS, NoOrderError{Family: useragent.FamilySafariIOS, Class: ClassNoCORS}, "transport: no wire-order law or captured header order for safari-ios no-cors requests"},
		{safariUA, ClassForm, NoOrderError{Family: useragent.FamilySafariIOS, Class: ClassForm}, "transport: no wire-order law or captured header order for safari-ios form requests"},
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
	for _, class := range []RequestClass{ClassNavigation, ClassReload, ClassXHR, ClassFetch, ClassScript, ClassImage, ClassForm, ClassPreflight, ClassNoCORS} {
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

// Real browser requests (header names in received order) of the classes strict Order refuses, from wireorder's
// universal witnesses: OrderUniversal answers each with one law result, header and pseudo-header order.
func TestOrderUniversalReproducesCaptures(t *testing.T) {
	chromeForm := wireorder.Added{ClientHints: lowEntropyHints, Origin: true, Body: true, Referer: true, Cookie: true, Priority: true, FetchUser: true}
	cases := []struct {
		source string
		r      OrderRequest
		wire   string
		pseudo []string
	}{
		{"Chrome 151 login form",
			OrderRequest{UserAgent: chrome151, Class: ClassForm, Method: "POST", HTTP2: true, Added: chromeForm},
			"content-length cache-control sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests content-type user-agent origin accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest referer accept-encoding accept-language cookie priority",
			chromiumPseudo},
		{"Safari 18.7.5 login form",
			OrderRequest{UserAgent: safariUA, Class: ClassForm, Method: "POST", HTTP2: true,
				Added: wireorder.Added{Origin: true, Body: true, Referer: true, Cookie: true, Priority: true}},
			"accept content-type origin sec-fetch-site sec-fetch-mode user-agent referer sec-fetch-dest content-length accept-language priority accept-encoding cookie",
			webkitPseudo},
		{"Chrome 151 preflight",
			OrderRequest{UserAgent: chrome151, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true,
				Added: wireorder.Added{Origin: true, Referer: true, Priority: true, RequestHeaders: true}},
			"accept access-control-request-method access-control-request-headers origin user-agent sec-fetch-mode sec-fetch-site sec-fetch-dest referer accept-encoding accept-language priority",
			chromiumPseudo},
		{"Safari 18.7 preflight without a referrer",
			OrderRequest{UserAgent: safariUA, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true,
				Added: wireorder.Added{Origin: true, Priority: true, RequestHeaders: true}},
			"sec-fetch-site origin access-control-request-method access-control-request-headers sec-fetch-mode user-agent content-length sec-fetch-dest accept accept-language priority accept-encoding",
			webkitPseudo},
		{"Chrome 151 cross-site stylesheet (no-cors)",
			OrderRequest{UserAgent: chrome151, Class: ClassNoCORS, Method: "GET", HTTP2: true,
				Added: wireorder.Added{ClientHints: lowEntropyHints, Referer: true, Priority: true, StorageAccess: true}},
			"sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest sec-fetch-storage-access referer accept-encoding accept-language priority",
			chromiumPseudo},
		{"Chrome 151 image",
			OrderRequest{UserAgent: chrome151, Class: ClassImage, Method: "GET", HTTP2: true,
				Added: wireorder.Added{ClientHints: lowEntropyHints, Referer: true, Cookie: true, Priority: true}},
			"sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest referer accept-encoding accept-language cookie priority",
			chromiumPseudo},
		{"Safari 26.6 image (no-cors)",
			OrderRequest{UserAgent: safari266, Class: ClassNoCORS, Method: "GET", HTTP2: true,
				Added: wireorder.Added{Referer: true, Cookie: true, Priority: true}},
			"sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding cookie",
			webkitPseudo},
		{"Safari 26.6 image (image)",
			OrderRequest{UserAgent: safari266, Class: ClassImage, Method: "GET", HTTP2: true,
				Added: wireorder.Added{Referer: true, Cookie: true, Priority: true}},
			"sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode accept-language priority accept-encoding cookie",
			webkitPseudo},
	}
	for _, tc := range cases {
		got, err := OrderUniversal(tc.r)
		if err != nil {
			t.Errorf("%s: %v", tc.source, err)
			continue
		}
		if want := strings.Fields(tc.wire); !slices.Equal(got.Header, want) {
			t.Errorf("%s:\n got %q\nwant %q", tc.source, got.Header, want)
		}
		if !slices.Equal(got.Pseudo, tc.pseudo) {
			t.Errorf("%s: pseudo %q, want %q", tc.source, got.Pseudo, tc.pseudo)
		}
	}
}

// OrderUniversal is wireorder.OrderUniversal on the UA's engine and the class's law class, refusals included.
func TestOrderUniversalIsTheLaw(t *testing.T) {
	chromium := wireorder.Engine{Kind: wireorder.Chromium, Major: 152}
	safari := wireorder.Engine{Kind: wireorder.WebKit, Major: 18, Minor: 7}
	mac := wireorder.Engine{Kind: wireorder.WebKit, Major: 26, Minor: 6}
	crios := wireorder.Engine{Kind: wireorder.WebKit, Major: 26, Minor: 6, WebView: true}
	xhrAdded := func(hints []string) wireorder.Added {
		return wireorder.Added{ClientHints: hints, Origin: true, Referer: true, Cookie: true, Body: true, Priority: true}
	}
	nav := wireorder.Added{ClientHints: lowEntropyHints, FetchUser: true, Referer: true, Cookie: true, Priority: true}
	cases := []struct {
		name   string
		r      OrderRequest
		engine wireorder.Engine
		class  wireorder.Class
	}{
		{"chrome navigation", OrderRequest{UserAgent: chromeUA, Class: ClassNavigation, Method: "GET", HTTP2: true, Added: nav},
			chromium, wireorder.ClassNavigation},
		{"chrome redirected navigation", OrderRequest{UserAgent: chromeUA, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true, Added: nav},
			chromium, wireorder.ClassNavigation},
		{"chrome script", OrderRequest{UserAgent: chromeUA, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, Referer: true, Cookie: true}}, chromium, wireorder.ClassScript},
		{"chrome xhr", OrderRequest{UserAgent: chromeUA, Class: ClassXHR, Method: "POST", HTTP2: true,
			Calls: []string{"content-type"}, Added: xhrAdded(lowEntropyHints)}, chromium, wireorder.ClassXHR},
		{"chrome http/1.1 fetch", OrderRequest{UserAgent: chromeUA, Class: ClassFetch, Method: "POST",
			Calls: []string{"x-b", "content-type", "x-a"}, Added: xhrAdded(lowEntropyHints)}, chromium, wireorder.ClassFetch},
		{"chrome form", OrderRequest{UserAgent: chromeUA, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, Origin: true, Body: true, Referer: true, Cookie: true, Priority: true, FetchUser: true}},
			chromium, wireorder.ClassForm},
		{"chrome http/1.1 preflight", OrderRequest{UserAgent: chromeUA, Class: ClassPreflight, Method: "OPTIONS",
			Added: wireorder.Added{Origin: true, Referer: true, RequestHeaders: true}}, chromium, wireorder.ClassPreflight},
		{"chrome image", OrderRequest{UserAgent: chromeUA, Class: ClassImage, Method: "GET", HTTP2: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, Referer: true, Priority: true}}, chromium, wireorder.ClassNoCORS},
		{"safari navigation", OrderRequest{UserAgent: safariUA, Class: ClassNavigation, Method: "GET", HTTP2: true,
			Added: wireorder.Added{UpgradeInsecureRequests: true, Priority: true}}, safari, wireorder.ClassNavigation},
		{"safari http/1.1 navigation", OrderRequest{UserAgent: safariUA, Class: ClassNavigation, Method: "GET",
			Added: wireorder.Added{Referer: true, Priority: true}}, safari, wireorder.ClassNavigation},
		{"safari parser script", OrderRequest{UserAgent: safariUA, Class: ClassScript, Method: "GET", HTTP2: true,
			Added: wireorder.Added{Referer: true, Cookie: true, Priority: true}}, safari, wireorder.ClassScript},
		{"safari fetch", OrderRequest{UserAgent: safariUA, Class: ClassFetch, Method: "GET", HTTP2: true,
			Calls: []string{"x-alpha", "x-beta"}, Added: wireorder.Added{Referer: true, Cookie: true, Priority: true}}, safari, wireorder.ClassFetch},
		{"macos safari xhr", OrderRequest{UserAgent: macSafariUA, Class: ClassXHR, Method: "POST", HTTP2: true,
			Calls: []string{"content-type"}, Added: xhrAdded(nil)}, mac, wireorder.ClassXHR},
		{"crios inserted script", OrderRequest{UserAgent: criosUA, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true,
			Added: wireorder.Added{Referer: true, Cookie: true, Priority: true}}, crios, wireorder.ClassScript},
		{"crios form", OrderRequest{UserAgent: criosUA, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: wireorder.Added{Origin: true, Body: true, Referer: true, Priority: true}}, crios, wireorder.ClassForm},
		// Refusals: a malformed request or class answers the law's own typed error.
		{"GET form", OrderRequest{UserAgent: chromeUA, Class: ClassForm, Method: "GET", HTTP2: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, Origin: true, Body: true}}, chromium, wireorder.ClassForm},
		{"preflight with a cookie", OrderRequest{UserAgent: safariUA, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true,
			Added: wireorder.Added{Origin: true, Cookie: true, RequestHeaders: true}}, safari, wireorder.ClassPreflight},
		{"image with page calls", OrderRequest{UserAgent: chromeUA, Class: ClassImage, Method: "GET", HTTP2: true,
			Calls: []string{"x-a"}, Added: wireorder.Added{ClientHints: lowEntropyHints}}, chromium, wireorder.ClassNoCORS},
		{"xhr with access-control-request-headers", OrderRequest{UserAgent: chromeUA, Class: ClassXHR, Method: "POST", HTTP2: true,
			Calls: []string{"content-type"}, Added: wireorder.Added{ClientHints: lowEntropyHints, Origin: true, Body: true, RequestHeaders: true}},
			chromium, wireorder.ClassXHR},
		{"unknown class", OrderRequest{UserAgent: chromeUA, Class: "beacon", Method: "POST", HTTP2: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, Origin: true, Body: true}}, chromium, wireorder.ClassUnknown},
		{"empty class", OrderRequest{UserAgent: safariUA, Method: "GET", HTTP2: true}, safari, wireorder.ClassUnknown},
	}
	for _, tc := range cases {
		got, err := OrderUniversal(tc.r)
		want, wantErr := wireorder.OrderUniversal(wireorder.Request{
			Engine: tc.engine, Class: tc.class, Method: tc.r.Method, HTTP2: tc.r.HTTP2, Calls: tc.r.Calls,
			Added: tc.r.Added, Redirected: tc.r.Redirected, Inserted: tc.r.Inserted,
		})
		if !reflect.DeepEqual(err, wantErr) {
			t.Errorf("%s: error %v, the law's %v", tc.name, err, wantErr)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %q %q\nlaw %q %q", tc.name, got.Header, got.Pseudo, want.Header, want.Pseudo)
		}
	}
	// The equality above holds for refusals too; these pin which typed error each malformed request answers.
	for name, tc := range map[string]struct {
		r      OrderRequest
		target any
	}{
		"GET form":                 {OrderRequest{UserAgent: chromeUA, Class: ClassForm, Method: "GET", HTTP2: true, Added: wireorder.Added{Origin: true, Body: true}}, new(*wireorder.InputError)},
		"preflight without origin": {OrderRequest{UserAgent: chromeUA, Class: ClassPreflight, Method: "OPTIONS", HTTP2: true}, new(*wireorder.InputError)},
		"unknown class":            {OrderRequest{UserAgent: chromeUA, Class: "beacon", Method: "GET", HTTP2: true}, new(*wireorder.UnwitnessedError)},
		"chrome 120 form": {OrderRequest{UserAgent: chrome120, Class: ClassForm, Method: "POST", HTTP2: true,
			Added: wireorder.Added{ClientHints: lowEntropyHints, Origin: true, Body: true, FetchUser: true}}, new(*wireorder.UnwitnessedError)},
	} {
		got, err := OrderUniversal(tc.r)
		if !errors.As(err, tc.target) || got.Header != nil || got.Pseudo != nil {
			t.Errorf("%s: %q %q, %v; want %T", name, got.Header, got.Pseudo, err, tc.target)
		}
	}
}

// OrderUniversal serves no captured row: a reload and every Android WebView request stay refused, as do lawless engines.
func TestOrderUniversalFailsClosed(t *testing.T) {
	type refusal struct {
		ua    string
		class RequestClass
		want  error
		text  string
	}
	var cases []refusal
	for _, class := range []RequestClass{ClassNavigation, ClassReload, ClassXHR, ClassFetch, ClassScript, ClassImage, ClassForm, ClassPreflight, ClassNoCORS} {
		cases = append(cases, refusal{webViewUA, class, &NoLawError{Family: useragent.FamilyAndroidWebView, Class: class},
			"transport: no wire-order law for android-webview " + string(class) + " requests"})
	}
	cases = append(cases,
		refusal{chromeUA, ClassReload, &NoLawError{Family: useragent.FamilyChrome, Class: ClassReload}, "transport: no wire-order law for chrome reload requests"},
		refusal{safariUA, ClassReload, &NoLawError{Family: useragent.FamilySafariIOS, Class: ClassReload}, "transport: no wire-order law for safari-ios reload requests"},
		refusal{criosUA, ClassReload, &NoLawError{Class: ClassReload}, "transport: no wire-order law for reload requests"},
		refusal{firefoxUA, ClassNavigation, &NoOrderError{Family: useragent.FamilyFirefox}, "transport: no wire-order law or captured header order for firefox"},
		refusal{edgeUA, ClassForm, &NoOrderError{Family: useragent.FamilyEdge}, "transport: no wire-order law or captured header order for edge"},
		refusal{operaUA, ClassPreflight, &NoOrderError{Family: useragent.FamilyOpera}, "transport: no wire-order law or captured header order for opera"},
		refusal{edgeAndroidUA, ClassNavigation, &NoOrderError{Family: useragent.FamilyEdge}, "transport: no wire-order law or captured header order for edge"},
		refusal{edgeAndroidUA, ClassReload, &NoOrderError{Family: useragent.FamilyEdge}, "transport: no wire-order law or captured header order for edge"},
		refusal{noVersionUA, ClassNavigation, &NoOrderError{Family: useragent.FamilySafariIOS}, "transport: no wire-order law or captured header order for safari-ios"},
	)
	for _, tc := range cases {
		got, err := OrderUniversal(OrderRequest{UserAgent: tc.ua, Class: tc.class, Method: "GET", HTTP2: true})
		if !reflect.DeepEqual(err, tc.want) || err.Error() != tc.text {
			t.Errorf("OrderUniversal(%q, %s) = %v; want %q", tc.ua, tc.class, err, tc.text)
		}
		if got.Header != nil || got.Pseudo != nil {
			t.Errorf("OrderUniversal(%q, %s) returned an order with its error", tc.ua, tc.class)
		}
	}
	if _, err := OrderUniversal(OrderRequest{Class: ClassNavigation, Method: "GET", HTTP2: true}); !errors.As(err, new(*useragent.UnsupportedError)) {
		t.Errorf("empty User-Agent: %v, want useragent.UnsupportedError", err)
	}
	if _, err := OrderUniversal(OrderRequest{UserAgent: samsungUA, Class: ClassNavigation, Method: "GET", HTTP2: true}); !errors.As(err, new(*useragent.UnsupportedError)) {
		t.Errorf("Samsung Internet (parsed as Chrome): %v, want useragent.UnsupportedError", err)
	}
}

// testShapePrefix is a captured Safari 18.7 username-validation XHR's Shape prefix (safari18.7-a#398).
const testShapePrefix = "x-gyjwza5z-"

// shapeXHR is safari18.7-a#398's request: content-type, then the Shape block without -a0.
func shapeXHR(ua string, hints []string, pins ...*wireorder.Pin) OrderRequest {
	calls := []string{"content-type"}
	for _, s := range "fbcdza" {
		calls = append(calls, testShapePrefix+string(s))
	}
	return OrderRequest{UserAgent: ua, Class: ClassXHR, Method: "POST", HTTP2: true, Calls: calls, ShapePrefix: testShapePrefix,
		Pins: pins, Added: wireorder.Added{ClientHints: hints, Origin: true, Referer: true, Cookie: true, Body: true, Priority: true}}
}

// A captured WebKit case on safari18.7-a#398's dictionary: its reverse of the law's first outcome (a captured case
// is its own order) followed by the generation's tail.
func capturedPin(t *testing.T) (*wireorder.Pin, []string) {
	t.Helper()
	safari := wireorder.Engine{Kind: wireorder.WebKit, Major: 18, Minor: 7}
	r := shapeXHR(safariUA, nil)
	outcomes, err := wireorder.Outcomes(r.law(safari, wireorder.ClassXHR, nil))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := wireorder.WebKitFacts(safari)
	if err != nil {
		t.Fatal(err)
	}
	dict := slices.DeleteFunc(slices.Clone(outcomes[0]), func(name string) bool { return slices.Contains(facts.Generation.Tail, name) })
	captured := slices.Clone(dict)
	slices.Reverse(captured)
	pin := &wireorder.Pin{ID: "test-captured", Engine: wireorder.WebKit.String(), Cases: []wireorder.PinCase{{
		Dictionary: captured, Captured: true, Generations: []string{facts.Generation.Name}, Witnesses: []wireorder.Witness{{HAR: "test"}}}}}
	return pin, slices.Concat(captured, outcomes[0][len(dict):])
}

// OrderUniversal passes the resolved engine's pins from a mixed candidate set and ShapePrefix unchanged.
func TestOrderUniversalSelectsEnginePins(t *testing.T) {
	pin, want := capturedPin(t)
	install := &wireorder.Pin{ID: "test-install", Engine: wireorder.WebKit.String(), Install: [][2]string{{"shape:a", "shape:b"}}}
	foreign := &wireorder.Pin{ID: "chromium-label", Engine: wireorder.Chromium.String()}

	// WebKit: the captured case orders the request; the chromium-labelled candidate is dropped.
	got, err := OrderUniversal(shapeXHR(safariUA, nil, foreign, pin, install))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Header, want) || !slices.Equal(got.Pseudo, webkitPseudo) {
		t.Fatalf("pinned WebKit request:\n got %q %q\nwant %q %q", got.Header, got.Pseudo, want, webkitPseudo)
	}

	// Chromium: the WebKit candidates are dropped (the Chromium law refuses any pin) and ShapePrefix still reaches it.
	chromium := wireorder.Engine{Kind: wireorder.Chromium, Major: 152}
	r := shapeXHR(chromeUA, lowEntropyHints, pin, install)
	got, err = OrderUniversal(r)
	law, lawErr := wireorder.OrderUniversal(r.law(chromium, wireorder.ClassXHR, nil))
	if err != nil || lawErr != nil || !reflect.DeepEqual(got, law) {
		t.Fatalf("Chromium with WebKit candidates = %q (%v), the unpinned law's %q (%v)", got.Header, err, law.Header, lawErr)
	}
	other := r
	other.ShapePrefix = "x-q7m2k9vb-"
	_, err = OrderUniversal(other)
	if input, ok := errors.AsType[*wireorder.InputError](err); !ok || input.Field != "shape_prefix" {
		t.Fatalf("Chromium with a prefix no call carries: %v, want the law's shape_prefix InputError", err)
	}
	// A matching-engine candidate is passed, so the Chromium law's own refusal stands.
	_, err = OrderUniversal(shapeXHR(chromeUA, lowEntropyHints, foreign))
	if input, ok := errors.AsType[*wireorder.InputError](err); !ok || input.Field != "pins" {
		t.Fatalf("Chromium with a chromium-labelled pin: %v, want the law's pins InputError", err)
	}

	// Strict Order passes pins as given: a WebKit pin on Chromium is the law's refusal.
	if _, err := Order(shapeXHR(chromeUA, lowEntropyHints, pin)); !errors.As(err, new(*wireorder.InputError)) {
		t.Fatalf("strict Chromium with a WebKit pin: %v, want the law's InputError", err)
	}
}

func TestOrderUniversalRefusesMalformedPinCandidates(t *testing.T) {
	pin, _ := capturedPin(t)
	for name, tc := range map[string]struct {
		bad   *wireorder.Pin
		field string
	}{
		"nil pin":      {nil, "pins[1]"},
		"empty engine": {&wireorder.Pin{ID: "p"}, "pins[1].engine"},
		"cased engine": {&wireorder.Pin{ID: "p", Engine: "WebKit"}, "pins[1].engine"},
		"unknown":      {&wireorder.Pin{ID: "p", Engine: "gecko"}, "pins[1].engine"},
	} {
		for _, ua := range []string{safariUA, chromeUA} {
			got, err := OrderUniversal(shapeXHR(ua, nil, pin, tc.bad))
			input, ok := errors.AsType[*wireorder.InputError](err)
			if !ok || input.Field != tc.field || got.Header != nil {
				t.Errorf("%s on %q: %q, %v; want an InputError on %s", name, ua, got.Header, err, tc.field)
			}
		}
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
