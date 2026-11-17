package transport

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/EvadeNow/evade-sdk/tlsprofile"
	"github.com/EvadeNow/evade-sdk/useragent"
	fhttp "github.com/bogdanfinn/fhttp"
)

const (
	iosSafari185    = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"
	iosSafari2661   = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.1 Mobile/15E148 Safari/604.1"
	iPhoneCriOS2661 = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1"
	windowsChrome   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
	macChrome       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	macSafari       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15"
)

func mustBrowser(t *testing.T, ua string) Browser {
	t.Helper()
	browser, err := NewBrowser(ua)
	if err != nil {
		t.Fatalf("NewBrowser(%q): %v", ua, err)
	}
	return browser
}

func TestNewBrowserBindsTheModeledBrowsers(t *testing.T) {
	for ua, want := range map[string]struct {
		family         useragent.Family
		tls            string
		acceptEncoding string
		desktopChrome  bool
		needsHints     bool
	}{
		iosSafari185:  {useragent.FamilySafariIOS, "safari_ios_18_5", "gzip, deflate, br", false, false},
		iosSafari2661: {useragent.FamilySafariIOS, "safari_ios_26_0", "gzip, deflate, br, zstd", false, false},
		// One Safari 26 network stack on Mac and iPhone (tlsprofile/testdata/safari-macos-26.4.json); its
		// release's Safari Accept-Encoding (HYPOTHESIS(webkit_macos_is_ios_late)).
		macSafari:     {useragent.FamilySafariMacOS, "safari_ios_26_0", "gzip, deflate, br, zstd", false, false},
		windowsChrome: {useragent.FamilyChrome, "chrome_154", ChromeAcceptEncoding, true, true},
		macChrome:     {useragent.FamilyChrome, "chrome_154", ChromeAcceptEncoding, true, true},
	} {
		browser := mustBrowser(t, ua)
		if browser.Agent.Family != want.family || browser.TLS.Name != want.tls ||
			browser.AcceptEncoding != want.acceptEncoding || browser.DesktopChrome() != want.desktopChrome ||
			browser.UserAgent() != ua {
			t.Errorf("%q = family %s tls %q accept-encoding %q desktop chrome %v", ua,
				browser.Agent.Family, browser.TLS.Name, browser.AcceptEncoding, browser.DesktopChrome())
		}
		if browser.TLS.Behavior.RandomizeExtensionOrder && want.family == useragent.FamilySafariIOS {
			t.Errorf("%q: iOS Safari's TLS profile randomizes its extension order", ua)
		}
		// Chrome sends sec-ch-ua* on every request: without its fingerprint's
		// hints it is not complete.
		if (browser.Complete() == nil) == want.needsHints {
			t.Errorf("%q Complete() = %v", ua, browser.Complete())
		}
	}
}

// TestCriOSRunsAsItsIOSReleaseSafari: Chrome for iPhone (iOS 26.6.1)
// presents its own User-Agent with the TLS profile and Accept-Encoding of
// Safari 26.6.1 on the same iPhone (tlsprofile/testdata/chrome-ios-149-ios-26.6.json).
func TestCriOSRunsAsItsIOSReleaseSafari(t *testing.T) {
	browser := mustBrowser(t, iPhoneCriOS2661)
	safari := mustBrowser(t, iosSafari2661)
	if browser.UserAgent() != iPhoneCriOS2661 || browser.Agent.Family != useragent.FamilySafariIOS ||
		browser.Agent.OS != useragent.OSIOS || browser.Agent.Major != 26 || browser.Agent.Minor != 6 || !browser.Agent.Mobile {
		t.Fatalf("CriOS agent = %+v", browser.Agent)
	}
	if browser.TLS.Name != safari.TLS.Name || browser.AcceptEncoding != safari.AcceptEncoding || browser.DesktopChrome() {
		t.Fatalf("CriOS TLS %q / Accept-Encoding %q, Safari 26.6.1's %q / %q", browser.TLS.Name, browser.AcceptEncoding,
			safari.TLS.Name, safari.AcceptEncoding)
	}
}

func TestNewBrowserFailsClosed(t *testing.T) {
	var unsupported *useragent.UnsupportedError
	if _, err := NewBrowser("Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/150.0 Mobile/15E148 Safari/605.1.15"); !errors.As(err, &unsupported) {
		t.Errorf("Firefox for iOS error = %v", err)
	}
	var noProfile *tlsprofile.NoProfileError
	for name, ua := range map[string]string{
		"Safari 5.1":                              "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
		"Chrome 151, unlike chrome_150":           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
		"Android Chrome 156, never captured":      "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
		"iOS Safari 18.3, unlike safari_ios_18_0": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
	} {
		if _, err := NewBrowser(ua); !errors.As(err, &noProfile) {
			t.Errorf("%s error = %v, want *tlsprofile.NoProfileError", name, err)
		}
	}
	// iOS Safari 18.7 binds under HYPOTHESIS(ios_18_7_hello_equals_18_5), marked on its profile.
	safari187 := mustBrowser(t, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1")
	if safari187.TLS.Name != "safari_ios_18_5" || safari187.TLS.Verified ||
		!strings.HasPrefix(safari187.TLS.Hypothesis, "HYPOTHESIS(ios_18_7_hello_equals_18_5)") {
		t.Errorf("iOS Safari 18.7.5 TLS = %q verified %t hypothesis %q", safari187.TLS.Name, safari187.TLS.Verified, safari187.TLS.Hypothesis)
	}
	// Chrome for iOS on an iOS release whose TLS is verified but whose Safari
	// Accept-Encoding is unwitnessed stays refused.
	if _, err := NewBrowser("Mozilla/5.0 (iPhone; CPU iPhone OS 26_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1"); err == nil ||
		!strings.Contains(err.Error(), "Safari 26.4's Accept-Encoding is not witnessed") {
		t.Errorf("CriOS on iOS 26.4 error = %v", err)
	}
	for name, ua := range map[string]string{
		"CriOS on iPad":   "Mozilla/5.0 (iPad; CPU OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
		"linux chrome":    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
		"windows edge":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
		"windows firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
	} {
		var unmodeled *UnmodeledBrowserError
		if _, err := NewBrowser(ua); !errors.As(err, &unmodeled) || unmodeled.UserAgent != ua {
			t.Errorf("%s error = %v, want *UnmodeledBrowserError", name, err)
		}
	}
	if err := (Browser{}).Complete(); err == nil {
		t.Error("an unbound browser is complete")
	}
}

// TestSafariAcceptEncodingByRelease: the captures' boundaries, and the
// releases between them that no capture states.
func TestSafariAcceptEncodingByRelease(t *testing.T) {
	for _, c := range []struct {
		major, minor int
		want         string
	}{
		{18, 0, "gzip, deflate, br"}, {18, 7, "gzip, deflate, br"}, {26, 0, "gzip, deflate, br"},
		{26, 2, "gzip, deflate, br"}, {26, 5, "gzip, deflate, br, zstd"}, {26, 6, "gzip, deflate, br, zstd"},
		{27, 0, "gzip, deflate, br, zstd"}, {27, 2, "gzip, deflate, br, zstd"},
		{17, 6, ""}, {26, 3, ""}, {26, 4, ""}, {27, 1, ""}, {27, 3, ""},
	} {
		got, err := SafariAcceptEncoding(c.major, c.minor)
		if got != c.want || (err == nil) != (c.want != "") {
			t.Errorf("Safari %d.%d = %q, %v; want %q", c.major, c.minor, got, err, c.want)
		}
	}
}

func TestAddClientHintsWritesOnlyLowEntropyHints(t *testing.T) {
	browser := mustBrowser(t, windowsChrome)
	headers := fhttp.Header{}
	browser.AddClientHints(headers)
	if len(headers) != 0 {
		t.Fatalf("a browser without hints added %v", headers)
	}
	browser.ClientHints = &ClientHints{
		Brands:          []BrandVersion{{Brand: "Chromium", Version: "151"}, {Brand: "Not=A?Brand", Version: "99"}},
		FullVersionList: []BrandVersion{{Brand: "Chromium", Version: "151.0.7922.71"}, {Brand: "Not=A?Brand", Version: "99.0.0.0"}},
		Platform:        "Windows", PlatformVersion: "19.0.0", Architecture: "x86", Bitness: "64",
		UAFullVersion: "151.0.7922.71",
	}
	browser.AddClientHints(headers)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	slices.Sort(names)
	if want := []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}; !slices.Equal(names, want) {
		t.Fatalf("client hint headers = %q, want %q", names, want)
	}
	if browser.Complete() != nil {
		t.Fatalf("hinted desktop Chrome incomplete: %v", browser.Complete())
	}
}

func TestLanguagesDropsWeights(t *testing.T) {
	browser := Browser{AcceptLanguage: "ja-JP,ja;q=0.9, en-US;q=0.8,en;q=0.7"}
	if got, want := browser.Languages(), []string{"ja-JP", "ja", "en-US", "en"}; !slices.Equal(got, want) {
		t.Fatalf("Languages() = %q, want %q", got, want)
	}
}
