package transport

import (
	"errors"
	"slices"
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
		// One Safari 26 network stack on Mac and iPhone (tlsprofile/testdata/safari-macos-26.4.json).
		macSafari:     {useragent.FamilySafariMacOS, "safari_ios_26_0", "gzip, deflate, br, zstd", false, false},
		windowsChrome: {useragent.FamilyChrome, "chrome_154", ChromeAcceptEncoding, true, true},
		macChrome:     {useragent.FamilyChrome, "chrome_154", ChromeAcceptEncoding, true, true},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36": {
			useragent.FamilyChrome, "chrome_150", ChromeAcceptEncoding, true, true},
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36": {
			useragent.FamilyChrome, "chrome_154", ChromeAcceptEncoding, false, true},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0": {
			useragent.FamilyEdge, "chrome_154", ChromeAcceptEncoding, false, true},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0": {
			useragent.FamilyFirefox, "firefox_148", "gzip, deflate, br, zstd", false, false},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/150.0 Mobile/15E148 Safari/605.1.15": {
			useragent.FamilySafariIOS, "safari_ios_26_0", "gzip, deflate, br, zstd", false, false},
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
		// Chromium sends sec-ch-ua* on every request: without its
		// fingerprint's hints it is not complete.
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
	for name, ua := range map[string]string{
		"no browser token":  "curl/8.10.1",
		"CriOS off iOS":     "Mozilla/5.0 (Linux; Android 14) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile Safari/604.1",
		"empty User-Agent":  " ",
		"Safari off Apple":  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
		"headless Chromium": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/157.0.0.0 Safari/537.36",
	} {
		if _, err := NewBrowser(ua); !errors.As(err, &unsupported) {
			t.Errorf("%s error = %v, want *useragent.UnsupportedError", name, err)
		}
	}
	var noProfile *tlsprofile.NoProfileError
	if _, err := NewBrowser("Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3"); !errors.As(err, &noProfile) {
		t.Errorf("Safari 5.1 error = %v, want *tlsprofile.NoProfileError", err)
	}
	if err := (Browser{}).Complete(); err == nil {
		t.Error("an unbound browser is complete")
	}
}

// TestAcceptEncodingByRelease: zstd from Safari 26.4, Chromium 123 and Firefox 126.
func TestAcceptEncodingByRelease(t *testing.T) {
	const legacy, zstd = "gzip, deflate, br", "gzip, deflate, br, zstd"
	for _, c := range []struct {
		agent useragent.Agent
		want  string
	}{
		{useragent.Agent{Family: useragent.FamilySafariIOS, Major: 17, Minor: 6}, legacy},
		{useragent.Agent{Family: useragent.FamilySafariIOS, Major: 18, Minor: 7}, legacy},
		{useragent.Agent{Family: useragent.FamilySafariIOS, Major: 26, Minor: 2}, legacy},
		{useragent.Agent{Family: useragent.FamilySafariIOS, Major: 26, Minor: 3}, legacy},
		{useragent.Agent{Family: useragent.FamilySafariMacOS, Major: 26, Minor: 4}, zstd},
		{useragent.Agent{Family: useragent.FamilySafariIOS, Major: 27, Minor: 2}, zstd},
		{useragent.Agent{Family: useragent.FamilyChrome, ChromiumMajor: 122}, legacy},
		{useragent.Agent{Family: useragent.FamilyEdge, Major: 123, ChromiumMajor: 123}, zstd},
		{useragent.Agent{Family: useragent.FamilyFirefox, Major: 125}, legacy},
		{useragent.Agent{Family: useragent.FamilyFirefox, Major: 126}, zstd},
	} {
		if got := acceptEncoding(c.agent); got != c.want {
			t.Errorf("%s %d (Chromium %d) = %q, want %q", c.agent.Family, c.agent.Major, c.agent.ChromiumMajor, got, c.want)
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
