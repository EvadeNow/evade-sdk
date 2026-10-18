package useragent

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSupported(t *testing.T) {
	tests := []struct {
		name          string
		ua            string
		family        Family
		os            OS
		major, minor  int
		chromiumMajor int
		mobile        bool
	}{
		{
			name:   "chrome windows",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			family: FamilyChrome, os: OSWindows, major: 131, chromiumMajor: 131,
		},
		{
			name:   "chrome macos carries Safari and Macintosh but is Chrome",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			family: FamilyChrome, os: OSMacOS, major: 130, chromiumMajor: 130,
		},
		{
			name:   "chrome linux",
			ua:     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
			family: FamilyChrome, os: OSLinux, major: 129, chromiumMajor: 129,
		},
		{
			name:   "chrome chromeos declares X11 but is CrOS",
			ua:     "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			family: FamilyChrome, os: OSChromeOS, major: 131, chromiumMajor: 131,
		},
		{
			name:   "chrome pre-reduction full version",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
			family: FamilyChrome, os: OSWindows, major: 99, chromiumMajor: 99,
		},
		{
			name:   "chrome 154 beyond the registry still parses",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
			family: FamilyChrome, os: OSWindows, major: 154, chromiumMajor: 154,
		},
		{
			name:   "chrome android phone",
			ua:     "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
			family: FamilyChrome, os: OSAndroid, major: 131, chromiumMajor: 131, mobile: true,
		},
		{
			name:   "chrome android tablet has no Mobile word",
			ua:     "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			family: FamilyChrome, os: OSAndroid, major: 131, chromiumMajor: 131,
		},
		{
			name:   "android webview phone",
			ua:     "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7103.60 Mobile Safari/537.36",
			family: FamilyAndroidWebView, os: OSAndroid, major: 151, chromiumMajor: 151, mobile: true,
		},
		{
			name:   "edge windows takes Major from Edg/",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.2.2903.86",
			family: FamilyEdge, os: OSWindows, major: 131, minor: 2, chromiumMajor: 131,
		},
		{
			name:   "edge android",
			ua:     "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.0.0",
			family: FamilyEdge, os: OSAndroid, major: 131, chromiumMajor: 131, mobile: true,
		},
		{
			name:   "opera windows keeps OPR/ and Chrome/ majors apart",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
			family: FamilyOpera, os: OSWindows, major: 115, chromiumMajor: 130,
		},
		{
			name:   "safari macos",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
			family: FamilySafariMacOS, os: OSMacOS, major: 17, minor: 4,
		},
		{
			name:   "safari ios 17",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
			family: FamilySafariIOS, os: OSIOS, major: 17, minor: 4, mobile: true,
		},
		{
			name:   "safari ios 18",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1",
			family: FamilySafariIOS, os: OSIOS, major: 18, minor: 7, mobile: true,
		},
		{
			name:   "safari ios 26 Version/ wins over the frozen OS 18_6",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
			family: FamilySafariIOS, os: OSIOS, major: 26, minor: 0, mobile: true,
		},
		{
			name:   "safari ios without Version/ falls back to the OS version",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1",
			family: FamilySafariIOS, os: OSIOS, major: 16, minor: 3, mobile: true,
		},
		{
			name:   "safari ipad is ios but not mobile despite Mobile/ build token",
			ua:     "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			family: FamilySafariIOS, os: OSIOS, major: 17, minor: 5,
		},
		{
			name:   "safari ipod",
			ua:     "Mozilla/5.0 (iPod touch; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7 Mobile/15E148 Safari/604.1",
			family: FamilySafariIOS, os: OSIOS, major: 15, minor: 7, mobile: true,
		},
		{
			name:   "firefox windows",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
			family: FamilyFirefox, os: OSWindows, major: 133,
		},
		{
			name:   "firefox macos",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
			family: FamilyFirefox, os: OSMacOS, major: 132,
		},
		{
			name:   "firefox linux",
			ua:     "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			family: FamilyFirefox, os: OSLinux, major: 128,
		},
		{
			name:   "firefox android phone",
			ua:     "Mozilla/5.0 (Android 14; Mobile; rv:133.0) Gecko/133.0 Firefox/133.0",
			family: FamilyFirefox, os: OSAndroid, major: 133, mobile: true,
		},
		{
			name:   "firefox android tablet",
			ua:     "Mozilla/5.0 (Android 14; Tablet; rv:133.0) Gecko/133.0 Firefox/133.0",
			family: FamilyFirefox, os: OSAndroid, major: 133,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.ua)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			want := Agent{
				Raw: tt.ua, Family: tt.family, OS: tt.os,
				Major: tt.major, Minor: tt.minor, ChromiumMajor: tt.chromiumMajor, Mobile: tt.mobile,
			}
			if got != want {
				t.Fatalf("Parse:\n got  %+v\n want %+v", got, want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name      string
		ua        string
		reasonHas string
	}{
		{
			name:      "chrome for ios",
			ua:        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.153 Mobile/15E148 Safari/604.1",
			reasonHas: "CriOS",
		},
		{
			name:      "firefox for ios carries Version/ and Safari/",
			ua:        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15",
			reasonHas: "FxiOS",
		},
		{
			name:      "edge for ios carries Version/ and Safari/",
			ua:        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/126.2592.86 Mobile/15E148 Safari/605.1.15",
			reasonHas: "EdgiOS",
		},
		{name: "empty", ua: ""},
		{name: "whitespace", ua: "   "},
		{name: "garbage", ua: "not a user agent"},
		{name: "curl", ua: "curl/8.4.0"},
		{
			name: "headless chrome is not a Chrome/ token",
			ua:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.6099.109 Safari/537.36",
		},
		{
			name: "safari ios without Version/ or OS version",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1",
		},
		{
			name: "safari macos without Version/ has no OS fallback",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1.15",
		},
		{
			name: "safari ios with malformed Version/ does not fall back",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/beta Mobile/15E148 Safari/604.1",
		},
		{
			name: "truncated android webview has no Chrome/",
			ua:   "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0",
		},
		{
			name: "android wv marker without Version/4.0",
			ua:   "Mozilla/5.0 (Linux; Android 13; Pixel 7; wv) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36",
		},
		{
			name: "android stock browser",
			ua:   "Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
		},
		{
			name: "chrome major overflows int",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99999999999999999999.0.0.0 Safari/537.36",
		},
		{
			name: "chrome version without minor",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131 Safari/537.36",
		},
		{
			name: "edge with non-numeric Edg/",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/abc",
		},
		{
			name: "chrome without a recognized OS",
			ua:   "Mozilla/5.0 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.ua)
			var unsupported *UnsupportedError
			if !errors.As(err, &unsupported) {
				t.Fatalf("Parse = %+v, %v; want *UnsupportedError", got, err)
			}
			if got != (Agent{}) {
				t.Fatalf("Parse returned a partial Agent %+v alongside the error", got)
			}
			if unsupported.UserAgent != tt.ua {
				t.Fatalf("UnsupportedError.UserAgent = %q, want %q", unsupported.UserAgent, tt.ua)
			}
			if !strings.Contains(unsupported.Reason, tt.reasonHas) {
				t.Fatalf("UnsupportedError.Reason = %q, want it to name %q", unsupported.Reason, tt.reasonHas)
			}
		})
	}
}
