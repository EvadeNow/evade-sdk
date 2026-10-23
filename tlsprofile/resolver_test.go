package tlsprofile

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/EvadeNow/evade-sdk/useragent"
	"github.com/bogdanfinn/tls-client/profiles"
)

var (
	blinkBehavior   = Behavior{RandomizeExtensionOrder: true, DisableHTTP3: true, ConnectUserAgent: true}
	safariBehavior  = Behavior{RandomizeExtensionOrder: false, DisableHTTP3: true, ConnectUserAgent: true}
	firefoxBehavior = Behavior{RandomizeExtensionOrder: true, DisableHTTP3: true, ConnectUserAgent: true}
)

func newResolver(t *testing.T) *Resolver {
	t.Helper()
	r, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func assertRegistryProfile(t *testing.T, p Profile) {
	t.Helper()
	client, ok := profiles.MappedTLSClients[p.Name]
	if !ok {
		t.Fatalf("profile %q is not a registry key", p.Name)
	}
	if strings.Contains(p.Name, "_PSK") {
		t.Fatalf("profile %q is a PSK variant", p.Name)
	}
	// ClientProfile holds a func, which DeepEqual never equates.
	same := p.Client.GetClientHelloStr() == client.GetClientHelloStr() &&
		reflect.DeepEqual(p.Client.GetSettings(), client.GetSettings()) &&
		reflect.DeepEqual(p.Client.GetSettingsOrder(), client.GetSettingsOrder()) &&
		reflect.DeepEqual(p.Client.GetPseudoHeaderOrder(), client.GetPseudoHeaderOrder()) &&
		p.Client.GetConnectionFlow() == client.GetConnectionFlow()
	if !same {
		t.Fatalf("profile %q carries a client that is not the registry's", p.Name)
	}
}

func TestResolve(t *testing.T) {
	r := newResolver(t)
	tests := []struct {
		name     string
		ua       string
		want     string
		behavior Behavior
	}{
		{
			name: "chrome 154 takes the newest key below it",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
			want: "chrome_152", behavior: blinkBehavior,
		},
		{
			name: "chrome 120 exact",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			want: "chrome_120", behavior: blinkBehavior,
		},
		{
			name: "chrome 149 skips the 146-150 gap downward",
			ua:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
			want: "chrome_146", behavior: blinkBehavior,
		},
		{
			name: "chrome 131 takes chrome_131 not chrome_131_PSK",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			want: "chrome_131", behavior: blinkBehavior,
		},
		{
			name: "chrome 130 has only a PSK key and falls to chrome_124",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			want: "chrome_124", behavior: blinkBehavior,
		},
		{
			name: "android chrome uses chrome keys",
			ua:   "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36",
			want: "chrome_150", behavior: blinkBehavior,
		},
		{
			name: "android webview 151 takes chrome_150",
			ua:   "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7103.60 Mobile Safari/537.36",
			want: "chrome_150", behavior: blinkBehavior,
		},
		{
			name: "edge resolves by Chromium major",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.3065.69",
			want: "chrome_133", behavior: blinkBehavior,
		},
		{
			name: "opera resolves by Chromium major 130, not OPR/115 or opera_*",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
			want: "chrome_124", behavior: blinkBehavior,
		},
		{
			name: "ios 18.7 takes safari_ios_18_5",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1",
			want: "safari_ios_18_5", behavior: safariBehavior,
		},
		{
			name: "ios 18.4 is below 18_5 and takes safari_ios_18_0",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
			want: "safari_ios_18_0", behavior: safariBehavior,
		},
		{
			name: "ios 26.0 exact",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
			want: "safari_ios_26_0", behavior: safariBehavior,
		},
		{
			name: "ios OS-version fallback 16.3 takes safari_ios_16_0",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1",
			want: "safari_ios_16_0", behavior: safariBehavior,
		},
		{
			name: "ipad uses safari_ios keys, not safari_ipad",
			ua:   "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			want: "safari_ios_17_0", behavior: safariBehavior,
		},
		{
			name: "safari macos 17.4 takes safari_16_0",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
			want: "safari_16_0", behavior: safariBehavior,
		},
		{
			name: "safari macos 15.6 takes safari_15_6_1, patch ignored",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
			want: "safari_15_6_1", behavior: safariBehavior,
		},
		{
			name: "firefox 133 exact",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
			want: "firefox_133", behavior: firefoxBehavior,
		},
		{
			name: "firefox 146 has only a PSK key and falls to firefox_135",
			ua:   "Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0",
			want: "firefox_135", behavior: firefoxBehavior,
		},
		{
			name: "firefox 150 takes firefox_148",
			ua:   "Mozilla/5.0 (Android 14; Mobile; rv:150.0) Gecko/150.0 Firefox/150.0",
			want: "firefox_148", behavior: firefoxBehavior,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := useragent.Parse(tt.ua)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			p, err := r.Resolve(a)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if p.Name != tt.want {
				t.Fatalf("Resolve = %q, want %q", p.Name, tt.want)
			}
			if p.Behavior != tt.behavior {
				t.Fatalf("Behavior = %+v, want %+v", p.Behavior, tt.behavior)
			}
			assertRegistryProfile(t, p)
		})
	}
}

func TestResolveNoProfile(t *testing.T) {
	r := newResolver(t)
	tests := []struct {
		name         string
		ua           string
		family       useragent.Family
		major, minor int
	}{
		{
			name:   "ios 15.4 is below the oldest key safari_ios_15_5",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1",
			family: useragent.FamilySafariIOS, major: 15, minor: 4,
		},
		{
			name:   "chrome 102 is below chrome_103",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
			family: useragent.FamilyChrome, major: 102,
		},
		{
			name:   "edge reports the Chromium major it compared",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36 Edg/101.0.1210.53",
			family: useragent.FamilyEdge, major: 101,
		},
		{
			name:   "safari macos 15.5 is below safari_15_6_1",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
			family: useragent.FamilySafariMacOS, major: 15, minor: 5,
		},
		{
			name:   "firefox 101 is below firefox_102",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
			family: useragent.FamilyFirefox, major: 101,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := useragent.Parse(tt.ua)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			p, err := r.Resolve(a)
			var noProfile *NoProfileError
			if !errors.As(err, &noProfile) {
				t.Fatalf("Resolve = %q, %v; want *NoProfileError", p.Name, err)
			}
			want := NoProfileError{Family: tt.family, Major: tt.major, Minor: tt.minor}
			if *noProfile != want {
				t.Fatalf("NoProfileError = %+v, want %+v", *noProfile, want)
			}
		})
	}
}

func TestResolveUnknownFamily(t *testing.T) {
	r := newResolver(t)
	_, err := r.Resolve(useragent.Agent{Family: "netscape", Major: 200, ChromiumMajor: 200})
	var noProfile *NoProfileError
	if !errors.As(err, &noProfile) || noProfile.Family != "netscape" {
		t.Fatalf("Resolve(unknown family) error = %v, want *NoProfileError for netscape", err)
	}
}

func TestResolveVersion(t *testing.T) {
	r := newResolver(t)
	tests := []struct {
		family       useragent.Family
		major, minor int
		want         string
	}{
		{useragent.FamilySafariIOS, 26, 2, "safari_ios_26_0"},
		{useragent.FamilySafariIOS, 18, 5, "safari_ios_18_5"},
		{useragent.FamilySafariIOS, 15, 5, "safari_ios_15_5"},
		{useragent.FamilySafariIOS, 15, 9, "safari_ios_15_6"},
		{useragent.FamilyAndroidWebView, 150, 0, "chrome_150"},
		{useragent.FamilyOpera, 117, 0, "chrome_117"},
		{useragent.FamilySafariMacOS, 16, 0, "safari_16_0"},
		{useragent.FamilyFirefox, 147, 0, "firefox_147"},
	}
	for _, tt := range tests {
		p, err := r.ResolveVersion(tt.family, tt.major, tt.minor)
		if err != nil {
			t.Fatalf("ResolveVersion(%s, %d, %d): %v", tt.family, tt.major, tt.minor, err)
		}
		if p.Name != tt.want {
			t.Fatalf("ResolveVersion(%s, %d, %d) = %q, want %q", tt.family, tt.major, tt.minor, p.Name, tt.want)
		}
		assertRegistryProfile(t, p)
	}
}

func TestSafariHeaderPriorityMatchesVersion(t *testing.T) {
	r := newResolver(t)
	p26, err := r.ResolveVersion(useragent.FamilySafariIOS, 26, 2)
	if err != nil {
		t.Fatal(err)
	}
	if priority := p26.Client.GetHeaderPriority(); priority == nil || !priority.IsZero() {
		t.Fatalf("Safari 26 header priority = %+v, want explicit zero", priority)
	}

	p18, err := r.ResolveVersion(useragent.FamilySafariIOS, 18, 7)
	if err != nil {
		t.Fatal(err)
	}
	priority := p18.Client.GetHeaderPriority()
	if priority == nil || priority.IsZero() || priority.Exclusive || priority.StreamDep != 0 || priority.Weight != 255 {
		t.Fatalf("Safari 18 header priority = %+v, want stream 0, non-exclusive, wire weight 255", priority)
	}
}

func TestResolveVersionNeverPSK(t *testing.T) {
	r := newResolver(t)
	families := []useragent.Family{
		useragent.FamilyChrome, useragent.FamilyFirefox,
		useragent.FamilySafariIOS, useragent.FamilySafariMacOS,
	}
	resolved := 0
	for _, f := range families {
		for major := 0; major <= 200; major++ {
			for minor := 0; minor <= 9; minor++ {
				p, err := r.ResolveVersion(f, major, minor)
				var noProfile *NoProfileError
				if errors.As(err, &noProfile) {
					continue
				}
				if err != nil {
					t.Fatalf("ResolveVersion(%s, %d, %d): %v", f, major, minor, err)
				}
				assertRegistryProfile(t, p)
				resolved++
			}
		}
	}
	if resolved == 0 {
		t.Fatal("sweep resolved no version at all")
	}
}

func TestNamed(t *testing.T) {
	r := newResolver(t)
	tests := []struct {
		key      string
		behavior Behavior
	}{
		{"okhttp4_android_13", Behavior{}},
		{"confirmed_ios", Behavior{}},
		{"mms_ios_2", Behavior{}},
		{"mesh_android", Behavior{}},
		{"zalando_android_mobile", Behavior{}},
		{"nike_ios_mobile", Behavior{}},
		{"cloudscraper", Behavior{}},
		{"chrome_152", blinkBehavior},
		{"brave_146", blinkBehavior},
		{"opera_91", blinkBehavior},
		{"safari_ios_26_0", safariBehavior},
		{"safari_ipad_15_6", safariBehavior},
		{"safari_15_6_1", safariBehavior},
		{"firefox_148", firefoxBehavior},
	}
	for _, tt := range tests {
		p, err := r.Named(tt.key)
		if err != nil {
			t.Fatalf("Named(%q): %v", tt.key, err)
		}
		if p.Name != tt.key {
			t.Fatalf("Named(%q).Name = %q", tt.key, p.Name)
		}
		if p.Behavior != tt.behavior {
			t.Fatalf("Named(%q).Behavior = %+v, want %+v", tt.key, p.Behavior, tt.behavior)
		}
		assertRegistryProfile(t, p)
	}
}

func TestNamedRejects(t *testing.T) {
	r := newResolver(t)
	for _, key := range []string{
		"chrome_152_PSK", "chrome_116_PSK_PQ", "firefox_146_PSK", "brave_146_PSK",
		"chrome_999", "CHROME_152", "chrome_152 ", "",
	} {
		_, err := r.Named(key)
		var noProfile *NoProfileError
		if !errors.As(err, &noProfile) || *noProfile != (NoProfileError{Key: key}) {
			t.Fatalf("Named(%q) error = %v, want *NoProfileError{Key: %q}", key, err, key)
		}
	}
}

func TestNamedCoversRegistry(t *testing.T) {
	r := newResolver(t)
	for key := range profiles.MappedTLSClients {
		_, err := r.Named(key)
		psk := strings.HasSuffix(key, "_PSK") || strings.HasSuffix(key, "_PSK_PQ")
		if psk && err == nil {
			t.Fatalf("Named(%q) succeeded for a PSK key", key)
		}
		if !psk && err != nil {
			t.Fatalf("Named(%q): %v", key, err)
		}
	}
}
