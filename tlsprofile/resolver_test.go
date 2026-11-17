package tlsprofile

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/EvadeNow/evade-sdk/useragent"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

var (
	blinkBehavior   = Behavior{RandomizeExtensionOrder: true, DisableHTTP3: true, ConnectUserAgent: true}
	safariBehavior  = Behavior{RandomizeExtensionOrder: false, DisableHTTP3: true, ConnectUserAgent: true}
	firefoxBehavior = Behavior{RandomizeExtensionOrder: false, DisableHTTP3: true, ConnectUserAgent: true}
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

// TestResolve covers verified releases the device fixtures do not state: the Records' releases inside a verified
// span, an iPad User-Agent, and the patch level the resolver ignores.
func TestResolve(t *testing.T) {
	r := newResolver(t)
	tests := []struct {
		name     string
		ua       string
		want     string
		behavior Behavior
	}{
		{
			name: "windows chrome 156 inside 154-157",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
			want: "chrome_154", behavior: blinkBehavior,
		},
		{
			name: "macos safari 26.6.2, patch ignored",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15",
			want: "safari_ios_26_0", behavior: safariBehavior,
		},
		{
			name: "macos safari 27.0 inside 26.4-27.2",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15",
			want: "safari_ios_26_0", behavior: safariBehavior,
		},
		{
			name: "ios safari 26.5 inside 26.4-27.2",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1",
			want: "safari_ios_26_0", behavior: safariBehavior,
		},
		{
			name: "ipad user agent on iOS 18.5",
			ua:   "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
			want: "safari_ios_18_5", behavior: safariBehavior,
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
	const (
		chromeSpan   = "chrome_154 for chrome on windows/macos 154.0-157.0"
		safari26Span = "safari_ios_26_0 for safari-ios/safari-macos on ios/macos 26.4-27.2"
		safari18Span = "safari_ios_18_5 for safari-ios on ios 18.4-18.6"
	)
	tests := []struct {
		name         string
		ua           string
		family       useragent.Family
		os           useragent.OS
		major, minor int
		nearest      string
	}{
		{
			name:   "chrome 151 below the verified span",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
			family: useragent.FamilyChrome, os: useragent.OSWindows, major: 151, nearest: chromeSpan,
		},
		{
			name:   "chrome 153 between refused 152 and verified 154",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
			family: useragent.FamilyChrome, os: useragent.OSWindows, major: 153, nearest: chromeSpan,
		},
		{
			name:   "chrome 158 above the newest capture",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
			family: useragent.FamilyChrome, os: useragent.OSMacOS, major: 158, nearest: chromeSpan,
		},
		{
			name:   "linux chrome 157 was never captured",
			ua:     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
			family: useragent.FamilyChrome, os: useragent.OSLinux, major: 157, nearest: chromeSpan,
		},
		{
			name:   "android chrome 156 was never captured",
			ua:     "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
			family: useragent.FamilyChrome, os: useragent.OSAndroid, major: 156, nearest: chromeSpan,
		},
		{
			name:   "opera reports the Chromium major it compared",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 OPR/120.0.0.0",
			family: useragent.FamilyOpera, os: useragent.OSWindows, major: 155,
		},
		{
			name:   "android webview 156",
			ua:     "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.7103.60 Mobile Safari/537.36",
			family: useragent.FamilyAndroidWebView, os: useragent.OSAndroid, major: 156,
		},
		{
			name:   "ios 18.8 above the 18.7 hypothesis",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.8 Mobile/15E148 Safari/604.1",
			family: useragent.FamilySafariIOS, os: useragent.OSIOS, major: 18, minor: 8, nearest: safari18Span,
		},
		{
			name:   "ios 26.2 below the 26.4 capture",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1",
			family: useragent.FamilySafariIOS, os: useragent.OSIOS, major: 26, minor: 2, nearest: safari26Span,
		},
		{
			name:   "macintosh safari 18.4 is a Mac or a desktop-mode iPad",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
			family: useragent.FamilySafariMacOS, os: useragent.OSMacOS, major: 18, minor: 4, nearest: safari26Span,
		},
		{
			name:   "firefox on android",
			ua:     "Mozilla/5.0 (Android 14; Mobile; rv:150.0) Gecko/150.0 Firefox/150.0",
			family: useragent.FamilyFirefox, os: useragent.OSAndroid, major: 150,
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
			want := NoProfileError{Family: tt.family, OS: tt.os, Major: tt.major, Minor: tt.minor, Nearest: tt.nearest}
			if *noProfile != want {
				t.Fatalf("NoProfileError = %+v, want %+v", *noProfile, want)
			}
		})
	}
}

func TestResolveUnknownFamily(t *testing.T) {
	r := newResolver(t)
	_, err := r.Resolve(useragent.Agent{Family: "netscape", OS: useragent.OSWindows, Major: 200, ChromiumMajor: 200})
	var noProfile *NoProfileError
	if !errors.As(err, &noProfile) || noProfile.Family != "netscape" {
		t.Fatalf("Resolve(unknown family) error = %v, want *NoProfileError for netscape", err)
	}
}

// TestVerifiedBoundsAreCaptured: both bounds of every verified span are a device fixture's release, so a span
// widens only with a capture (TestResolveMatchesRealDevice checks each fixture's wire).
func TestVerifiedBoundsAreCaptured(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	type captured struct {
		family useragent.Family
		os     useragent.OS
		at     release
	}
	var captures []captured
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var echo struct {
			UserAgent string `json:"user_agent"`
		}
		if err := json.Unmarshal(data, &echo); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		a, err := useragent.Parse(echo.UserAgent)
		if err != nil {
			continue // Chrome for iOS: transport.NewBrowser reads it as its iOS release's Safari
		}
		at := release{a.Major, a.Minor}
		if a.Family.Blink() {
			at = release{a.ChromiumMajor, 0}
		}
		captures = append(captures, captured{a.Family, a.OS, at})
	}
	for _, v := range verifiedProfiles() {
		if v.hypothesis != "" {
			continue // a hypothesis span is one no capture states
		}
		for _, bound := range []release{v.from, v.through} {
			if !slices.ContainsFunc(captures, func(c captured) bool {
				return c.at == bound && slices.Contains(v.families, c.family) && slices.Contains(v.oses, c.os)
			}) {
				t.Errorf("%s bound %d.%d has no device fixture", v.key, bound.major, bound.minor)
			}
		}
	}
}

// TestResolveMarksTheIOS187Hypothesis: 18.4-18.6 are captured, 18.7 is HYPOTHESIS(ios_18_7_hello_equals_18_5).
func TestResolveMarksTheIOS187Hypothesis(t *testing.T) {
	r := newResolver(t)
	for _, c := range []struct {
		minor      int
		hypothesis bool
	}{{4, false}, {5, false}, {6, false}, {7, true}} {
		p, err := r.Resolve(useragent.Agent{Family: useragent.FamilySafariIOS, OS: useragent.OSIOS, Major: 18, Minor: c.minor})
		if err != nil {
			t.Fatalf("18.%d: %v", c.minor, err)
		}
		marked := strings.HasPrefix(p.Hypothesis, "HYPOTHESIS(ios_18_7_hello_equals_18_5)")
		if p.Name != "safari_ios_18_5" || marked != c.hypothesis || p.Verified == c.hypothesis {
			t.Fatalf("18.%d = %q verified %t hypothesis %q", c.minor, p.Name, p.Verified, p.Hypothesis)
		}
	}
}

func TestSafariHeaderPriority(t *testing.T) {
	r := newResolver(t)
	for _, key := range []string{"safari_ios_26_0", "safari_27_2"} {
		p, err := r.Named(key)
		if err != nil {
			t.Fatal(err)
		}
		if priority := p.Client.GetHeaderPriority(); priority == nil || !priority.IsZero() {
			t.Fatalf("%s header priority = %+v, want explicit zero", key, priority)
		}
	}
}

func TestSafari26ClientHelloMatchesNative26_6Extensions(t *testing.T) {
	r := newResolver(t)
	profile, err := r.Resolve(useragent.Agent{Family: useragent.FamilySafariIOS, OS: useragent.OSIOS, Major: 26, Minor: 6})
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	if err := serverConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	handshakeErr := make(chan error, 1)
	go func() {
		conn := tls.UClient(clientConn, &tls.Config{ServerName: "example.com"},
			profile.Client.GetClientHelloId(), false, false, false)
		handshakeErr <- conn.Handshake()
	}()

	got, err := formatClientHelloExtensions(readTLSRecord(t, serverConn))
	if err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshakeErr; err == nil {
		t.Fatal("ClientHello-only handshake unexpectedly completed")
	}

	fixture, err := os.ReadFile("testdata/safari_ios_26_6_extensions.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(fixture))
	if got != want {
		t.Fatalf("serialized Safari 26 ClientHello extensions:\n%s\nwant native Safari 26.6 fixture:\n%s", got, want)
	}
}

func readTLSRecord(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read TLS record header: %v", err)
	}
	if header[0] != 22 {
		t.Fatalf("TLS record type = %d, want handshake", header[0])
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read TLS record payload: %v", err)
	}
	return payload
}

func formatClientHelloExtensions(record []byte) (string, error) {
	if len(record) < 4 || record[0] != 1 {
		return "", fmt.Errorf("tlsprofile: first handshake message is not a ClientHello")
	}
	helloLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if helloLen > len(record)-4 {
		return "", fmt.Errorf("tlsprofile: ClientHello spans TLS records")
	}
	hello := record[4 : 4+helloLen]
	offset := 2 + 32 // legacy_version and random
	skipVector := func(width int) error {
		if len(hello)-offset < width {
			return io.ErrUnexpectedEOF
		}
		size := int(hello[offset])
		if width == 2 {
			size = int(binary.BigEndian.Uint16(hello[offset:]))
		}
		offset += width
		if len(hello)-offset < size {
			return io.ErrUnexpectedEOF
		}
		offset += size
		return nil
	}
	if len(hello) < offset {
		return "", io.ErrUnexpectedEOF
	}
	if err := skipVector(1); err != nil { // legacy_session_id
		return "", err
	}
	if err := skipVector(2); err != nil { // cipher_suites
		return "", err
	}
	if err := skipVector(1); err != nil { // legacy_compression_methods
		return "", err
	}
	if len(hello)-offset < 2 {
		return "", io.ErrUnexpectedEOF
	}
	end := offset + 2 + int(binary.BigEndian.Uint16(hello[offset:]))
	offset += 2
	if end > len(hello) {
		return "", io.ErrUnexpectedEOF
	}

	var extensionTypes []string
	for offset < end {
		if end-offset < 4 {
			return "", io.ErrUnexpectedEOF
		}
		extensionType := binary.BigEndian.Uint16(hello[offset:])
		extensionLen := int(binary.BigEndian.Uint16(hello[offset+2:]))
		offset += 4
		if end-offset < extensionLen {
			return "", io.ErrUnexpectedEOF
		}
		offset += extensionLen
		high, low := byte(extensionType>>8), byte(extensionType)
		if high == low && low&0x0f == 0x0a {
			extensionTypes = append(extensionTypes, "GREASE")
		} else {
			extensionTypes = append(extensionTypes, fmt.Sprintf("%04x", extensionType))
		}
	}
	return strings.Join(extensionTypes, "\n"), nil
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
