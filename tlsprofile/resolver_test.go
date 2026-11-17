package tlsprofile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
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

// TestResolve: every Chromium family on every OS takes chrome_<newest at most its Chromium major>, Safari (and
// every iOS browser) safari_ios_<newest at most its major>, Firefox firefox_<newest at most its major>.
func TestResolve(t *testing.T) {
	r := newResolver(t)
	tests := []struct {
		name     string
		ua       string
		want     string
		behavior Behavior
	}{
		{"windows chrome 157", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36", "chrome_154", blinkBehavior},
		{"macos chrome 154", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36", "chrome_154", blinkBehavior},
		{"linux chrome 160", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36", "chrome_154", blinkBehavior},
		{"chromeos chrome 156", "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36", "chrome_154", blinkBehavior},
		{"android chrome 156", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36", "chrome_154", blinkBehavior},
		{"windows edge 157", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0", "chrome_154", blinkBehavior},
		{"opera on chromium 155", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 OPR/120.0.0.0", "chrome_154", blinkBehavior},
		{"android webview 156", "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.7103.60 Mobile Safari/537.36", "chrome_154", blinkBehavior},
		{"samsung internet on chromium 154", "Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/154.0.0.0 Mobile Safari/537.36", "chrome_154", blinkBehavior},
		{"chrome 151 takes chrome_150", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", "chrome_150", blinkBehavior},
		{"chrome 153 takes chrome_152", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36", "chrome_152", blinkBehavior},
		{"macos safari 26.6.2", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15", "safari_ios_26_0", safariBehavior},
		{"ios safari 27.2", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1", "safari_ios_26_0", safariBehavior},
		{"ios safari 26.2", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1", "safari_ios_26_0", safariBehavior},
		{"ipad safari 18.5", "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1", "safari_ios_18_5", safariBehavior},
		{"ios safari 18.0 takes 18.x's profile", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", "safari_ios_18_5", safariBehavior},
		{"ios safari 18.7.5", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1", "safari_ios_18_5", safariBehavior},
		{"ios safari 17.6", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1", "safari_ios_17_0", safariBehavior},
		{"macintosh safari 16.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15", "safari_ios_16_0", safariBehavior},
		{"chrome for iOS 26.6.1", "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1", "safari_ios_26_0", safariBehavior},
		{"firefox for iOS 18.3", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/150.0 Mobile/15E148 Safari/605.1.15", "safari_ios_18_5", safariBehavior},
		{"edge for iPad 17.5", "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/126.0.2592.80 Mobile/15E148 Safari/605.1.15", "safari_ios_17_0", safariBehavior},
		{"windows firefox 160", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0", "firefox_148", firefoxBehavior},
		{"android firefox 150", "Mozilla/5.0 (Android 14; Mobile; rv:150.0) Gecko/150.0 Firefox/150.0", "firefox_148", firefoxBehavior},
		{"linux firefox 140", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "firefox_135", firefoxBehavior},
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

// TestResolveNoProfile: a family on no modeled stack, or a release older than every profile of its stack.
func TestResolveNoProfile(t *testing.T) {
	r := newResolver(t)
	for _, a := range []useragent.Agent{
		{Family: "netscape", OS: useragent.OSWindows, Major: 200},
		{Family: useragent.FamilyChrome, OS: useragent.OSWindows, Major: 90, ChromiumMajor: 90},
		{Family: useragent.FamilyEdge, OS: useragent.OSWindows, Major: 101, ChromiumMajor: 101},
		{Family: useragent.FamilySafariIOS, OS: useragent.OSIOS, Major: 5, Minor: 1},
		{Family: useragent.FamilyFirefox, OS: useragent.OSLinux, Major: 100},
	} {
		_, err := r.Resolve(a)
		major := a.Major
		if a.Family.Blink() {
			major = a.ChromiumMajor
		}
		var noProfile *NoProfileError
		if !errors.As(err, &noProfile) || *noProfile != (NoProfileError{Family: a.Family, OS: a.OS, Major: major}) {
			t.Errorf("Resolve(%+v) error = %v, want *NoProfileError naming %s %d", a, err, a.Family, major)
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
