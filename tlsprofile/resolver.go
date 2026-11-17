// Package tlsprofile selects tls-client built-in profiles for browser identities. A release resolves only to a
// profile real devices of that browser were captured sending; any other release fails with *NoProfileError rather
// than taking an older or unrelated profile.
package tlsprofile

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/EvadeNow/evade-sdk/useragent"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
)

// Behavior is connection behavior that belongs to a browser family rather than to one ClientHello.
type Behavior struct {
	RandomizeExtensionOrder bool
	DisableHTTP3            bool
	ConnectUserAgent        bool // send the browser User-Agent on proxy CONNECT
}

type Profile struct {
	Name     string // tls-client registry key, e.g. "chrome_154"
	Client   profiles.ClientProfile
	Behavior Behavior
	// Verified: Resolve took the profile from a verified span (a real-device capture at both ends equals it).
	Verified bool
	// Hypothesis is set instead when Resolve took it from a hypothesis span: the HYPOTHESIS marker, its claim and
	// the capture that would falsify it. Named sets neither.
	Hypothesis string
}

// NoProfileError reports a release no built-in profile is verified for (Key empty), or a Named key that is not a
// non-PSK built-in profile.
type NoProfileError struct {
	Family       useragent.Family
	OS           useragent.OS
	Major, Minor int
	// Nearest is the verified span of Family closest to Major.Minor, on OS when Family has one there (the release
	// to re-capture against, see README.md); empty when Family has no verified span at all.
	Nearest string
	Key     string // set when a named profile was requested
}

func (e *NoProfileError) Error() string {
	if e.Key != "" {
		return fmt.Sprintf("tlsprofile: no non-PSK built-in profile named %q", e.Key)
	}
	nearest := "none for " + string(e.Family)
	if e.Nearest != "" {
		nearest = e.Nearest
	}
	return fmt.Sprintf("tlsprofile: no built-in profile is verified against a real %s %d.%d on %s; nearest verified span: %s",
		e.Family, e.Major, e.Minor, e.OS, nearest)
}

// RegistryKeyError reports a built-in registry key of unknown form, or a verified profile the registry no longer
// has; New refuses to build a partial index.
type RegistryKeyError struct {
	Key    string
	Reason string
}

func (e *RegistryKeyError) Error() string {
	return fmt.Sprintf("tlsprofile: built-in profile key %q: %s", e.Key, e.Reason)
}

// Anchored, so _PSK/_PSK_PQ keys never parse as versioned browser keys.
var (
	pskKeyRe         = regexp.MustCompile(`^[a-z]+_\d+_PSK(?:_PQ)?$`)
	chromeKeyRe      = regexp.MustCompile(`^chrome_\d+$`)
	firefoxKeyRe     = regexp.MustCompile(`^firefox_\d+$`)
	safariIOSKeyRe   = regexp.MustCompile(`^safari_ios_(\d+)_\d+$`)
	safariMacOSKeyRe = regexp.MustCompile(`^safari_(\d+)_\d+(?:_\d+)?$`)
	blinkNamedKeyRe  = regexp.MustCompile(`^(?:brave|opera)_\d+$`)
	safariNamedKeyRe = regexp.MustCompile(`^safari_ipad_\d+_\d+$`)
	nativeKeyRe      = regexp.MustCompile(`^(?:okhttp4_android_\d+|(?:zalando|nike)_(?:ios|android)_mobile|mms_ios(?:_\d+)?|mesh_(?:ios|android)(?:_\d+)?|confirmed_(?:ios|android)|cloudscraper)$`)
)

type stack int

const (
	stackBlink stack = iota
	stackSafari
	stackFirefox
	stackNative
)

func (s stack) behavior() Behavior {
	switch s {
	case stackBlink:
		return Behavior{RandomizeExtensionOrder: true, DisableHTTP3: true, ConnectUserAgent: true}
	case stackSafari:
		// Safari sends a fixed extension order.
		return Behavior{RandomizeExtensionOrder: false, DisableHTTP3: true, ConnectUserAgent: true}
	case stackFirefox:
		// Firefox 148 and 160 sent the same extension order (testdata/firefox-windows-*.json): NSS does not permute it.
		return Behavior{RandomizeExtensionOrder: false, DisableHTTP3: true, ConnectUserAgent: true}
	}
	return Behavior{}
}

// release is a browser version at the resolver's granularity: the Chromium major for Blink, major.minor otherwise.
type release struct{ major, minor int }

func (a release) atMost(b release) bool {
	return a.major < b.major || a.major == b.major && a.minor <= b.minor
}

// distance orders releases for Nearest: majors dominate, minors break ties.
func (a release) distance(b release) int {
	d := (a.major-b.major)*1000 + a.minor - b.minor
	if d < 0 {
		return -d
	}
	return d
}

func (v verified) String() string {
	families := make([]string, len(v.families))
	for i, f := range v.families {
		families[i] = string(f)
	}
	oses := make([]string, len(v.oses))
	for i, os := range v.oses {
		oses[i] = string(os)
	}
	return fmt.Sprintf("%s for %s on %s %d.%d-%d.%d", v.key, strings.Join(families, "/"), strings.Join(oses, "/"),
		v.from.major, v.from.minor, v.through.major, v.through.minor)
}

// verified is a built-in profile and the releases of families on oses that real devices were captured sending its
// ClientHello and HTTP/2 preface (testdata, TestResolveMatchesRealDevice). Both bounds are captured releases; a
// release between them is taken to send what both bounds send (HYPOTHESIS(tls_release_span), falsified by a
// capture inside a span that differs from its profile). A span with a hypothesis has no capture: Resolve marks its
// profile with it instead of Verified.
type verified struct {
	key           string
	families      []useragent.Family
	oses          []useragent.OS
	from, through release
	hypothesis    string
}

// verifiedProfiles is every release the resolver answers for (README.md lists each span's fixtures and devices).
// Absent, each refused by a capture or never captured: Chrome 151 (sends no trust_anchors extension, chrome_150
// does), Chrome 152 (32 trust anchors where chrome_152 carries 28, on macOS and Android), Chrome on Android at 154+
// and on Linux/ChromeOS (never captured), Edge 157 (no trust_anchors, Chrome 157 has them), Opera and Android
// WebView (never captured), Firefox 148 and 160 (cipher suites and HEADERS stream differ from firefox_148), iOS
// Safari 18.0.1 and 18.3 (no built-in matches), and a Macintosh Safari
// User-Agent below 26, which an iPad in desktop mode also sends with iOS HTTP/2 settings
// (safari-ipad-desktop-16.0) while a Mac sends macOS ones.
func verifiedProfiles() []verified {
	return []verified{
		{
			key:      "chrome_154",
			families: []useragent.Family{useragent.FamilyChrome},
			oses:     []useragent.OS{useragent.OSWindows, useragent.OSMacOS},
			from:     release{154, 0}, through: release{157, 0},
		},
		{
			// From 26 one Safari release ships on iPhone, iPad and Mac with one network stack: macOS 26.4, iPhone
			// 26.6 and 27.2, an iPad's desktop-mode 26.6.1 and Chrome for iOS on 26.6 all send this profile.
			key:      "safari_ios_26_0",
			families: []useragent.Family{useragent.FamilySafariIOS, useragent.FamilySafariMacOS},
			oses:     []useragent.OS{useragent.OSIOS, useragent.OSMacOS},
			from:     release{26, 4}, through: release{27, 2},
		},
		{
			key:      "safari_ios_18_5",
			families: []useragent.Family{useragent.FamilySafariIOS},
			oses:     []useragent.OS{useragent.OSIOS},
			from:     release{18, 4}, through: release{18, 6},
		},
		{
			// No BrowserStack device runs 18.7; 18.4, 18.5 and 18.6 all send safari_ios_18_5.
			key:      "safari_ios_18_5",
			families: []useragent.Family{useragent.FamilySafariIOS},
			oses:     []useragent.OS{useragent.OSIOS},
			from:     release{18, 7}, through: release{18, 7},
			hypothesis: "HYPOTHESIS(ios_18_7_hello_equals_18_5): iOS Safari 18.7 sends 18.6's ClientHello and HTTP/2 " +
				"settings (safari_ios_18_5); falsified by one real iOS 18.7 tls.peet.ws echo differing from it on any " +
				"field TestResolveMatchesRealDevice compares",
		},
	}
}

type verifiedProfile struct {
	verified
	profile Profile
}

// Resolver is an immutable index of the tls-client built-in registry, safe for concurrent use.
type Resolver struct {
	named    map[string]Profile
	verified []verifiedProfile
}

// New indexes profiles.MappedTLSClients, failing with *RegistryKeyError on a key of unknown form or a verified
// profile the registry lacks.
func New() (*Resolver, error) {
	r := &Resolver{named: make(map[string]Profile, len(profiles.MappedTLSClients))}
	for key, client := range profiles.MappedTLSClients {
		var (
			s           stack
			safariMajor []string
		)
		switch {
		case pskKeyRe.MatchString(key):
			continue
		case chromeKeyRe.MatchString(key), blinkNamedKeyRe.MatchString(key):
			s = stackBlink
		case firefoxKeyRe.MatchString(key):
			s = stackFirefox
		case safariIOSKeyRe.MatchString(key):
			s, safariMajor = stackSafari, safariIOSKeyRe.FindStringSubmatch(key)
		case safariMacOSKeyRe.MatchString(key):
			s, safariMajor = stackSafari, safariMacOSKeyRe.FindStringSubmatch(key)
		case safariNamedKeyRe.MatchString(key):
			s = stackSafari
		case nativeKeyRe.MatchString(key):
			s = stackNative
		default:
			return nil, &RegistryKeyError{Key: key, Reason: "matches no known key form"}
		}
		p := Profile{Name: key, Client: client, Behavior: s.behavior()}
		if safariMajor != nil && majorAtLeast(safariMajor[1], 26) {
			// Safari 26 and 27 send no HTTP/2 HEADERS priority (testdata/safari-*). A zero priority param
			// suppresses fhttp's non-browser fallback without serializing a priority block.
			p.Client = withHeaderPriority(client, &http2.PriorityParam{})
		}
		r.named[key] = p
	}
	for _, v := range verifiedProfiles() {
		p, ok := r.named[v.key]
		if !ok {
			return nil, &RegistryKeyError{Key: v.key, Reason: "verified against real devices but not a non-PSK built-in profile"}
		}
		r.verified = append(r.verified, verifiedProfile{verified: v, profile: p})
	}
	return r, nil
}

// majorAtLeast reports whether the decimal in s is at least bound.
func majorAtLeast(s string, bound int) bool {
	major, err := strconv.Atoi(s)
	return err == nil && major >= bound
}

// withHeaderPriority rebuilds a profile with explicit HTTP/2 HEADERS priority parameters.
func withHeaderPriority(c profiles.ClientProfile, priority *http2.PriorityParam) profiles.ClientProfile {
	return profiles.NewClientProfile(c.GetClientHelloId(), c.GetSettings(), c.GetSettingsOrder(),
		c.GetPseudoHeaderOrder(), c.GetConnectionFlow(), c.GetPriorities(), priority,
		c.GetStreamID(), c.GetAllowHTTP(), c.GetHttp3Settings(), c.GetHttp3SettingsOrder(),
		c.GetHttp3PriorityParam(), c.GetHttp3PseudoHeaderOrder(), c.GetHttp3SendGreaseFrames())
}

// Resolve returns the profile real devices of a's family and OS were captured sending at a's release (the Chromium
// major for Blink families, major.minor otherwise; patch ignored), Verified, or the profile of a hypothesis span
// with its Hypothesis set.
func (r *Resolver) Resolve(a useragent.Agent) (Profile, error) {
	at := release{a.Major, a.Minor}
	if a.Family.Blink() {
		at = release{a.ChromiumMajor, 0}
	}
	for _, v := range r.verified {
		if slices.Contains(v.families, a.Family) && slices.Contains(v.oses, a.OS) && v.from.atMost(at) && at.atMost(v.through) {
			p := v.profile
			p.Verified, p.Hypothesis = v.hypothesis == "", v.hypothesis
			return p, nil
		}
	}
	return Profile{}, &NoProfileError{Family: a.Family, OS: a.OS, Major: at.major, Minor: at.minor, Nearest: r.nearest(a, at)}
}

// nearest names the verified span of a's family closest to at, preferring one on a's OS.
func (r *Resolver) nearest(a useragent.Agent, at release) string {
	var best *verifiedProfile
	bestOnOS, bestDistance := false, 0
	for i := range r.verified {
		v := &r.verified[i]
		if v.hypothesis != "" || !slices.Contains(v.families, a.Family) {
			continue
		}
		onOS := slices.Contains(v.oses, a.OS)
		d := min(at.distance(v.from), at.distance(v.through))
		if best == nil || onOS && !bestOnOS || onOS == bestOnOS && d < bestDistance {
			best, bestOnOS, bestDistance = v, onOS, d
		}
	}
	if best == nil {
		return ""
	}
	return best.verified.String()
}

// Named returns the built-in profile with exactly this registry key; PSK and unknown keys fail with *NoProfileError.
func (r *Resolver) Named(key string) (Profile, error) {
	p, ok := r.named[key]
	if !ok {
		return Profile{}, &NoProfileError{Key: key}
	}
	return p, nil
}
