// Package tlsprofile selects the tls-client built-in profile a browser identity presents. One rule per network
// stack (README.md): Chromium, Safari and Firefox each take their newest built-in profile whose major is at most the
// release's; every other family fails with *NoProfileError.
package tlsprofile

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"

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
}

// NoProfileError reports an agent no rule gives a profile: a family on no modeled network stack, or a release older
// than every built-in profile of its stack (Key empty); or a Named key that is not a non-PSK built-in profile.
type NoProfileError struct {
	Family useragent.Family
	OS     useragent.OS
	Major  int    // the release major the rule compared: the Chromium major for Chromium families
	Key    string // set when a named profile was requested
}

func (e *NoProfileError) Error() string {
	if e.Key != "" {
		return fmt.Sprintf("tlsprofile: no non-PSK built-in profile named %q", e.Key)
	}
	if _, ok := stackOf(e.Family); !ok {
		return fmt.Sprintf("tlsprofile: %q on %s is no Chromium, Safari or Firefox family; no TLS rule covers it", e.Family, e.OS)
	}
	return fmt.Sprintf("tlsprofile: %s %d on %s is older than every built-in profile of its network stack", e.Family, e.Major, e.OS)
}

// RegistryKeyError reports a built-in registry key of unknown form; New refuses to build a partial index.
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
	chromeKeyRe      = regexp.MustCompile(`^chrome_(\d+)$`)
	firefoxKeyRe     = regexp.MustCompile(`^firefox_(\d+)$`)
	safariIOSKeyRe   = regexp.MustCompile(`^safari_ios_(\d+)_(\d+)$`)
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

// stackOf is the network stack a family's browsers run: Chromium's BoringSSL for every Chromium shell, Apple's for
// Safari (and every iOS browser, which useragent.Parse reads as the Safari of its iOS release), NSS for Firefox.
func stackOf(f useragent.Family) (stack, bool) {
	switch {
	case f.Blink():
		return stackBlink, true
	case f == useragent.FamilySafariIOS, f == useragent.FamilySafariMacOS:
		return stackSafari, true
	case f == useragent.FamilyFirefox:
		return stackFirefox, true
	}
	return 0, false
}

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

// release is a resolvable built-in profile, a chrome_N, firefox_N or safari_ios_N_M key, and its version.
type release struct {
	major, minor int
	profile      Profile
}

// Resolver is an immutable index of the tls-client built-in registry, safe for concurrent use.
type Resolver struct {
	named    map[string]Profile
	releases map[stack][]release // per browser stack, oldest first
}

// New indexes profiles.MappedTLSClients, failing with *RegistryKeyError on a key of unknown form.
func New() (*Resolver, error) {
	r := &Resolver{named: make(map[string]Profile, len(profiles.MappedTLSClients)), releases: map[stack][]release{}}
	for key, client := range profiles.MappedTLSClients {
		var (
			s           stack
			version     []string // a resolvable key's major (and minor) digits
			safariMajor string
		)
		switch {
		case pskKeyRe.MatchString(key):
			continue
		case chromeKeyRe.MatchString(key):
			s, version = stackBlink, chromeKeyRe.FindStringSubmatch(key)[1:]
		case blinkNamedKeyRe.MatchString(key):
			s = stackBlink
		case firefoxKeyRe.MatchString(key):
			s, version = stackFirefox, firefoxKeyRe.FindStringSubmatch(key)[1:]
		case safariIOSKeyRe.MatchString(key):
			s, version = stackSafari, safariIOSKeyRe.FindStringSubmatch(key)[1:]
			safariMajor = version[0]
		case safariMacOSKeyRe.MatchString(key):
			s, safariMajor = stackSafari, safariMacOSKeyRe.FindStringSubmatch(key)[1]
		case safariNamedKeyRe.MatchString(key):
			s = stackSafari
		case nativeKeyRe.MatchString(key):
			s = stackNative
		default:
			return nil, &RegistryKeyError{Key: key, Reason: "matches no known key form"}
		}
		if majorAtLeast(safariMajor, 26) {
			// Safari 26 and 27 send no HTTP/2 HEADERS priority (testdata/safari-*). A zero priority param
			// suppresses fhttp's non-browser fallback without serializing a priority block.
			client = withHeaderPriority(client, &http2.PriorityParam{})
		}
		p := Profile{Name: key, Client: client, Behavior: s.behavior()}
		r.named[key] = p
		if version != nil {
			rel := release{profile: p}
			rel.major, _ = strconv.Atoi(version[0])
			if len(version) > 1 {
				rel.minor, _ = strconv.Atoi(version[1])
			}
			r.releases[s] = append(r.releases[s], rel)
		}
	}
	for _, releases := range r.releases {
		slices.SortFunc(releases, func(a, b release) int {
			return cmp.Or(cmp.Compare(a.major, b.major), cmp.Compare(a.minor, b.minor))
		})
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

// Resolve returns the newest built-in profile of a's network stack whose major is at most a's release major: the
// Chromium major against chrome_N for every Chromium family on every OS; Version/ (an iOS browser's iOS release)
// against safari_ios_N_M for Safari on iPhone, iPad and Mac; the Firefox major against firefox_N. Minor and patch
// are ignored, so Safari 18.x takes safari_ios_18_5 and Safari 26 and later safari_ios_26_0. Any other family, or
// a release older than every profile of its stack, fails with *NoProfileError.
func (r *Resolver) Resolve(a useragent.Agent) (Profile, error) {
	s, ok := stackOf(a.Family)
	if !ok {
		return Profile{}, &NoProfileError{Family: a.Family, OS: a.OS, Major: a.Major}
	}
	major := a.Major
	if s == stackBlink {
		major = a.ChromiumMajor
	}
	releases := r.releases[s]
	for i := len(releases) - 1; i >= 0; i-- {
		if releases[i].major <= major {
			return releases[i].profile, nil
		}
	}
	return Profile{}, &NoProfileError{Family: a.Family, OS: a.OS, Major: major}
}

// Named returns the built-in profile with exactly this registry key; PSK and unknown keys fail with *NoProfileError.
func (r *Resolver) Named(key string) (Profile, error) {
	p, ok := r.named[key]
	if !ok {
		return Profile{}, &NoProfileError{Key: key}
	}
	return p, nil
}
