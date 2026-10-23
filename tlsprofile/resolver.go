// Package tlsprofile selects tls-client built-in profiles for browser identities,
// failing with *NoProfileError rather than falling back to an unrelated profile.
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
	Name     string // tls-client registry key, e.g. "chrome_150"
	Client   profiles.ClientProfile
	Behavior Behavior
}

type NoProfileError struct {
	Family       useragent.Family
	Major, Minor int
	Key          string // set when a named profile was requested
}

func (e *NoProfileError) Error() string {
	if e.Key != "" {
		return fmt.Sprintf("tlsprofile: no non-PSK built-in profile named %q", e.Key)
	}
	return fmt.Sprintf("tlsprofile: no compatible non-PSK built-in profile for %s %d.%d", e.Family, e.Major, e.Minor)
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
	safariMacOSKeyRe = regexp.MustCompile(`^safari_(\d+)_(\d+)(?:_(\d+))?$`)
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
		// Extension-order randomization is unverified against a Firefox capture.
		return Behavior{RandomizeExtensionOrder: true, DisableHTTP3: true, ConnectUserAgent: true}
	}
	return Behavior{}
}

type versioned struct {
	major, minor, patch int
	profile             Profile
}

// Resolver is an immutable index of the tls-client built-in registry, safe for concurrent use.
type Resolver struct {
	named                                   map[string]Profile
	chrome, firefox, safariIOS, safariMacOS []versioned // newest first
}

// New indexes profiles.MappedTLSClients, failing with *RegistryKeyError on a key of unknown form.
func New() (*Resolver, error) {
	r := &Resolver{named: make(map[string]Profile, len(profiles.MappedTLSClients))}
	for key, client := range profiles.MappedTLSClients {
		var (
			s     stack
			index *[]versioned
			m     []string
		)
		switch {
		case pskKeyRe.MatchString(key):
			continue
		case chromeKeyRe.MatchString(key):
			s, index, m = stackBlink, &r.chrome, chromeKeyRe.FindStringSubmatch(key)
		case firefoxKeyRe.MatchString(key):
			s, index, m = stackFirefox, &r.firefox, firefoxKeyRe.FindStringSubmatch(key)
		case safariIOSKeyRe.MatchString(key):
			s, index, m = stackSafari, &r.safariIOS, safariIOSKeyRe.FindStringSubmatch(key)
		case safariMacOSKeyRe.MatchString(key):
			s, index, m = stackSafari, &r.safariMacOS, safariMacOSKeyRe.FindStringSubmatch(key)
		case blinkNamedKeyRe.MatchString(key):
			s = stackBlink
		case safariNamedKeyRe.MatchString(key):
			s = stackSafari
		case nativeKeyRe.MatchString(key):
			s = stackNative
		default:
			return nil, &RegistryKeyError{Key: key, Reason: "matches no known key form"}
		}
		p := Profile{Name: key, Client: client, Behavior: s.behavior()}
		// HYPOTHESIS(safari26_no_stream_priority): iOS Safari 26 and later
		// send no HTTP/2 stream priority (curl-impersonate curl_safari260_ios:
		// "HTTP/2: removed priority", --http2-no-priority; Safari 18 keeps a
		// weight-256, non-exclusive priority). The tls-client profile states
		// none, so fhttp falls back to its exclusive weight-255 default; a
		// zero priority param makes the HEADERS frame skip the block
		// (fhttp http2 frame.go IsZero). Falsified by a real Safari 26
		// frame capture showing a priority block.
		if s == stackSafari && index == &r.safariIOS && len(m) > 1 && majorAtLeast(m[1], 26) {
			p.Client = noHeaderPriority(client)
		}
		r.named[key] = p
		if index == nil {
			continue
		}
		v, err := keyVersion(key, m[1:])
		if err != nil {
			return nil, err
		}
		v.profile = p
		*index = append(*index, v)
	}
	newestFirst := func(a, b versioned) int {
		return cmp.Or(cmp.Compare(b.major, a.major), cmp.Compare(b.minor, a.minor), cmp.Compare(b.patch, a.patch))
	}
	for _, index := range []*[]versioned{&r.chrome, &r.firefox, &r.safariIOS, &r.safariMacOS} {
		slices.SortFunc(*index, newestFirst)
	}
	return r, nil
}

// majorAtLeast reports whether the decimal in s is at least bound.
func majorAtLeast(s string, bound int) bool {
	major, err := strconv.Atoi(s)
	return err == nil && major >= bound
}

// noHeaderPriority rebuilds the profile with a zero header priority, which
// makes fhttp's HEADERS frame skip the priority block (frame.go IsZero).
func noHeaderPriority(c profiles.ClientProfile) profiles.ClientProfile {
	return profiles.NewClientProfile(c.GetClientHelloId(), c.GetSettings(), c.GetSettingsOrder(),
		c.GetPseudoHeaderOrder(), c.GetConnectionFlow(), c.GetPriorities(), &http2.PriorityParam{},
		c.GetStreamID(), c.GetAllowHTTP(), c.GetHttp3Settings(), c.GetHttp3SettingsOrder(),
		c.GetHttp3PriorityParam(), c.GetHttp3PseudoHeaderOrder(), c.GetHttp3SendGreaseFrames())
}

func keyVersion(key string, parts []string) (versioned, error) {
	var nums [3]int
	for i, part := range parts {
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return versioned{}, &RegistryKeyError{Key: key, Reason: err.Error()}
		}
		nums[i] = n
	}
	return versioned{major: nums[0], minor: nums[1], patch: nums[2]}, nil
}

// Resolve selects the profile for a parsed User-Agent; Blink families resolve by ChromiumMajor.
func (r *Resolver) Resolve(a useragent.Agent) (Profile, error) {
	if a.Family.Blink() {
		return r.ResolveVersion(a.Family, a.ChromiumMajor, 0)
	}
	return r.ResolveVersion(a.Family, a.Major, a.Minor)
}

// ResolveVersion returns the newest profile of f not above major.minor (Chromium major for Blink; patch ignored).
func (r *Resolver) ResolveVersion(f useragent.Family, major, minor int) (Profile, error) {
	var index []versioned
	switch {
	case f.Blink():
		index = r.chrome
	case f == useragent.FamilySafariIOS:
		index = r.safariIOS
	case f == useragent.FamilySafariMacOS:
		index = r.safariMacOS
	case f == useragent.FamilyFirefox:
		index = r.firefox
	}
	for _, v := range index {
		if v.major < major || (v.major == major && v.minor <= minor) {
			return v.profile, nil
		}
	}
	return Profile{}, &NoProfileError{Family: f, Major: major, Minor: minor}
}

// Named returns the built-in profile with exactly this registry key; PSK and unknown keys fail with *NoProfileError.
func (r *Resolver) Named(key string) (Profile, error) {
	p, ok := r.named[key]
	if !ok {
		return Profile{}, &NoProfileError{Key: key}
	}
	return p, nil
}
