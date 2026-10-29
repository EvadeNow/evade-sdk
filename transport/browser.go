package transport

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/EvadeNow/evade-sdk/tlsprofile"
	"github.com/EvadeNow/evade-sdk/useragent"
	fhttp "github.com/bogdanfinn/fhttp"
)

// ChromeAcceptEncoding is Chrome's Accept-Encoding on every request class
// (the Windows/macOS Chrome 151-155 and Android Chrome 156 captures).
const ChromeAcceptEncoding = "gzip, deflate, br, zstd"

// defaultAcceptLanguage is the Accept-Language a session starts with; the
// caller replaces it with the exit region's.
const defaultAcceptLanguage = "en-US,en;q=0.9"

// Browser is one session's browser identity: its User-Agent, the TLS profile
// that User-Agent selects, and the values it sends on every request. Keeping
// them together keeps a request builder from pairing one browser's
// User-Agent with another's TLS stack, encodings or languages.
type Browser struct {
	Agent          useragent.Agent
	TLS            tlsprofile.Profile
	AcceptLanguage string
	// AcceptEncoding is the browser build's Accept-Encoding
	// (SafariAcceptEncoding, ChromeAcceptEncoding).
	AcceptEncoding string
	// ClientHints is the fingerprint's navigator.userAgentData; nil on
	// engines without UA-CH (Safari). Chrome needs it (Complete).
	ClientHints *ClientHints
}

// UnmodeledBrowserError is a User-Agent of a browser NewBrowser has no
// witnessed model of.
type UnmodeledBrowserError struct {
	UserAgent string
	Reason    string
}

func (e *UnmodeledBrowserError) Error() string {
	return fmt.Sprintf("transport: browser %q is not modeled: %s", e.UserAgent, e.Reason)
}

// NewBrowser parses ua and binds the TLS profile tlsprofile selects for it.
// Modeled browsers are the captured ones: iOS Safari, macOS Safari, Chrome
// for iPhone, desktop Chrome on Windows/macOS, and mobile Chrome on Android.
// Chrome further needs its fingerprint's ClientHints before use (Complete).
//
// Chrome for iOS on an iPhone runs as the iOS Safari of its iOS release:
// every iOS browser fetches through the system WebKit, so its TLS profile
// and Accept-Encoding are that release's Safari's, while Agent.Raw stays its
// own User-Agent (HYPOTHESIS(ios_third_party_safari_tls), falsified by a
// captured Chrome for iOS ClientHello whose bytes differ from the same iOS
// release's Safari's). macOS Safari takes its Version/ release's Safari
// Accept-Encoding (HYPOTHESIS(webkit_macos_is_ios_late)).
func NewBrowser(ua string) (Browser, error) {
	raw := strings.TrimSpace(ua)
	agent, criOS, err := iPhoneCriOSAgent(raw)
	if err != nil {
		return Browser{}, err
	}
	if !criOS {
		if agent, err = useragent.Parse(raw); err != nil {
			return Browser{}, err
		}
	}
	desktopChrome := agent.Family == useragent.FamilyChrome &&
		(agent.OS == useragent.OSWindows || agent.OS == useragent.OSMacOS)
	androidChrome := agent.Family == useragent.FamilyChrome && agent.OS == useragent.OSAndroid && agent.Mobile
	safari := agent.Family == useragent.FamilySafariIOS || agent.Family == useragent.FamilySafariMacOS
	if !safari && !desktopChrome && !androidChrome {
		return Browser{}, &UnmodeledBrowserError{UserAgent: raw, Reason: fmt.Sprintf(
			"%s on %s: only iOS Safari, macOS Safari, Chrome for iPhone, desktop Chrome on Windows or macOS, and mobile Chrome on Android are modeled",
			agent.Family, agent.OS)}
	}
	resolver, err := tlsprofile.New()
	if err != nil {
		return Browser{}, fmt.Errorf("transport: build TLS profile registry: %w", err)
	}
	profile, err := resolver.Resolve(agent)
	if err != nil {
		return Browser{}, err
	}
	acceptEncoding := ChromeAcceptEncoding
	if safari {
		if acceptEncoding, err = SafariAcceptEncoding(agent.Major, agent.Minor); err != nil {
			return Browser{}, err
		}
	}
	return Browser{Agent: agent, TLS: profile, AcceptLanguage: defaultAcceptLanguage, AcceptEncoding: acceptEncoding}, nil
}

// iPhoneCriOS is Chrome for iOS on an iPhone, whose OS token carries the real
// iOS release (Safari freezes it; CriOS does not).
var iPhoneCriOS = regexp.MustCompile(
	`^Mozilla/5\.0 \(iPhone; CPU iPhone OS (\d+)_(\d+)(?:_\d+)? like Mac OS X\) AppleWebKit/[0-9.]+ \(KHTML, like Gecko\) CriOS/[0-9.]+ Mobile/[0-9A-Za-z]+ Safari/[0-9.]+$`)

// iPhoneCriOSAgent reads a Chrome for iOS User-Agent (ok) as the iOS Safari
// agent of its iOS release, keeping the raw User-Agent (NewBrowser).
// useragent.Parse refuses CriOS for every other SDK consumer.
func iPhoneCriOSAgent(raw string) (agent useragent.Agent, ok bool, err error) {
	if !strings.Contains(raw, " CriOS/") {
		return useragent.Agent{}, false, nil
	}
	match := iPhoneCriOS.FindStringSubmatch(raw)
	if match == nil {
		return useragent.Agent{}, true, &UnmodeledBrowserError{UserAgent: raw, Reason: "Chrome for iOS is modeled only on iPhone, with its iOS version"}
	}
	major, majorErr := strconv.Atoi(match[1])
	minor, minorErr := strconv.Atoi(match[2])
	if majorErr != nil || minorErr != nil {
		return useragent.Agent{}, true, &UnmodeledBrowserError{UserAgent: raw, Reason: "the iOS version does not parse"}
	}
	return useragent.Agent{Raw: raw, Family: useragent.FamilySafariIOS, OS: useragent.OSIOS, Major: major, Minor: minor, Mobile: true}, true, nil
}

// SafariAcceptEncoding is Safari's Accept-Encoding by its release major and
// minor: zstd from 26.5 (the 26.5, 26.6 and 26.6.1 captures) and on 27.0
// (the BrowserStack Safari 27.0 captures), none on 18.x, 26.0.1 and 26.2
// (the 18.7.5, 26.0.1 and 26.2 captures). 18.x minors other than 18.7 are
// taken as 18.7 (zstd arrived after 26.2); 26.3, 26.4, 27.1+ and pre-18
// releases are unwitnessed and refused.
func SafariAcceptEncoding(major, minor int) (string, error) {
	switch {
	case major == 18, major == 26 && minor <= 2:
		return "gzip, deflate, br", nil
	case major == 26 && minor >= 5, major == 27 && minor == 0:
		return "gzip, deflate, br, zstd", nil
	}
	return "", fmt.Errorf("transport: Safari %d.%d's Accept-Encoding is not witnessed", major, minor)
}

// UserAgent is the User-Agent the browser sends.
func (b Browser) UserAgent() string { return b.Agent.Raw }

// DesktopChrome reports the desktop Chrome model.
func (b Browser) DesktopChrome() bool {
	return b.Agent.Family == useragent.FamilyChrome &&
		(b.Agent.OS == useragent.OSWindows || b.Agent.OS == useragent.OSMacOS)
}

// Complete fails closed on a browser no request may leave with: no
// User-Agent or Accept-Language, or Chrome without client hints (Chrome sends
// sec-ch-ua* on every request; only its fingerprint states them).
func (b Browser) Complete() error {
	if b.UserAgent() == "" || b.AcceptLanguage == "" {
		return errors.New("transport: no browser is bound: it has no User-Agent or Accept-Language")
	}
	if b.Agent.Family == useragent.FamilyChrome && b.ClientHints == nil {
		return fmt.Errorf("transport: Chrome %q has no client hints: take them from its fingerprint", b.UserAgent())
	}
	return nil
}

// AddClientHints installs the browser's low-entropy UA-CH headers into
// headers, the only ones Chrome sends to a site that asks for no more by
// Accept-CH. A browser without UA-CH adds none.
func (b Browser) AddClientHints(headers fhttp.Header) {
	if b.ClientHints == nil {
		return
	}
	for _, header := range b.ClientHints.Values() {
		switch header.Name {
		case "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform":
			headers[header.Name] = []string{header.Value}
		}
	}
}

// Languages is Accept-Language's language tags in order, without weights.
func (b Browser) Languages() []string {
	parts := strings.Split(b.AcceptLanguage, ",")
	languages := make([]string, 0, len(parts))
	for _, part := range parts {
		language, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		if language != "" {
			languages = append(languages, language)
		}
	}
	return languages
}
