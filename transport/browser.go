package transport

import (
	"errors"
	"fmt"
	"strings"

	"github.com/EvadeNow/evade-sdk/tlsprofile"
	"github.com/EvadeNow/evade-sdk/useragent"
	fhttp "github.com/bogdanfinn/fhttp"
)

// ChromeAcceptEncoding is Chromium's Accept-Encoding on every request class
// from 123, which added zstd (the Windows/macOS Chrome 151-155 and Android
// Chrome 156 captures).
const ChromeAcceptEncoding = "gzip, deflate, br, zstd"

// legacyAcceptEncoding is the Accept-Encoding of every modeled stack before
// it added zstd.
const legacyAcceptEncoding = "gzip, deflate, br"

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
	// AcceptEncoding is the browser build's Accept-Encoding (acceptEncoding).
	AcceptEncoding string
	// ClientHints is the fingerprint's navigator.userAgentData; nil on
	// engines without UA-CH (Safari, Firefox). Chromium needs it (Complete).
	ClientHints *ClientHints
}

// NewBrowser parses ua and binds the TLS profile (tlsprofile.Resolver.Resolve)
// and Accept-Encoding of its network stack: every Chromium family on every
// OS, Safari on iPhone, iPad and Mac, and Firefox. Chrome, Edge and Firefox
// for iOS bind as the Safari of their iOS release (useragent.Parse), keeping
// their own User-Agent. Anything else fails with *useragent.UnsupportedError
// or *tlsprofile.NoProfileError. Chromium further needs its fingerprint's
// ClientHints before use (Complete).
func NewBrowser(ua string) (Browser, error) {
	agent, err := useragent.Parse(strings.TrimSpace(ua))
	if err != nil {
		return Browser{}, err
	}
	resolver, err := tlsprofile.New()
	if err != nil {
		return Browser{}, fmt.Errorf("transport: build TLS profile registry: %w", err)
	}
	profile, err := resolver.Resolve(agent)
	if err != nil {
		return Browser{}, err
	}
	return Browser{Agent: agent, TLS: profile, AcceptLanguage: defaultAcceptLanguage, AcceptEncoding: acceptEncoding(agent)}, nil
}

// acceptEncoding is the Accept-Encoding of a resolved agent's network stack:
// zstd joins gzip, deflate and br from Safari 26.4 (WebKit, so every iOS
// browser from iOS 26.4), Chromium 123 and Firefox 126. Safari's bound lies
// between the iPhone Safari 26.2 capture (none, shape/hars) and the macOS
// Safari 26.4 echo (zstd, tlsprofile/testdata); HYPOTHESIS(safari_26_3_no_zstd):
// 26.3 sends none, falsified by one 26.3 capture carrying zstd
// (tlsprofile/README.md).
func acceptEncoding(a useragent.Agent) string {
	var zstd bool
	switch {
	case a.Family.Blink():
		zstd = a.ChromiumMajor >= 123
	case a.Family == useragent.FamilyFirefox:
		zstd = a.Major >= 126
	default: // Safari: tlsprofile refused every other family
		zstd = a.Major > 26 || a.Major == 26 && a.Minor >= 4
	}
	if zstd {
		return ChromeAcceptEncoding
	}
	return legacyAcceptEncoding
}

// UserAgent is the User-Agent the browser sends.
func (b Browser) UserAgent() string { return b.Agent.Raw }

// DesktopChrome reports the desktop Chrome model.
func (b Browser) DesktopChrome() bool {
	return b.Agent.Family == useragent.FamilyChrome &&
		(b.Agent.OS == useragent.OSWindows || b.Agent.OS == useragent.OSMacOS)
}

// Complete fails closed on a browser no request may leave with: no
// User-Agent or Accept-Language, or Chromium without client hints (every
// Chromium family sends sec-ch-ua* on every request; only its fingerprint
// states them).
func (b Browser) Complete() error {
	if b.UserAgent() == "" || b.AcceptLanguage == "" {
		return errors.New("transport: no browser is bound: it has no User-Agent or Accept-Language")
	}
	if b.Agent.Family.Blink() && b.ClientHints == nil {
		return fmt.Errorf("transport: Chromium %q has no client hints: take them from its fingerprint", b.UserAgent())
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
