package wireorder

import (
	"fmt"
	"strings"
)

// ReferrerPolicy is the policy the engine reads from a document's
// Referrer-Policy header value (its lines comma-joined), "" for none (the
// default): the last token that names a policy ASCII case-insensitively.
// WebKit (parseReferrerPolicy, Source/WebCore/platform/ReferrerPolicy.cpp)
// trims space, tab, LF and CR and skips every other token, as the W3C
// Referrer Policy does (§8.1). Chromium (Blink
// SecurityPolicy::ReferrerPolicyFromHeaderValue) skips an unrecognised token
// only when it is ASCII letters and '-' (the empty token included); any
// other invalidates the whole header, which leaves the default. Its strip is
// ASCII whitespace (LF, VT, FF, CR too) through 160.0.8167.1 and space and
// tab from 160.0.8168.0; a Chrome 160 user agent does not say which build
// and no source after 160 is read, so from 160 on a token edged by LF, VT,
// FF or CR is refused. Read at Chromium 151.0.7922.226, every major's last
// tag to 159, 160.0.8155.0-160.0.8180.1 and main, and WebKit
// WebKit-7620.1.16.111.5 and main (2026-11-24).
func (e Engine) ReferrerPolicy(header string) (string, error) {
	if e.Kind != Chromium && e.Kind != WebKit {
		return "", fmt.Errorf("Referrer-Policy %q: %s has no header-reading law", header, e)
	}
	effective := ""
	for token := range strings.SplitSeq(header, ",") {
		switch {
		case e.Kind == WebKit:
			token = strings.Trim(token, " \t\n\r")
		case e.Major < 160:
			token = strings.Trim(token, " \t\n\v\f\r")
		default:
			token = strings.Trim(token, " \t")
			if strings.Trim(token, "\n\v\f\r") != token {
				return "", fmt.Errorf("Referrer-Policy %q: token %q is edged by whitespace Chromium %d may strip or reject (stripped through 160.0.8167.1, the header invalid from 160.0.8168.0)", header, token, e.Major)
			}
		}
		letters := true
		for i := range len(token) {
			if c := token[i] | 0x20; (c < 'a' || c > 'z') && token[i] != '-' {
				letters = false
				break
			}
		}
		if !letters {
			if e.Kind == Chromium {
				return "", nil
			}
			continue
		}
		switch lower := strings.ToLower(token); lower {
		case "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url":
			effective = lower
		}
	}
	return effective, nil
}
