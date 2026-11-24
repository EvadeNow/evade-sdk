package wireorder

import (
	"strings"
	"testing"
)

// Blink's ReferrerPolicyFromHeaderValue and WebKit's parseReferrerPolicy on
// the same header values.
func TestReferrerPolicyIsTheEnginesHeaderRule(t *testing.T) {
	chrome151 := Engine{Kind: Chromium, Major: 151}
	chrome160 := Engine{Kind: Chromium, Major: 160}
	safari := Engine{Kind: WebKit, Major: 18, Minor: 7}
	for _, c := range []struct {
		header         string
		chrome, webkit string
	}{
		{"", "", ""},
		{"no-referrer", "no-referrer", "no-referrer"},
		{"NO-REFERRER", "no-referrer", "no-referrer"},
		{"strict-origin, no-referrer", "no-referrer", "no-referrer"},
		{"no-referrer, bogus", "no-referrer", "no-referrer"},
		{"no-referrer,", "no-referrer", "no-referrer"},
		{"\tsame-origin ", "same-origin", "same-origin"},
		{"never, origin", "origin", "origin"},
		// a token that is not letters and '-' drops the whole header in
		// Blink and is skipped by WebKit
		{"x_1, same-origin", "", "same-origin"},
		{"no-referrer, foo_bar", "", "no-referrer"},
		{"\u017fame-origin", "", ""},
		{"no-referrer, \u017fame-origin", "", "no-referrer"},
		// VT: Chromium 151 strips it, WebKit keeps it in the token
		{"\vno-referrer", "no-referrer", ""},
	} {
		if got, err := chrome151.ReferrerPolicy(c.header); err != nil || got != c.chrome {
			t.Errorf("chromium 151 %q = %q, %v; want %q", c.header, got, err, c.chrome)
		}
		if got, err := safari.ReferrerPolicy(c.header); err != nil || got != c.webkit {
			t.Errorf("webkit %q = %q, %v; want %q", c.header, got, err, c.webkit)
		}
	}
	for _, header := range []string{"\vno-referrer", "origin, \nno-referrer", "same-origin\f"} {
		if _, err := chrome160.ReferrerPolicy(header); err == nil || !strings.Contains(err.Error(), "160.0.8168.0") {
			t.Errorf("chromium 160 %q: %v, want the build-split refusal", header, err)
		}
	}
	if _, err := (Engine{}).ReferrerPolicy("origin"); err == nil {
		t.Error("an unknown engine read a policy")
	}
}
