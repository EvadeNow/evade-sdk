package transport

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

// Captured from Chrome 154 on Windows.
func chrome154Hints() ClientHints {
	return ClientHints{
		Brands: []BrandVersion{{"Chromium", "154"}, {"Google Chrome", "154"}, {"Not A(Brand", "99"}},
		FullVersionList: []BrandVersion{
			{"Chromium", "154.0.8037.58"}, {"Google Chrome", "154.0.8037.58"}, {"Not A(Brand", "99.0.0.0"},
		},
		Platform:        "Windows",
		PlatformVersion: "10.0.0",
		Architecture:    "x86",
		Bitness:         "64",
		UAFullVersion:   "154.0.8037.58",
	}
}

func TestValuesMatchCapturedChrome(t *testing.T) {
	want := Headers{
		{"sec-ch-ua", `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Windows"`},
		{"sec-ch-ua-platform-version", `"10.0.0"`},
		{"sec-ch-ua-arch", `"x86"`},
		{"sec-ch-ua-bitness", `"64"`},
		{"sec-ch-ua-model", `""`},
		{"sec-ch-ua-full-version-list", `"Chromium";v="154.0.8037.58", "Google Chrome";v="154.0.8037.58", "Not A(Brand";v="99.0.0.0"`},
		{"sec-ch-ua-wow64", "?0"},
	}
	hints := chrome154Hints()
	if err := hints.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := hints.Values(); !slices.Equal(got, want) {
		t.Fatalf("values =\n%q\nwant\n%q", got, want)
	}
}

func TestValuesQuoteEmbeddedCharacters(t *testing.T) {
	hints := ClientHints{
		Brands:   []BrandVersion{{"Chromium", "152"}, {"Not?A_Brand", "24"}, {"Google Chrome", "152"}},
		Mobile:   true,
		Platform: "Android",
	}
	want := Headers{
		{"sec-ch-ua", `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`},
		{"sec-ch-ua-mobile", "?1"},
		{"sec-ch-ua-platform", `"Android"`},
	}
	if got := hints.Values(); !slices.Equal(got, want) {
		t.Fatalf("low-entropy values = %q, want %q", got, want)
	}
}

func TestValuesWithoutBrandsIsEmpty(t *testing.T) {
	if got := (ClientHints{Platform: "iOS", Mobile: true}).Values(); got != nil {
		t.Fatalf("a family without UA-CH produced %q", got)
	}
}

func TestValidateNamesMissingField(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*ClientHints)
		field string
	}{
		{"empty brands", func(c *ClientHints) { c.Brands = nil }, "brands"},
		{"brand without version", func(c *ClientHints) { c.Brands[1].Version = "" }, "brands"},
		{"platform", func(c *ClientHints) { c.Platform = "" }, "platform"},
		{"partial high entropy", func(c *ClientHints) { c.FullVersionList = nil }, "fullVersionList"},
		{"platform version", func(c *ClientHints) { c.PlatformVersion = "" }, "platformVersion"},
		{"full version", func(c *ClientHints) { c.UAFullVersion = "" }, "uaFullVersion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hints := chrome154Hints()
			tc.edit(&hints)
			err := hints.Validate()
			var hintsErr *ClientHintsError
			if !errors.As(err, &hintsErr) || hintsErr.Field != tc.field {
				t.Fatalf("Validate = %v, want missing %s", err, tc.field)
			}
		})
	}
	lowOnly := ClientHints{Brands: chrome154Hints().Brands, Platform: "Android", Mobile: true}
	if err := lowOnly.Validate(); err != nil {
		t.Fatalf("low-entropy-only hints rejected: %v", err)
	}
}

func TestClientHintsDecodeCollectorJSON(t *testing.T) {
	raw := `{"architecture":"x86","bitness":"64","brands":[{"brand":"Chromium","version":"154"}],` +
		`"fullVersionList":[{"brand":"Chromium","version":"154.0.8037.58"}],"mobile":false,"model":"",` +
		`"platform":"Windows","platformVersion":"10.0.0","uaFullVersion":"154.0.8037.58","wow64":true}`
	var hints ClientHints
	if err := json.Unmarshal([]byte(raw), &hints); err != nil {
		t.Fatal(err)
	}
	if err := hints.Validate(); err != nil {
		t.Fatal(err)
	}
	values := hints.Values()
	if last := values[len(values)-1]; last != (Header{"sec-ch-ua-wow64", "?1"}) {
		t.Fatalf("wow64 header = %v", last)
	}
	if values[0].Value != `"Chromium";v="154"` {
		t.Fatalf("sec-ch-ua = %q", values[0].Value)
	}
}
