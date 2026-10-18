package transport

import (
	"fmt"
	"strconv"
	"strings"
)

type BrandVersion struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// ClientHints is a fingerprint's navigator.userAgentData under the browser's JSON keys; copy it from the UA's fingerprint, never synthesize it.
type ClientHints struct {
	Brands          []BrandVersion `json:"brands"`
	FullVersionList []BrandVersion `json:"fullVersionList"`
	Mobile          bool           `json:"mobile"`
	Platform        string         `json:"platform"`
	PlatformVersion string         `json:"platformVersion"`
	Architecture    string         `json:"architecture"`
	Bitness         string         `json:"bitness"`
	Model           string         `json:"model"`
	UAFullVersion   string         `json:"uaFullVersion"`
	Wow64           bool           `json:"wow64"`
}

type ClientHintsError struct {
	Field string
}

func (e *ClientHintsError) Error() string {
	return "transport: client hints missing " + e.Field
}

// Validate requires brands and platform, and high-entropy hints all or none (arch, bitness and model may be empty).
func (c ClientHints) Validate() error {
	if !validBrands(c.Brands) {
		return &ClientHintsError{Field: "brands"}
	}
	if c.Platform == "" {
		return &ClientHintsError{Field: "platform"}
	}
	if !c.highEntropy() && c.PlatformVersion == "" && c.UAFullVersion == "" &&
		c.Architecture == "" && c.Bitness == "" && c.Model == "" {
		return nil
	}
	if !validBrands(c.FullVersionList) {
		return &ClientHintsError{Field: "fullVersionList"}
	}
	if c.PlatformVersion == "" {
		return &ClientHintsError{Field: "platformVersion"}
	}
	if c.UAFullVersion == "" {
		return &ClientHintsError{Field: "uaFullVersion"}
	}
	return nil
}

// Values renders the sec-ch-ua* headers byte for byte as Chrome sends them; nil without brands.
func (c ClientHints) Values() Headers {
	if len(c.Brands) == 0 {
		return nil
	}
	headers := make(Headers, 0, 9)
	headers = append(headers,
		Header{Name: "sec-ch-ua", Value: brandList(c.Brands)},
		Header{Name: "sec-ch-ua-mobile", Value: structuredBool(c.Mobile)},
	)
	if c.Platform != "" {
		headers = append(headers, Header{Name: "sec-ch-ua-platform", Value: strconv.Quote(c.Platform)})
	}
	if !c.highEntropy() {
		return headers
	}
	return append(headers,
		Header{Name: "sec-ch-ua-platform-version", Value: strconv.Quote(c.PlatformVersion)},
		Header{Name: "sec-ch-ua-arch", Value: strconv.Quote(c.Architecture)},
		Header{Name: "sec-ch-ua-bitness", Value: strconv.Quote(c.Bitness)},
		Header{Name: "sec-ch-ua-model", Value: strconv.Quote(c.Model)},
		Header{Name: "sec-ch-ua-full-version-list", Value: brandList(c.FullVersionList)},
		Header{Name: "sec-ch-ua-wow64", Value: structuredBool(c.Wow64)},
	)
}

// The full version list is the one high-entropy value that is never empty.
func (c ClientHints) highEntropy() bool {
	return len(c.FullVersionList) != 0
}

func validBrands(brands []BrandVersion) bool {
	if len(brands) == 0 {
		return false
	}
	for _, brand := range brands {
		if brand.Brand == "" || brand.Version == "" {
			return false
		}
	}
	return true
}

func brandList(brands []BrandVersion) string {
	var list strings.Builder
	for i, brand := range brands {
		if i > 0 {
			list.WriteString(", ")
		}
		fmt.Fprintf(&list, "%q;v=%q", brand.Brand, brand.Version)
	}
	return list.String()
}

func structuredBool(value bool) string {
	if value {
		return "?1"
	}
	return "?0"
}
