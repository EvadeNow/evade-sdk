package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const (
	placeholderCountry = "{CC}"
	placeholderCity    = "{CITY}"
	placeholderSession = "{SESSION}"
)

// Template expands {CC} to the country, {CITY} to "_city_<city>" (or nothing) and {SESSION} to the sticky id.
type Template struct {
	template                        string
	vendor                          Vendor
	hasCountry, hasCity, hasSession bool
}

var _ Provider = (*Template)(nil)

type TemplateError struct {
	Vendor string
	Reason string
	Err    error
}

func (e *TemplateError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("proxy: %s template: %s: %v", e.Vendor, e.Reason, e.Err)
	}
	return fmt.Sprintf("proxy: %s template: %s", e.Vendor, e.Reason)
}

func (e *TemplateError) Unwrap() error { return e.Err }

type RequestError struct {
	Vendor string
	Field  string // "Country", "City" or "Session"
	Reason string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("proxy: %s request %s: %s", e.Vendor, e.Field, e.Reason)
}

// NewTemplate validates raw against v's rules after v.Canonicalize, parsing it with sample placeholder values.
func NewTemplate(raw string, v Vendor) (*Template, error) {
	if v.Name == "" {
		return nil, &TemplateError{Vendor: "unnamed", Reason: "vendor has no name"}
	}
	if v.RTC == RTCPolicyUnknown {
		return nil, &TemplateError{Vendor: v.Name, Reason: "vendor has no RTC policy"}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, &TemplateError{Vendor: v.Name, Reason: "template is empty"}
	}
	if v.Canonicalize != nil {
		canonical, err := v.Canonicalize(raw)
		if err != nil {
			if _, ok := errors.AsType[*TemplateError](err); ok {
				return nil, err
			}
			return nil, &TemplateError{Vendor: v.Name, Reason: "canonicalize", Err: err}
		}
		raw = canonical
	}
	t := &Template{
		template:   raw,
		vendor:     v,
		hasCountry: strings.Contains(raw, placeholderCountry),
		hasCity:    strings.Contains(raw, placeholderCity),
		hasSession: strings.Contains(raw, placeholderSession),
	}
	if v.Sticky && (!t.hasCountry || !t.hasSession) {
		return nil, &TemplateError{Vendor: v.Name, Reason: "template requires {CC} and {SESSION}"}
	}
	if t.hasSession {
		if v.SessionBytes <= 0 {
			return nil, &TemplateError{Vendor: v.Name, Reason: "vendor mints no session bytes for {SESSION}"}
		}
		if minted := 2 * v.SessionBytes; !withinBounds(minted, v.MinSession, v.MaxSession) {
			return nil, &TemplateError{Vendor: v.Name, Reason: fmt.Sprintf(
				"minted session length %d is outside the vendor bounds [%d, %d]", minted, v.MinSession, v.MaxSession)}
		}
	}
	sample := strings.NewReplacer(
		placeholderCountry, "US", placeholderCity, "", placeholderSession, "session1",
	).Replace(raw)
	parsed, err := url.Parse(sample)
	if err != nil {
		return nil, &TemplateError{Vendor: v.Name, Reason: "template is not a URL", Err: err}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" || parsed.Hostname() == "" {
		return nil, &TemplateError{Vendor: v.Name, Reason: "template must be an absolute proxy URL"}
	}
	if len(v.Schemes) != 0 && !slices.Contains(v.Schemes, scheme) {
		return nil, &TemplateError{Vendor: v.Name, Reason: fmt.Sprintf(
			"scheme %q is not one of %s", scheme, strings.Join(v.Schemes, ", "))}
	}
	if len(v.Hosts) != 0 && !hostAllowed(parsed.Hostname(), v.Hosts) {
		return nil, &TemplateError{Vendor: v.Name, Reason: fmt.Sprintf(
			"host %q is not under %s", parsed.Hostname(), strings.Join(v.Hosts, ", "))}
	}
	if v.Authenticated {
		if parsed.Port() == "" {
			return nil, &TemplateError{Vendor: v.Name, Reason: "template requires an explicit port"}
		}
		if parsed.User == nil || parsed.User.Username() == "" {
			return nil, &TemplateError{Vendor: v.Name, Reason: "template requires a username"}
		}
		if password, ok := parsed.User.Password(); !ok || password == "" {
			return nil, &TemplateError{Vendor: v.Name, Reason: "template requires a password"}
		}
	}
	return t, nil
}

// Acquire keeps a pinned session as a label only when the template has no {SESSION}.
func (t *Template) Acquire(ctx context.Context, r Request) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	v := t.vendor
	country := ""
	if t.hasCountry {
		country = strings.ToUpper(strings.TrimSpace(r.Country))
		if len(country) != 2 || !upperLetter(country[0]) || !upperLetter(country[1]) {
			return Lease{}, &RequestError{Vendor: v.Name, Field: "Country", Reason: fmt.Sprintf("%q is not a two-letter country code", r.Country)}
		}
	}
	city, err := normalizeCity(r.City)
	if err != nil {
		return Lease{}, &RequestError{Vendor: v.Name, Field: "City", Reason: err.Error()}
	}
	if city != "" && !t.hasCity {
		return Lease{}, &RequestError{Vendor: v.Name, Field: "City", Reason: "template has no {CITY} placeholder"}
	}
	session := strings.TrimSpace(r.Session)
	if session != "" {
		if !withinBounds(len(session), v.MinSession, v.MaxSession) {
			return Lease{}, &RequestError{Vendor: v.Name, Field: "Session", Reason: fmt.Sprintf(
				"length %d is outside [%d, %d]", len(session), v.MinSession, v.MaxSession)}
		}
		if !v.SessionEscape && !alphanumeric(session) {
			return Lease{}, &RequestError{Vendor: v.Name, Field: "Session", Reason: "must be ASCII alphanumeric"}
		}
	} else if t.hasSession {
		random := make([]byte, v.SessionBytes)
		// Never errors since Go 1.24; it crashes instead.
		_, _ = rand.Read(random)
		session = hex.EncodeToString(random)
	}
	sessionValue := session
	if v.SessionEscape {
		sessionValue = url.QueryEscape(session)
	}
	countryValue := country
	if !v.CountryUpper {
		countryValue = strings.ToLower(country)
	}
	citySegment := ""
	if city != "" {
		citySegment = "_city_" + city
	}
	expanded := strings.NewReplacer(
		placeholderCountry, countryValue,
		placeholderCity, citySegment,
		placeholderSession, sessionValue,
	).Replace(t.template)
	return Lease{
		URL:       expanded,
		SessionID: session,
		Country:   country,
		RTC:       v.RTC,
	}, nil
}

// normalizeCity mirrors the residential pools' city selector: case is preserved, invalid bytes are rejected, not dropped.
func normalizeCity(city string) (string, error) {
	city = strings.ReplaceAll(strings.TrimSpace(city), " ", "-")
	for i := range len(city) {
		c := city[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return "", errors.New("may contain only letters, digits, spaces, and hyphens")
		}
	}
	return city, nil
}

func withinBounds(n, minimum, maximum int) bool {
	return (minimum == 0 || n >= minimum) && (maximum == 0 || n <= maximum)
}

func hostAllowed(host string, suffixes []string) bool {
	host = strings.ToLower(host)
	for _, suffix := range suffixes {
		suffix = strings.ToLower(suffix)
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
