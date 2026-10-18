package proxy

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
)

var hexSession = regexp.MustCompile(`^[0-9a-f]+$`)

func mustTemplate(t *testing.T, raw string, v Vendor) *Template {
	t.Helper()
	tmpl, err := NewTemplate(raw, v)
	if err != nil {
		t.Fatalf("NewTemplate(%q): %v", raw, err)
	}
	return tmpl
}

func TestAcquireExpandsPerVendor(t *testing.T) {
	cases := []struct {
		name        string
		vendor      Vendor
		template    string
		country     string
		sessionLen  int
		want        string
		wantCountry string
		wantRTC     RTCPolicy
	}{
		{
			name:        "evomi uppercases country and mints 10 chars",
			vendor:      Evomi(),
			template:    "http://acct:pw_country-{CC}_session-{SESSION}@core-residential.evomi.com:1000",
			country:     " us ",
			sessionLen:  10,
			want:        "http://acct:pw_country-US_session-%s@core-residential.evomi.com:1000",
			wantCountry: "US",
			wantRTC:     RTCPolicyProxyOnly,
		},
		{
			name:        "socks5 lowercases country and relays UDP",
			vendor:      SOCKS5Residential(),
			template:    "socks5://user-cc-{CC}-sess-{SESSION}:pw@gw.example.net:7000",
			country:     "DE",
			sessionLen:  10,
			want:        "socks5://user-cc-de-sess-%s:pw@gw.example.net:7000",
			wantCountry: "DE",
			wantRTC:     RTCPolicySOCKS5UDP,
		},
		{
			name:        "infatica drops the baked-in pair and mints 24 chars",
			vendor:      Infatica(),
			template:    "http://account_c_AU_s_k3f9xq2mvb7twz1p_c_{CC}_s_{SESSION}_ttl_15m_rotm_0:pass@pool.infatica.io:10000",
			country:     "ca",
			sessionLen:  24,
			want:        "http://account_c_CA_s_%s_ttl_15m_rotm_0:pass@pool.infatica.io:10000",
			wantCountry: "CA",
			wantRTC:     RTCPolicyProxyOnly,
		},
		{
			name:        "generic template mints 24 chars",
			vendor:      Generic(),
			template:    "http://u-{CC}-{SESSION}:p@proxy.example.com:8080",
			country:     "gb",
			sessionLen:  24,
			want:        "http://u-GB-%s:p@proxy.example.com:8080",
			wantCountry: "GB",
			wantRTC:     RTCPolicyProxyOnly,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lease, err := mustTemplate(t, tc.template, tc.vendor).Acquire(context.Background(), Request{Country: tc.country})
			if err != nil {
				t.Fatal(err)
			}
			if len(lease.SessionID) != tc.sessionLen || !hexSession.MatchString(lease.SessionID) {
				t.Fatalf("SessionID = %q, want %d lowercase hex chars", lease.SessionID, tc.sessionLen)
			}
			if want := strings.Replace(tc.want, "%s", lease.SessionID, 1); lease.URL != want {
				t.Errorf("URL = %q, want %q", lease.URL, want)
			}
			if lease.Country != tc.wantCountry || lease.RTC != tc.wantRTC {
				t.Errorf("Country, RTC = %q, %d; want %q, %d", lease.Country, lease.RTC, tc.wantCountry, tc.wantRTC)
			}
		})
	}
}

func TestAcquireMintsDistinctSessions(t *testing.T) {
	tmpl := mustTemplate(t, "http://u:p_country-{CC}_session-{SESSION}@rp.evomi.com:1000", Evomi())
	first, err := tmpl.Acquire(context.Background(), Request{Country: "US"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := tmpl.Acquire(context.Background(), Request{Country: "US"})
	if err != nil {
		t.Fatal(err)
	}
	if first.SessionID == second.SessionID || first.URL == second.URL {
		t.Fatalf("two acquires shared session %q", first.SessionID)
	}
}

func TestAcquirePinnedSessionBounds(t *testing.T) {
	tmpl := mustTemplate(t, "http://u:p_country-{CC}_session-{SESSION}@rp.evomi.com:1000", Evomi())
	cases := []struct {
		session string
		ok      bool
	}{
		{"abcde", false},
		{"abcdef", true},
		{"abcdefghij", true},
		{"abcdefghijk", false},
		{"abc-def", false},
	}
	for _, tc := range cases {
		lease, err := tmpl.Acquire(context.Background(), Request{Country: "US", Session: tc.session})
		if !tc.ok {
			reqErr, isReq := errors.AsType[*RequestError](err)
			if !isReq || reqErr.Field != "Session" {
				t.Errorf("session %q: err = %v, want Session RequestError", tc.session, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("session %q: %v", tc.session, err)
			continue
		}
		want := "http://u:p_country-US_session-" + tc.session + "@rp.evomi.com:1000"
		if lease.URL != want || lease.SessionID != tc.session {
			t.Errorf("session %q: URL, SessionID = %q, %q", tc.session, lease.URL, lease.SessionID)
		}
	}
}

func TestAcquireEscapesPinnedSession(t *testing.T) {
	v := Evomi()
	v.SessionEscape = true
	tmpl := mustTemplate(t, "http://u:p_session-{SESSION}_country-{CC}@rp.evomi.com:1000", v)
	lease, err := tmpl.Acquire(context.Background(), Request{Country: "US", Session: "ab+c d/"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://u:p_session-ab%2Bc+d%2F_country-US@rp.evomi.com:1000"; lease.URL != want {
		t.Errorf("URL = %q, want %q", lease.URL, want)
	}
	if lease.SessionID != "ab+c d/" {
		t.Errorf("SessionID = %q, want the unescaped pin", lease.SessionID)
	}
}

func TestAcquireRejectsBadCountry(t *testing.T) {
	tmpl := mustTemplate(t, "socks5://u-{CC}-{SESSION}:p@gw.example.net:7000", SOCKS5Residential())
	for _, country := range []string{"", "U", "U1", "USA", "ü"} {
		_, err := tmpl.Acquire(context.Background(), Request{Country: country})
		if reqErr, ok := errors.AsType[*RequestError](err); !ok || reqErr.Field != "Country" {
			t.Errorf("country %q: err = %v, want Country RequestError", country, err)
		}
	}
}

func TestAcquireCity(t *testing.T) {
	const raw = "http://u:p_country-{CC}{CITY}_session-{SESSION}@rp.evomi.com:1000"
	tmpl := mustTemplate(t, raw, Evomi())
	cases := []struct {
		city string
		want string // expected segment between country and session; "!" = rejected
	}{
		{"", ""},
		{"New York", "_city_New-York"},
		{"  los angeles ", "_city_los-angeles"},
		{"Winston-Salem", "_city_Winston-Salem"},
		{"São Paulo", "!"},
		{"St. Louis", "!"},
	}
	for _, tc := range cases {
		lease, err := tmpl.Acquire(context.Background(), Request{Country: "US", City: tc.city, Session: "sess01"})
		if tc.want == "!" {
			if reqErr, ok := errors.AsType[*RequestError](err); !ok || reqErr.Field != "City" {
				t.Errorf("city %q: err = %v, want City RequestError", tc.city, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("city %q: %v", tc.city, err)
			continue
		}
		if want := "http://u:p_country-US" + tc.want + "_session-sess01@rp.evomi.com:1000"; lease.URL != want {
			t.Errorf("city %q: URL = %q, want %q", tc.city, lease.URL, want)
		}
	}

	noCity := mustTemplate(t, "http://u:p_country-{CC}_session-{SESSION}@rp.evomi.com:1000", Evomi())
	_, err := noCity.Acquire(context.Background(), Request{Country: "US", City: "Boston"})
	if reqErr, ok := errors.AsType[*RequestError](err); !ok || reqErr.Field != "City" {
		t.Errorf("city without {CITY}: err = %v, want City RequestError", err)
	}
}

func TestGenericPassthrough(t *testing.T) {
	tmpl := mustTemplate(t, "  http://u:p@proxy.example.com:8080 ", Generic())
	lease, err := tmpl.Acquire(context.Background(), Request{Country: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	want := Lease{URL: "http://u:p@proxy.example.com:8080", RTC: RTCPolicyProxyOnly}
	if lease != want {
		t.Errorf("lease = %+v, want %+v", lease, want)
	}
	labeled, err := tmpl.Acquire(context.Background(), Request{Session: "run42"})
	if err != nil {
		t.Fatal(err)
	}
	if labeled.URL != want.URL || labeled.SessionID != "run42" {
		t.Errorf("labeled lease = %+v, want URL %q with SessionID run42", labeled, want.URL)
	}
}

func TestAcquireHonorsCanceledContext(t *testing.T) {
	tmpl := mustTemplate(t, "http://u:p@proxy.example.com:8080", Generic())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tmpl.Acquire(ctx, Request{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestNewTemplateValidation(t *testing.T) {
	inconsistent := Evomi()
	inconsistent.SessionBytes = 6 // 12 hex chars exceeds Evomi's 10
	noRTC := Generic()
	noRTC.RTC = RTCPolicyUnknown
	cases := []struct {
		name     string
		vendor   Vendor
		template string
		ok       bool
	}{
		{"evomi host", Evomi(), "http://u:p-{CC}-{SESSION}@rp.evomi.com:1000", true},
		{"evomi apex alt host, mixed case", Evomi(), "http://u:p-{CC}-{SESSION}@Core.EVOMI-proxy.com:1000", true},
		{"evomi foreign host", Evomi(), "http://u:p-{CC}-{SESSION}@proxy.example.com:1000", false},
		{"evomi suffix without dot", Evomi(), "http://u:p-{CC}-{SESSION}@notevomi.com:1000", false},
		{"evomi as subdomain of attacker", Evomi(), "http://u:p-{CC}-{SESSION}@evomi.com.attacker.net:1000", false},
		{"evomi socks5 scheme", Evomi(), "socks5://u:p-{CC}-{SESSION}@rp.evomi.com:1000", false},
		{"evomi missing session", Evomi(), "http://u:p-{CC}@rp.evomi.com:1000", false},
		{"evomi missing country", Evomi(), "http://u:p-{SESSION}@rp.evomi.com:1000", false},
		{"evomi inconsistent session bytes", inconsistent, "http://u:p-{CC}-{SESSION}@rp.evomi.com:1000", false},
		{"infatica foreign host", Infatica(), "http://a_c_{CC}_s_{SESSION}:p@pool.example.com:10000", false},
		{"infatica without selector pair", Infatica(), "http://a-{CC}-{SESSION}:p@pool.infatica.io:10000", false},
		{"socks5 authenticated", SOCKS5Residential(), "socks5://u-{CC}-{SESSION}:p@gw.example.net:7000", true},
		{"socks5 http scheme", SOCKS5Residential(), "http://u-{CC}-{SESSION}:p@gw.example.net:7000", false},
		{"socks5 no port", SOCKS5Residential(), "socks5://u-{CC}-{SESSION}:p@gw.example.net", false},
		{"socks5 no password", SOCKS5Residential(), "socks5://u-{CC}-{SESSION}@gw.example.net:7000", false},
		{"socks5 empty password", SOCKS5Residential(), "socks5://u-{CC}-{SESSION}:@gw.example.net:7000", false},
		{"generic socks5h", Generic(), "socks5h://proxy.example.com:1080", true},
		{"generic ftp", Generic(), "ftp://proxy.example.com:21", false},
		{"generic no scheme", Generic(), "proxy.example.com:8080", false},
		{"generic empty", Generic(), "   ", false},
		{"vendor without RTC", noRTC, "http://proxy.example.com:8080", false},
	}
	for _, tc := range cases {
		_, err := NewTemplate(tc.template, tc.vendor)
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok {
			if _, isTemplate := errors.AsType[*TemplateError](err); !isTemplate {
				t.Errorf("%s: err = %v, want *TemplateError", tc.name, err)
			}
		}
	}
}

func TestCanonicalizeInfatica(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "exported credential with baked-in pair",
			in:   "http://account_c_AU_s_k3f9xq2mvb7twz1p_c_{CC}_s_{SESSION}_ttl_15m_rotm_0:pass@pool.infatica.io:10000",
			want: "http://account_c_{CC}_s_{SESSION}_ttl_15m_rotm_0:pass@pool.infatica.io:10000",
		},
		{
			name: "already canonical",
			in:   "http://account_c_{CC}_s_{SESSION}_ttl_15m:pass@pool.infatica.io:10000",
			want: "http://account_c_{CC}_s_{SESSION}_ttl_15m:pass@pool.infatica.io:10000",
		},
		{
			name: "lower-case concrete country is not a selector",
			in:   "http://account_c_au_s_old_c_{CC}_s_{SESSION}:pass@pool.infatica.io:10000",
			want: "http://account_c_au_s_old_c_{CC}_s_{SESSION}:pass@pool.infatica.io:10000",
		},
		{
			name: "non-alphanumeric concrete session is kept",
			in:   "http://account_c_AU_s_old-1_c_{CC}_s_{SESSION}:pass@pool.infatica.io:10000",
			want: "http://account_c_AU_s_old-1_c_{CC}_s_{SESSION}:pass@pool.infatica.io:10000",
		},
	}
	for _, tc := range cases {
		got, err := CanonicalizeInfatica(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
	if _, err := CanonicalizeInfatica("http://account-{CC}-{SESSION}:pass@pool.infatica.io:10000"); err == nil {
		t.Error("template without _c_{CC}_s_{SESSION} was accepted")
	}
}
