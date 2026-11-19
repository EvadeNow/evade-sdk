package proxy

// Vendor is a plain value: start from a constructor and override fields per account.
type Vendor struct {
	Name                   string
	Schemes                []string // empty allows any
	Hosts                  []string // host suffixes; empty allows any
	Sticky                 bool     // template must carry {CC} and {SESSION}
	Authenticated          bool     // template must carry a port, username and password
	SessionBytes           int      // minted id is hex, so 2*SessionBytes chars
	MinSession, MaxSession int      // id length in chars; zero is unbounded
	SessionEscape          bool     // query-escape the session; without it a pinned one must be alphanumeric
	CountryUpper           bool
	RTC                    RTCPolicy
	Canonicalize           func(template string) (string, error)
}

func Evomi() Vendor {
	return Vendor{
		Name:         "evomi",
		Schemes:      []string{"http"},
		Hosts:        []string{"evomi.com", "evomi-proxy.com"},
		Sticky:       true,
		SessionBytes: 5,
		MinSession:   6,
		MaxSession:   10,
		CountryUpper: true,
		RTC:          RTCPolicyProxyOnly,
	}
}

// Nyxon accepts the budget gateway's country-us/session/time selectors;
// its session id is 8 lowercase alphanumerics.
func Nyxon() Vendor {
	return Vendor{
		Name:         "nyxon",
		Schemes:      []string{"http"},
		Hosts:        []string{"nyxon.sh", "nyxonproxy.com"},
		Sticky:       true,
		SessionBytes: 4,
		MinSession:   8,
		MaxSession:   8,
		CountryUpper: true,
		RTC:          RTCPolicyProxyOnly,
	}
}

// Generic accepts any host; placeholders are optional and leases claim no UDP path.
func Generic() Vendor {
	return Vendor{
		Name:         "generic",
		Schemes:      []string{"http", "https", "socks4", "socks4a", "socks5", "socks5h"},
		SessionBytes: 12,
		CountryUpper: true,
		RTC:          RTCPolicyProxyOnly,
	}
}

func upperLetter(c byte) bool { return c >= 'A' && c <= 'Z' }

func alphanumeric(s string) bool {
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
