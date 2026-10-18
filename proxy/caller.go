package proxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// CallerError names the malformed part ("scheme", "host", "port", "userinfo", "url") and never echoes credentials.
type CallerError struct {
	Part   string
	Reason string
}

func (e *CallerError) Error() string {
	return fmt.Sprintf("proxy: caller proxy %s: %s", e.Part, e.Reason)
}

// ParseCaller accepts a proxy URL or host:port:user:pass (http unless a scheme prefixes it); the lease has no session, no country, and no UDP path.
func ParseCaller(raw string) (Lease, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Lease{}, &CallerError{Part: "url", Reason: "is empty"}
	}
	scheme, authority, hasScheme := strings.Cut(raw, "://")
	if hasScheme {
		scheme = strings.ToLower(strings.TrimSpace(scheme))
		if !callerScheme(scheme) {
			return Lease{}, &CallerError{Part: "scheme", Reason: fmt.Sprintf(
				"%q is not one of http, https, socks4, socks4a, socks5, socks5h", scheme)}
		}
	} else {
		scheme, authority = "http", raw
	}

	// Before url.Parse, which would read user:pass as part of the port; N=4 keeps colons in the password.
	if parts := strings.SplitN(authority, ":", 4); len(parts) == 4 {
		if port, err := strconv.Atoi(parts[1]); err == nil {
			return callerColonForm(scheme, parts[0], port, parts[2], parts[3])
		}
	}
	if !hasScheme {
		return Lease{}, &CallerError{Part: "scheme", Reason: "missing; use scheme://host:port or host:port:user:pass"}
	}

	parsed, err := url.Parse(scheme + "://" + authority)
	if err != nil {
		// url.Error quotes the input, credentials included, so it is never surfaced.
		hostport := authority[strings.LastIndex(authority, "@")+1:]
		if _, port, splitErr := net.SplitHostPort(hostport); splitErr == nil {
			if _, atoiErr := strconv.Atoi(port); atoiErr != nil {
				return Lease{}, &CallerError{Part: "port", Reason: "is not numeric"}
			}
		}
		return Lease{}, &CallerError{Part: "url", Reason: "does not parse"}
	}
	if parsed.Hostname() == "" {
		return Lease{}, &CallerError{Part: "host", Reason: "is empty"}
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Lease{}, &CallerError{Part: "url", Reason: "must not carry a path, query, or fragment"}
	}
	if portText := parsed.Port(); portText != "" {
		if port, err := strconv.Atoi(portText); err != nil || port < 1 || port > 65535 {
			return Lease{}, &CallerError{Part: "port", Reason: fmt.Sprintf("%q is not in 1-65535", portText)}
		}
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		password, hasPassword := parsed.User.Password()
		if username == "" || !hasPassword || password == "" {
			return Lease{}, &CallerError{Part: "userinfo", Reason: "requires a non-empty username and password"}
		}
		parsed.User = url.UserPassword(username, password)
	}
	return Lease{URL: parsed.String(), RTC: RTCPolicyProxyOnly}, nil
}

func callerColonForm(scheme, host string, port int, username, password string) (Lease, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return Lease{}, &CallerError{Part: "host", Reason: "is empty"}
	}
	if strings.ContainsAny(host, "/?#@[]:") {
		return Lease{}, &CallerError{Part: "host", Reason: "contains URL delimiters"}
	}
	if port < 1 || port > 65535 {
		return Lease{}, &CallerError{Part: "port", Reason: fmt.Sprintf("%d is not in 1-65535", port)}
	}
	// Vendors publish credentials raw or percent-encoded; decode so url.UserPassword re-encodes once.
	username, errUser := url.PathUnescape(username)
	password, errPass := url.PathUnescape(password)
	if errUser != nil || errPass != nil || username == "" || password == "" {
		return Lease{}, &CallerError{Part: "userinfo", Reason: "requires a non-empty, validly escaped username and password"}
	}
	proxyURL := &url.URL{
		Scheme: scheme,
		Host:   host + ":" + strconv.Itoa(port),
		User:   url.UserPassword(username, password),
	}
	return Lease{URL: proxyURL.String(), RTC: RTCPolicyProxyOnly}, nil
}

func callerScheme(scheme string) bool {
	switch scheme {
	case "http", "https", "socks4", "socks4a", "socks5", "socks5h":
		return true
	}
	return false
}
