// Package transport builds browser-shaped tls-client HTTP clients, header wire orders, client hints and CONNECT tracing.
package transport

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/EvadeNow/evade-sdk/proxy"
	"github.com/EvadeNow/evade-sdk/tlsprofile"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// MinTimeout is the shortest timeout New accepts; tls-client's deadline also covers the proxy CONNECT.
const MinTimeout = time.Second

type Config struct {
	Profile            tlsprofile.Profile
	UserAgent          string      // sent on proxy CONNECT; required when Profile.Behavior.ConnectUserAgent
	Proxy              proxy.Lease // zero value connects directly
	Timeout            time.Duration
	Jar                fhttp.CookieJar
	FollowRedirects    bool
	DisableCompression bool                                                    // for callers sending the browser's own accept-encoding
	DialContext        func(context.Context, string, string) (net.Conn, error) // replaces proxy dialing; the caller routes through Proxy
	CaptureCA          *x509.CertPool                                          // capture-proxy CA, verified rather than skipping verification
	Trace              *ConnectTrace                                           // requires an http:// Proxy; excludes DialContext
}

type ConfigError struct {
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("transport: invalid %s: %s", e.Field, e.Reason)
}

// New returns the client and the profile name it presents; an incomplete or contradictory Config fails instead of defaulting.
func New(c Config) (tlsclient.HttpClient, string, error) {
	resolved, err := resolveOptions(c)
	if err != nil {
		return nil, "", err
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), resolved.options()...)
	if err != nil {
		return nil, "", fmt.Errorf("transport: build %s client: %w", c.Profile.Name, err)
	}
	return client, c.Profile.Name, nil
}

type route uint8

const (
	routeDirect route = iota
	routeProxyURL
	routeDialContext
	routeTracedProxy
)

// clientOptions is the inspectable form of tls-client's opaque option closures.
type clientOptions struct {
	profile              profiles.ClientProfile
	timeout              time.Duration
	jar                  fhttp.CookieJar
	randomExtensionOrder bool
	connectHeaders       fhttp.Header
	transport            *tlsclient.TransportOptions
	route                route
	proxyURL             string
	dialContext          func(context.Context, string, string) (net.Conn, error)
	trace                *ConnectTrace
	followRedirects      bool
}

func resolveOptions(c Config) (clientOptions, error) {
	if c.Profile.Name == "" || c.Profile.Client.GetClientHelloId().Client == "" {
		return clientOptions{}, &ConfigError{Field: "Profile", Reason: "no tls-client profile"}
	}
	if c.Timeout < MinTimeout {
		return clientOptions{}, &ConfigError{Field: "Timeout", Reason: fmt.Sprintf("%s is below %s", c.Timeout, MinTimeout)}
	}
	scheme := ""
	if c.Proxy.URL != "" {
		parsed, err := url.Parse(c.Proxy.URL)
		if err != nil || parsed.Host == "" {
			return clientOptions{}, &ConfigError{Field: "Proxy", Reason: "lease URL is not an absolute proxy URL"}
		}
		switch parsed.Scheme {
		case "http", "https", "socks5":
			scheme = parsed.Scheme
		default:
			return clientOptions{}, &ConfigError{Field: "Proxy", Reason: fmt.Sprintf("unsupported proxy scheme %q", parsed.Scheme)}
		}
	}

	resolved := clientOptions{
		profile:              c.Profile.Client,
		timeout:              c.Timeout,
		jar:                  c.Jar,
		randomExtensionOrder: c.Profile.Behavior.RandomizeExtensionOrder,
		followRedirects:      c.FollowRedirects,
	}
	switch {
	case c.Trace != nil && c.DialContext != nil:
		return clientOptions{}, &ConfigError{Field: "Trace", Reason: "a caller DialContext bypasses the traced CONNECT"}
	case c.Trace != nil:
		if scheme != "http" {
			return clientOptions{}, &ConfigError{Field: "Trace", Reason: "CONNECT tracing requires an http:// proxy lease"}
		}
		resolved.route, resolved.proxyURL, resolved.trace = routeTracedProxy, c.Proxy.URL, c.Trace
	case c.DialContext != nil:
		resolved.route, resolved.dialContext = routeDialContext, c.DialContext
	case scheme != "":
		resolved.route, resolved.proxyURL = routeProxyURL, c.Proxy.URL
	}
	connects := resolved.route == routeTracedProxy || resolved.route == routeProxyURL && scheme != "socks5"
	if c.Profile.Behavior.ConnectUserAgent && connects {
		if c.UserAgent == "" {
			return clientOptions{}, &ConfigError{Field: "UserAgent", Reason: c.Profile.Name + " sends its User-Agent on CONNECT"}
		}
		resolved.connectHeaders = fhttp.Header{"user-agent": {c.UserAgent}}
	}
	if c.DisableCompression || c.CaptureCA != nil {
		resolved.transport = &tlsclient.TransportOptions{DisableCompression: c.DisableCompression, RootCAs: c.CaptureCA}
	}
	return resolved, nil
}

func (o clientOptions) options() []tlsclient.HttpClientOption {
	options := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(o.profile),
		tlsclient.WithTimeoutMilliseconds(int(o.timeout.Milliseconds())),
		// Proxied browsers can't use QUIC, and tls-client refuses HTTP/3 over non-SOCKS5 proxies.
		tlsclient.WithDisableHttp3(),
	}
	if o.jar != nil {
		options = append(options, tlsclient.WithCookieJar(o.jar))
	}
	if o.randomExtensionOrder {
		options = append(options, tlsclient.WithRandomTLSExtensionOrder())
	}
	if o.connectHeaders != nil {
		options = append(options, tlsclient.WithConnectHeaders(o.connectHeaders))
	}
	if o.transport != nil {
		options = append(options, tlsclient.WithTransportOptions(o.transport))
	}
	switch o.route {
	case routeProxyURL:
		options = append(options, tlsclient.WithProxyUrl(o.proxyURL))
	case routeDialContext:
		options = append(options, tlsclient.WithDialContext(o.dialContext))
	case routeTracedProxy:
		options = append(options, tlsclient.WithProxyDialerFactory(o.trace.dialerFactory(o.proxyURL)))
	}
	if !o.followRedirects {
		options = append(options, tlsclient.WithNotFollowRedirects())
	}
	return options
}
