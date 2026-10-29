package transport

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EvadeNow/evade-sdk/proxy"
	"github.com/EvadeNow/evade-sdk/tlsprofile"
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"github.com/bogdanfinn/fhttp/httptrace"
	"github.com/bogdanfinn/tls-client/profiles"
)

func chromeProfile(behavior tlsprofile.Behavior) tlsprofile.Profile {
	return tlsprofile.Profile{Name: "chrome_152", Client: profiles.MappedTLSClients["chrome_152"], Behavior: behavior}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	valid := Config{Profile: chromeProfile(tlsprofile.Behavior{}), Timeout: 30 * time.Second}
	cases := []struct {
		name  string
		edit  func(*Config)
		field string
	}{
		{"no profile", func(c *Config) { c.Profile = tlsprofile.Profile{} }, "Profile"},
		{"profile name without client", func(c *Config) { c.Profile.Client = profiles.ClientProfile{} }, "Profile"},
		{"timeout below one second", func(c *Config) { c.Timeout = 999 * time.Millisecond }, "Timeout"},
		{"zero timeout", func(c *Config) { c.Timeout = 0 }, "Timeout"},
		{"ftp proxy", func(c *Config) { c.Proxy = proxy.Lease{URL: "ftp://proxy.example:21"} }, "Proxy"},
		{"relative proxy", func(c *Config) { c.Proxy = proxy.Lease{URL: "proxy.example:8080"} }, "Proxy"},
		{"trace without proxy", func(c *Config) { c.Trace = NewConnectTrace() }, "Trace"},
		{"trace through socks5", func(c *Config) {
			c.Trace = NewConnectTrace()
			c.Proxy = proxy.Lease{URL: "socks5://proxy.example:1080"}
		}, "Trace"},
		{"trace with dial context", func(c *Config) {
			c.Trace = NewConnectTrace()
			c.Proxy = proxy.Lease{URL: "http://proxy.example:8080"}
			c.DialContext = (&net.Dialer{}).DialContext
		}, "Trace"},
		{"connect user agent missing", func(c *Config) {
			c.Profile.Behavior.ConnectUserAgent = true
			c.Proxy = proxy.Lease{URL: "http://proxy.example:8080"}
		}, "UserAgent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := valid
			tc.edit(&config)
			client, name, err := New(config)
			var configErr *ConfigError
			if !errors.As(err, &configErr) || configErr.Field != tc.field {
				t.Fatalf("New error = %v, want *ConfigError for %s", err, tc.field)
			}
			if client != nil || name != "" {
				t.Fatalf("New returned client %v, name %q alongside the error", client, name)
			}
		})
	}
}

func TestNewBuildsConfiguredClient(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		config    Config
		wantProxy string
	}{
		{"direct", Config{Timeout: time.Second}, ""},
		{"http proxy", Config{Timeout: 5 * time.Second, Proxy: proxy.Lease{URL: "http://u:p@proxy.example:8080"}}, "http://u:p@proxy.example:8080"},
		{"socks5 proxy", Config{Timeout: 5 * time.Second, Proxy: proxy.Lease{URL: "socks5://proxy.example:1080"}}, "socks5://proxy.example:1080"},
		{"dial context", Config{Timeout: 5 * time.Second, Proxy: proxy.Lease{URL: "http://proxy.example:8080"}, DialContext: (&net.Dialer{}).DialContext}, ""},
		{"traced proxy", Config{Timeout: 5 * time.Second, Proxy: proxy.Lease{URL: "http://proxy.example:8080"}, Trace: NewConnectTrace()}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config
			config.Profile = chromeProfile(tlsprofile.Behavior{RandomizeExtensionOrder: true, ConnectUserAgent: true})
			config.UserAgent = "Mozilla/5.0"
			config.Jar = jar
			client, name, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			if name != "chrome_152" {
				t.Fatalf("profile name = %q", name)
			}
			if got := client.GetProxy(); got != tc.wantProxy {
				t.Fatalf("proxy = %q, want %q", got, tc.wantProxy)
			}
			if client.GetCookieJar() != jar {
				t.Fatal("client does not use the configured jar")
			}
			if client.GetFollowRedirect() {
				t.Fatal("client follows redirects although FollowRedirects is false")
			}
		})
	}
	client, _, err := New(Config{Profile: chromeProfile(tlsprofile.Behavior{}), Timeout: time.Second, FollowRedirects: true})
	if err != nil {
		t.Fatal(err)
	}
	if !client.GetFollowRedirect() || client.GetCookieJar() != nil {
		t.Fatalf("follow = %v, jar = %v; want following redirects with no jar", client.GetFollowRedirect(), client.GetCookieJar())
	}
}

func TestSafari26ProfileHandshakes(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	resolver, err := tlsprofile.New()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := resolver.Named("safari_ios_26_0")
	if err != nil {
		t.Fatal(err)
	}
	client, _, err := New(Config{Profile: profile, Timeout: 5 * time.Second, CaptureCA: pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Safari 26 local TLS handshake: %v", err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
}

func TestResolveOptionsPerFlag(t *testing.T) {
	pool := x509.NewCertPool()
	base := func() Config {
		return Config{Profile: chromeProfile(tlsprofile.Behavior{}), Timeout: 1500 * time.Millisecond}
	}
	t.Run("defaults", func(t *testing.T) {
		got, err := resolveOptions(base())
		if err != nil {
			t.Fatal(err)
		}
		if got.route != routeDirect || got.proxyURL != "" || got.transport != nil || got.connectHeaders != nil ||
			got.randomExtensionOrder || got.followRedirects || got.jar != nil || got.timeout != 1500*time.Millisecond {
			t.Fatalf("defaults = %+v", got)
		}
	})
	t.Run("transport options", func(t *testing.T) {
		config := base()
		config.DisableCompression = true
		config.CaptureCA = pool
		got, err := resolveOptions(config)
		if err != nil {
			t.Fatal(err)
		}
		if got.transport == nil || !got.transport.DisableCompression || got.transport.RootCAs != pool {
			t.Fatalf("transport = %+v, want DisableCompression and the capture CA", got.transport)
		}
		config = base()
		config.CaptureCA = pool
		got, _ = resolveOptions(config)
		if got.transport == nil || got.transport.DisableCompression || got.transport.RootCAs != pool {
			t.Fatalf("capture-only transport = %+v", got.transport)
		}
	})
	t.Run("behavior", func(t *testing.T) {
		config := base()
		config.Profile.Behavior = tlsprofile.Behavior{RandomizeExtensionOrder: true, ConnectUserAgent: true}
		config.UserAgent = "UA/1"
		config.Proxy = proxy.Lease{URL: "https://proxy.example"}
		got, err := resolveOptions(config)
		if err != nil {
			t.Fatal(err)
		}
		if !got.randomExtensionOrder || got.route != routeProxyURL || got.proxyURL != config.Proxy.URL {
			t.Fatalf("options = %+v", got)
		}
		if values := got.connectHeaders["user-agent"]; len(got.connectHeaders) != 1 || len(values) != 1 || values[0] != "UA/1" {
			t.Fatalf("connect headers = %v, want only lowercase user-agent", got.connectHeaders)
		}
	})
	t.Run("no CONNECT means no connect headers", func(t *testing.T) {
		for _, edit := range []func(*Config){
			func(c *Config) {},
			func(c *Config) { c.Proxy = proxy.Lease{URL: "socks5://proxy.example:1080"} },
			func(c *Config) {
				c.Proxy = proxy.Lease{URL: "http://proxy.example:8080"}
				c.DialContext = (&net.Dialer{}).DialContext
			},
		} {
			config := base()
			config.Profile.Behavior.ConnectUserAgent = true
			edit(&config)
			got, err := resolveOptions(config)
			if err != nil {
				t.Fatal(err)
			}
			if got.connectHeaders != nil {
				t.Fatalf("route %d sends connect headers %v", got.route, got.connectHeaders)
			}
		}
	})
	t.Run("traced route", func(t *testing.T) {
		config := base()
		config.Proxy = proxy.Lease{URL: "http://proxy.example:8080"}
		config.Trace = NewConnectTrace()
		got, err := resolveOptions(config)
		if err != nil {
			t.Fatal(err)
		}
		if got.route != routeTracedProxy || got.trace != config.Trace || got.proxyURL != config.Proxy.URL {
			t.Fatalf("options = %+v", got)
		}
	})
}

type fakeProxy struct {
	addr     string
	requests chan connectRequest
}

type connectRequest struct {
	raw    string
	header fhttp.Header
	target string
}

func startFakeProxy(t *testing.T, status string) *fakeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	p := &fakeProxy{addr: listener.Addr().String(), requests: make(chan connectRequest, 1)}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var raw strings.Builder
		reader := bufio.NewReader(conn)
		for !strings.HasSuffix(raw.String(), "\r\n\r\n") {
			b, err := reader.ReadByte()
			if err != nil {
				return
			}
			raw.WriteByte(b)
		}
		request, err := fhttp.ReadRequest(bufio.NewReader(strings.NewReader(raw.String())))
		if err != nil {
			return
		}
		p.requests <- connectRequest{raw: raw.String(), header: request.Header, target: request.Host}
		_, _ = conn.Write([]byte(status))
		// Keep the tunnel open so the ClientHello write reaches a live connection.
		_, _ = reader.ReadByte()
	}()
	return p
}

func TestConnectTraceCountsTunnelBytes(t *testing.T) {
	const response = "HTTP/1.1 200 Connection established\r\n\r\n"
	p := startFakeProxy(t, response)
	trace := NewConnectTrace()
	dial := trace.dialerFactory("http://user:secret@" + p.addr)
	dialer, err := dial("", 5*time.Second, nil, fhttp.Header{"user-agent": {"UA/1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		ConnectStart:      func(network, addr string) { events = append(events, "connect "+network+" "+addr) },
		TLSHandshakeStart: func() { events = append(events, "tls") },
	})
	conn, err := dialer.DialContext(ctx, "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := <-p.requests
	if request.target != "target.example:443" {
		t.Fatalf("CONNECT target = %q", request.target)
	}
	// "user:secret" in base64.
	if got := request.header.Get("Proxy-Authorization"); got != "Basic dXNlcjpzZWNyZXQ=" {
		t.Fatalf("Proxy-Authorization = %q", got)
	}
	if got := request.header.Get("User-Agent"); got != "UA/1" {
		t.Fatalf("CONNECT user-agent = %q", got)
	}
	hello := []byte("client-hello")
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	wantEvents := []string{"connect tcp " + p.addr, "tls"}
	if strings.Join(events, "|") != strings.Join(wantEvents, "|") {
		t.Fatalf("events = %q, want %q", events, wantEvents)
	}
	got := trace.Snapshot()
	want := NetworkBytes{Read: int64(len(response)), Wrote: int64(len(request.raw) + len(hello) + len("more"))}
	if len(got) != 1 || got["target.example"] != want {
		t.Fatalf("snapshot = %+v, want target.example: %+v", got, want)
	}
}

func TestConnectTraceRejectedTunnel(t *testing.T) {
	p := startFakeProxy(t, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	trace := NewConnectTrace()
	dialer, err := trace.dialerFactory("http://"+p.addr)("", 5*time.Second, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dialer.DialContext(context.Background(), "tcp", "target.example:443")
	var connectErr *ProxyConnectError
	if !errors.As(err, &connectErr) || connectErr.StatusCode != 407 || connectErr.Err != nil {
		t.Fatalf("error = %#v, want *ProxyConnectError with status 407", err)
	}
	if request := <-p.requests; request.header.Get("Proxy-Authorization") != "" {
		t.Fatalf("credential-less proxy got Proxy-Authorization %q", request.header.Get("Proxy-Authorization"))
	}
}

func TestConnectTraceThroughClient(t *testing.T) {
	p := startFakeProxy(t, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
	trace := NewConnectTrace()
	client, _, err := New(Config{
		Profile:   chromeProfile(tlsprofile.Behavior{ConnectUserAgent: true}),
		UserAgent: "UA/2",
		Timeout:   5 * time.Second,
		Proxy:     proxy.Lease{URL: "http://" + p.addr},
		Trace:     trace,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get("https://target.example/"); err == nil {
		t.Fatal("request through a refusing proxy succeeded")
	}
	request := <-p.requests
	if request.target != "target.example:443" || request.header.Get("User-Agent") != "UA/2" {
		t.Fatalf("CONNECT = %q", request.raw)
	}
	if got := trace.Snapshot()["target.example"]; got.Wrote != int64(len(request.raw)) {
		t.Fatalf("traced bytes = %+v, want the %d CONNECT bytes written", got, len(request.raw))
	}
}

func TestTraceDialerRequiresHTTPProxy(t *testing.T) {
	_, err := NewConnectTrace().dialerFactory("socks5://proxy.example:1080")("", time.Second, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), `"socks5"`) {
		t.Fatalf("error = %v, want a refusal naming the socks5 scheme", err)
	}
}
