package evade

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	tlsclient "github.com/bogdanfinn/tls-client"
)

type captured struct {
	method, path, authorization, contentType string
	body                                     string
}

func testServer(t *testing.T, status int, body string, header http.Header) (*httptest.Server, *captured) {
	t.Helper()
	seen := &captured{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		*seen = captured{
			method: r.Method, path: r.URL.RequestURI(), body: string(raw),
			authorization: r.Header.Get("Authorization"), contentType: r.Header.Get("Content-Type"),
		}
		for name, values := range header {
			w.Header()[name] = values
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server, seen
}

func newTestClient(t *testing.T, config Config) *Client {
	t.Helper()
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestCallSendsBearerJSONWithoutHTMLEscaping(t *testing.T) {
	server, seen := testServer(t, http.StatusOK, `{"headers":{"x-a":"<b>&"},"added_later":[1]}`, nil)
	client := newTestClient(t, Config{BaseURL: server.URL + "//", APIKey: "sk_test"})
	in := struct {
		PageHTML string `json:"page_html"`
	}{PageHTML: `<html a="1">&amp;</html>`}
	var out struct {
		Headers map[string]string `json:"headers"`
	}
	if _, err := client.Call(context.Background(), http.MethodPost, "/solve", in, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if seen.method != http.MethodPost || seen.path != "/solve" {
		t.Fatalf("request line = %s %s, want POST /solve", seen.method, seen.path)
	}
	if seen.authorization != "Bearer sk_test" {
		t.Fatalf("Authorization = %q", seen.authorization)
	}
	if seen.contentType != "application/json" {
		t.Fatalf("Content-Type = %q", seen.contentType)
	}
	if want := `{"page_html":"<html a=\"1\">&amp;</html>"}` + "\n"; seen.body != want {
		t.Fatalf("body = %q, want %q", seen.body, want)
	}
	if out.Headers["x-a"] != "<b>&" {
		t.Fatalf("decoded headers = %v", out.Headers)
	}
}

func TestCallWithoutKeyOrBodySendsNeitherHeader(t *testing.T) {
	server, seen := testServer(t, http.StatusOK, `{}`, nil)
	client := newTestClient(t, Config{BaseURL: server.URL})
	if _, err := client.Call(context.Background(), http.MethodGet, "/api/v1/status?verbose=1", nil, nil); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if seen.authorization != "" || seen.contentType != "" || seen.body != "" {
		t.Fatalf("request carried authorization=%q content-type=%q body=%q",
			seen.authorization, seen.contentType, seen.body)
	}
	if seen.path != "/api/v1/status?verbose=1" {
		t.Fatalf("path = %q", seen.path)
	}
}

func TestCallEnforcesResponseCap(t *testing.T) {
	const limit = 16
	tests := []struct {
		name   string
		status int
		body   string
		over   bool
	}{
		{"at cap", http.StatusOK, `{"a":"12345678"}`, false},
		{"one past cap", http.StatusOK, `{"a":"1234567890"}`, true},
		{"error body past cap", http.StatusBadGateway, strings.Repeat("x", limit+1), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, _ := testServer(t, test.status, test.body, nil)
			client := newTestClient(t, Config{BaseURL: server.URL, MaxResponseBytes: limit})
			var out map[string]string
			_, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &out)
			var tooLarge *ResponseTooLargeError
			if !test.over {
				if err != nil {
					t.Fatalf("Call at the cap: %v", err)
				}
				return
			}
			if !errors.As(err, &tooLarge) || tooLarge.Limit != limit || tooLarge.Status != test.status {
				t.Fatalf("error = %#v, want *ResponseTooLargeError{Status:%d Limit:%d}", err, test.status, limit)
			}
		})
	}
}

func TestCallReturnsAPIErrorForNon2xx(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   APIError
		text   string
	}{
		{
			name: "envelope", status: http.StatusBadRequest,
			body: `{"success":false,"error":{"code":"invalid_request","message":"target_api_method: is required"}}`,
			want: APIError{Status: 400, Code: CodeInvalidRequest, Message: "target_api_method: is required"},
			text: "evade: 400 invalid_request: target_api_method: is required",
		},
		{
			name: "empty body", status: http.StatusBadGateway, body: "",
			want: APIError{Status: 502},
			text: "evade: 502: ",
		},
		{
			name: "plain text body", status: http.StatusBadRequest, body: "unknown iOS app\n",
			want: APIError{Status: 400, Message: "unknown iOS app"},
			text: "evade: 400: unknown iOS app",
		},
		{
			name: "json without error code", status: http.StatusServiceUnavailable, body: `{"success":false}`,
			want: APIError{Status: 503, Message: `{"success":false}`},
			text: `evade: 503: {"success":false}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, _ := testServer(t, test.status, test.body, nil)
			client := newTestClient(t, Config{BaseURL: server.URL, MaxRetries: new(0)})
			out := map[string]any{"untouched": true}
			_, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &out)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %v, want *APIError", err)
			}
			want := test.want
			want.Attempts = 1 // retries are disabled, so every failure is the first answer
			if *apiErr != want {
				t.Fatalf("APIError = %#v, want %#v", *apiErr, want)
			}
			if apiErr.Error() != test.text {
				t.Fatalf("Error() = %q, want %q", apiErr.Error(), test.text)
			}
			if len(out) != 1 || out["untouched"] != true {
				t.Fatalf("error response was decoded into out: %v", out)
			}
		})
	}
}

func TestCallRejectsEmptySuccessBodyWhenDecoding(t *testing.T) {
	server, _ := testServer(t, http.StatusOK, "", nil)
	client := newTestClient(t, Config{BaseURL: server.URL})
	var out map[string]any
	_, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &out)
	var apiErr *APIError
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want a non-API decode failure", err)
	}
}

func TestCallNoContentRequires204(t *testing.T) {
	tests := []struct {
		status int
		body   string
		ok     bool
	}{
		{http.StatusNoContent, "", true},
		{http.StatusOK, `{"success":true}`, false},
		{http.StatusOK, "", false},
	}
	for _, test := range tests {
		server, seen := testServer(t, test.status, test.body, nil)
		client := newTestClient(t, Config{BaseURL: server.URL})
		_, err := client.Call(context.Background(), http.MethodDelete, "/solve/session/abc", nil, NoContent{})
		if seen.method != http.MethodDelete {
			t.Fatalf("method = %s", seen.method)
		}
		if test.ok {
			if err != nil {
				t.Fatalf("status %d: %v", test.status, err)
			}
			continue
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != test.status || apiErr.Code != "" {
			t.Fatalf("status %d: error = %#v, want *APIError with that status and no code", test.status, err)
		}
	}
}

func TestCallRejectsRelativePath(t *testing.T) {
	server, seen := testServer(t, http.StatusOK, `{}`, nil)
	client := newTestClient(t, Config{BaseURL: server.URL})
	if _, err := client.Call(context.Background(), http.MethodPost, "solve", nil, nil); err == nil {
		t.Fatal("Call accepted a path without a leading slash")
	}
	if seen.method != "" {
		t.Fatalf("request reached the server: %+v", seen)
	}
}

func TestNewClientRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		config Config
		field  string
	}{
		{Config{}, "BaseURL"},
		{Config{BaseURL: "/"}, "BaseURL"},
		{Config{BaseURL: "shape.example.com"}, "BaseURL"},
		{Config{BaseURL: "ftp://shape.example.com"}, "BaseURL"},
		{Config{BaseURL: "https://shape.example.com?x=1"}, "BaseURL"},
		{Config{BaseURL: "https://shape.example.com", Timeout: -1}, "Timeout"},
		{Config{BaseURL: "https://shape.example.com", Timeout: time.Microsecond}, "Timeout"},
		{Config{BaseURL: "https://shape.example.com", MaxResponseBytes: -1}, "MaxResponseBytes"},
		{Config{BaseURL: "https://shape.example.com", MaxRetries: new(-1)}, "MaxRetries"},
		{Config{BaseURL: "https://shape.example.com", MaxBackoff: -1}, "MaxBackoff"},
	}
	for _, test := range tests {
		_, err := NewClient(test.config)
		var configErr *ConfigError
		if !errors.As(err, &configErr) || configErr.Field != test.field {
			t.Fatalf("NewClient(%+v) error = %v, want *ConfigError on %s", test.config, err, test.field)
		}
	}
}

func TestNewClientDefaults(t *testing.T) {
	client := newTestClient(t, Config{BaseURL: "https://shape.example.com/"})
	if client.baseURL != "https://shape.example.com" {
		t.Fatalf("baseURL = %q", client.baseURL)
	}
	if client.http == nil || client.maxBytes != defaultMaxResponseBytes {
		t.Fatalf("http = %v, max bytes = %d", client.http, client.maxBytes)
	}
	if client.maxRetries != 3 || client.maxBackoff != 30*time.Second {
		t.Fatalf("max retries = %d, max backoff = %v, want 3 and 30s", client.maxRetries, client.maxBackoff)
	}
	custom, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger())
	if err != nil {
		t.Fatalf("NewHttpClient: %v", err)
	}
	client = newTestClient(t, Config{BaseURL: "https://shape.example.com", HTTP: custom, Timeout: 5})
	if client.http != custom {
		t.Fatal("a caller-supplied HTTP client was replaced")
	}
	client = newTestClient(t, Config{BaseURL: "https://shape.example.com", MaxRetries: new(0)})
	if client.maxRetries != 0 {
		t.Fatalf("MaxRetries new(0) gave max retries = %d, want 0", client.maxRetries)
	}
}

func TestDefaultClientEnforcesTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	client := newTestClient(t, Config{BaseURL: server.URL, Timeout: 100 * time.Millisecond, MaxRetries: new(0)})
	start := time.Now()
	_, err := client.Call(context.Background(), http.MethodGet, "/status", nil, nil)
	var apiErr *APIError
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want a transport timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("returned after %v, want soon after the 100ms timeout", elapsed)
	}
}

type reply struct {
	status int
	header http.Header
	body   string
}

// scriptedServer answers the n-th request with replies[n], repeating the
// last reply once they run out; requests returns every body received so far.
func scriptedServer(t *testing.T, replies ...reply) (server *httptest.Server, requests func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		mu.Lock()
		bodies = append(bodies, string(raw))
		answer := replies[min(len(bodies), len(replies))-1]
		mu.Unlock()
		for name, values := range answer.header {
			w.Header()[name] = values
		}
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	}))
	t.Cleanup(server.Close)
	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

// recordWaits replaces client's sleep so a test sees each requested delay
// without spending it.
func recordWaits(client *Client) *[]time.Duration {
	waits := &[]time.Duration{}
	client.wait = func(_ context.Context, delay time.Duration) error {
		*waits = append(*waits, delay)
		return nil
	}
	return waits
}

const (
	unavailableBody = `{"success":false,"error":{"code":"quota_unavailable","message":"quota is temporarily unavailable"}}`
	rateLimitedBody = `{"success":false,"error":{"code":"rate_limited","message":"slow down"}}`
)

func TestCallRetries429And503ThenSucceeds(t *testing.T) {
	server, requests := scriptedServer(t,
		reply{status: http.StatusServiceUnavailable, body: unavailableBody},
		reply{status: http.StatusTooManyRequests, body: rateLimitedBody},
		reply{status: http.StatusOK, body: `{"token":"t"}`},
	)
	client := newTestClient(t, Config{BaseURL: server.URL})
	waits := recordWaits(client)
	var out struct {
		Token string `json:"token"`
	}
	if _, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out.Token != "t" || len(requests()) != 3 {
		t.Fatalf("token = %q after %d requests, want t after 3", out.Token, len(requests()))
	}
	// Full jitter: the n-th wait is uniform below 500ms doubled n-1 times.
	if len(*waits) != 2 || (*waits)[0] < 0 || (*waits)[0] >= 500*time.Millisecond ||
		(*waits)[1] < 0 || (*waits)[1] >= time.Second {
		t.Fatalf("waits = %v, want one below 500ms then one below 1s", *waits)
	}
}

func TestCallResendsIdenticalBody(t *testing.T) {
	server, requests := scriptedServer(t,
		reply{status: http.StatusServiceUnavailable, body: unavailableBody},
		reply{status: http.StatusServiceUnavailable, body: unavailableBody},
		reply{status: http.StatusNoContent},
	)
	client := newTestClient(t, Config{BaseURL: server.URL})
	recordWaits(client)
	in := map[string]string{"html": `<a href="x">&</a>`}
	if _, err := client.Call(context.Background(), http.MethodPost, "/solve", in, NoContent{}); err != nil {
		t.Fatalf("Call: %v", err)
	}
	want := `{"html":"<a href=\"x\">&</a>"}` + "\n"
	bodies := requests()
	if len(bodies) != 3 {
		t.Fatalf("%d requests, want 3", len(bodies))
	}
	for i, body := range bodies {
		if body != want {
			t.Fatalf("attempt %d body = %q, want %q", i+1, body, want)
		}
	}
}

func TestCallHonorsRetryAfter(t *testing.T) {
	tests := []struct {
		name     string
		header   func() string
		min, max time.Duration
	}{
		{"seconds", func() string { return "7" }, 7 * time.Second, 7 * time.Second},
		// An HTTP-date has whole-second resolution, so the delay lands
		// within the second before the date.
		{"http-date", func() string { return time.Now().Add(20 * time.Second).UTC().Format(http.TimeFormat) },
			18 * time.Second, 20 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, requests := scriptedServer(t,
				reply{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": {test.header()}}, body: rateLimitedBody},
				reply{status: http.StatusOK, body: `{}`},
			)
			client := newTestClient(t, Config{BaseURL: server.URL})
			waits := recordWaits(client)
			if _, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &struct{}{}); err != nil {
				t.Fatalf("Call: %v", err)
			}
			if len(requests()) != 2 || len(*waits) != 1 || (*waits)[0] < test.min || (*waits)[0] > test.max {
				t.Fatalf("%d requests, waits %v; want 2 requests and one wait in [%v, %v]",
					len(requests()), *waits, test.min, test.max)
			}
		})
	}
}

func TestCallDoesNotRetry(t *testing.T) {
	tests := []struct {
		name  string
		reply reply
	}{
		{"400", reply{status: http.StatusBadRequest, body: `{"success":false,"error":{"code":"invalid_request","message":"bad"}}`}},
		{"401", reply{status: http.StatusUnauthorized, body: `{"success":false,"error":{"code":"invalid_api_key","message":"no"}}`}},
		{"500", reply{status: http.StatusInternalServerError, body: `{"success":false,"error":{"code":"solve_failed","message":"failed"}}`}},
		{"exhausted balance", reply{status: http.StatusTooManyRequests,
			body: `{"success":false,"error":{"code":"quota_exceeded","message":"balance exhausted"}}`}},
		{"retry-after beyond max backoff", reply{status: http.StatusTooManyRequests,
			header: http.Header{"Retry-After": {"3600"}},
			body:   `{"success":false,"error":{"code":"quota_exceeded","message":"window exhausted"}}`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, requests := scriptedServer(t, test.reply)
			client := newTestClient(t, Config{BaseURL: server.URL})
			waits := recordWaits(client)
			_, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &struct{}{})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != test.reply.status || apiErr.Attempts != 1 {
				t.Fatalf("error = %#v, want *APIError status %d after 1 attempt", err, test.reply.status)
			}
			if len(requests()) != 1 || len(*waits) != 0 {
				t.Fatalf("%d requests, waits %v; want 1 request and no wait", len(requests()), *waits)
			}
		})
	}
}

func TestCallStopsAtMaxRetries(t *testing.T) {
	tests := []struct {
		name       string
		maxRetries *int
		attempts   int
	}{
		{"default", nil, 4},
		{"two", new(2), 3},
		{"zero disables", new(0), 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, requests := scriptedServer(t, reply{status: http.StatusServiceUnavailable, body: unavailableBody})
			client := newTestClient(t, Config{BaseURL: server.URL, MaxRetries: test.maxRetries})
			waits := recordWaits(client)
			_, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &struct{}{})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != http.StatusServiceUnavailable ||
				apiErr.Code != CodeQuotaUnavailable || apiErr.Attempts != test.attempts {
				t.Fatalf("error = %#v, want 503 quota_unavailable after %d attempts", err, test.attempts)
			}
			if len(requests()) != test.attempts || len(*waits) != test.attempts-1 {
				t.Fatalf("%d requests, %d waits; want %d and %d", len(requests()), len(*waits), test.attempts, test.attempts-1)
			}
		})
	}
}

func TestCallBackoffStaysUnderMaxBackoff(t *testing.T) {
	server, _ := scriptedServer(t, reply{status: http.StatusServiceUnavailable, body: unavailableBody})
	client := newTestClient(t, Config{BaseURL: server.URL, MaxRetries: new(8), MaxBackoff: 2 * time.Second})
	waits := recordWaits(client)
	if _, err := client.Call(context.Background(), http.MethodGet, "/status", nil, nil); err == nil {
		t.Fatal("Call succeeded against a server that only answers 503")
	}
	ceilings := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 2 * time.Second,
		2 * time.Second, 2 * time.Second, 2 * time.Second, 2 * time.Second}
	if len(*waits) != len(ceilings) {
		t.Fatalf("waits = %v, want %d", *waits, len(ceilings))
	}
	for i, wait := range *waits {
		if wait < 0 || wait >= ceilings[i] {
			t.Fatalf("wait %d = %v, want in [0, %v)", i+1, wait, ceilings[i])
		}
	}
}

func TestCallReturnsLastAPIErrorRatherThanWaitPastDeadline(t *testing.T) {
	server, requests := scriptedServer(t, reply{status: http.StatusServiceUnavailable,
		header: http.Header{"Retry-After": {"10"}}, body: unavailableBody})
	client := newTestClient(t, Config{BaseURL: server.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err := client.Call(ctx, http.MethodPost, "/solve", map[string]string{}, &struct{}{})
	elapsed := time.Since(start)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusServiceUnavailable || apiErr.Attempts != 1 ||
		apiErr.RateLimit.RetryAfter != 10*time.Second {
		t.Fatalf("error = %#v, want the 503 with its 10s Retry-After after 1 attempt", err)
	}
	if errors.Is(err, context.DeadlineExceeded) || elapsed > time.Second || len(requests()) != 1 {
		t.Fatalf("returned after %v and %d requests with %v; want at once after 1 request", elapsed, len(requests()), err)
	}
}

func TestCallWaitEndsWithContext(t *testing.T) {
	server, requests := scriptedServer(t, reply{status: http.StatusTooManyRequests,
		header: http.Header{"Retry-After": {"10"}}, body: rateLimitedBody})
	client := newTestClient(t, Config{BaseURL: server.URL})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := client.Call(ctx, http.MethodPost, "/solve", map[string]string{}, &struct{}{})
	var apiErr *APIError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &apiErr) || apiErr.Code != CodeRateLimited {
		t.Fatalf("error = %v, want context.Canceled wrapping the 429 rate_limited", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second || len(requests()) != 1 {
		t.Fatalf("returned after %v and %d requests; want soon after cancel with 1 request", elapsed, len(requests()))
	}
}
