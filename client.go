package evade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

const (
	defaultTimeout          = 60 * time.Second
	defaultMaxResponseBytes = 32 << 20
	defaultMaxRetries       = 3
	defaultMaxBackoff       = 30 * time.Second
	backoffBase             = 500 * time.Millisecond
)

// Config configures a Client. Only BaseURL is required.
type Config struct {
	BaseURL string // trailing slashes are dropped
	APIKey  string // sent as a Bearer token; empty sends no Authorization header
	// HTTP is the tls-client the calls go through; nil builds one on
	// tls-client's default profile.
	HTTP tlsclient.HttpClient
	// Timeout applies only when HTTP is nil; zero means 60s. tls-client
	// counts it in whole milliseconds, so a shorter one is refused.
	Timeout          time.Duration
	MaxResponseBytes int64 // zero means 32 MiB
	// MaxRetries is how many times a 429 or 503 answer is retried; nil
	// means 3 and new(0) disables retries.
	MaxRetries *int
	// MaxBackoff caps each wait between attempts; zero means 30s. A
	// Retry-After longer than this is not waited out: the call returns its
	// *APIError so the caller decides whether to come back that much later.
	MaxBackoff time.Duration
}

// ConfigError reports an invalid Config field.
type ConfigError struct {
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("evade: config %s: %s", e.Field, e.Reason)
}

// ResponseTooLargeError reports a response body over Config.MaxResponseBytes.
type ResponseTooLargeError struct {
	Status int
	Limit  int64
}

func (e *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("evade: %d response body exceeds %d bytes", e.Status, e.Limit)
}

// Client calls the Evade solve APIs. It is safe for concurrent use.
type Client struct {
	baseURL    string
	apiKey     string
	http       tlsclient.HttpClient
	maxBytes   int64
	maxRetries int
	maxBackoff time.Duration
	wait       func(context.Context, time.Duration) error
}

// NewClient validates c and returns a Client.
func NewClient(c Config) (*Client, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		return nil, &ConfigError{Field: "BaseURL", Reason: "is required"}
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, &ConfigError{Field: "BaseURL", Reason: err.Error()}
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, &ConfigError{Field: "BaseURL", Reason: "must be an absolute http or https URL"}
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, &ConfigError{Field: "BaseURL", Reason: "must not carry a query or fragment"}
	}
	if c.Timeout < 0 {
		return nil, &ConfigError{Field: "Timeout", Reason: "must not be negative"}
	}
	if c.MaxResponseBytes < 0 {
		return nil, &ConfigError{Field: "MaxResponseBytes", Reason: "must not be negative"}
	}
	if c.MaxRetries != nil && *c.MaxRetries < 0 {
		return nil, &ConfigError{Field: "MaxRetries", Reason: "must not be negative"}
	}
	if c.MaxBackoff < 0 {
		return nil, &ConfigError{Field: "MaxBackoff", Reason: "must not be negative"}
	}
	client := &Client{baseURL: base, apiKey: c.APIKey, http: c.HTTP, maxBytes: c.MaxResponseBytes,
		maxRetries: defaultMaxRetries, maxBackoff: c.MaxBackoff, wait: sleep}
	if c.MaxRetries != nil {
		client.maxRetries = *c.MaxRetries
	}
	if client.maxBackoff == 0 {
		client.maxBackoff = defaultMaxBackoff
	}
	if client.maxBytes == 0 {
		client.maxBytes = defaultMaxResponseBytes
	}
	if client.http == nil {
		timeout := c.Timeout
		if timeout == 0 {
			timeout = defaultTimeout
		}
		// Truncated to 0ms it would mean no timeout at all.
		if timeout < time.Millisecond {
			return nil, &ConfigError{Field: "Timeout", Reason: "must be at least 1ms"}
		}
		built, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
			tlsclient.WithTimeoutMilliseconds(int(timeout.Milliseconds())))
		if err != nil {
			return nil, fmt.Errorf("evade: build tls-client: %w", err)
		}
		client.http = built
	}
	return client, nil
}

// NoContent, passed as Call's out, requires a 204 response.
type NoContent struct{}

// Call sends in as JSON and decodes a 2xx body into out; a non-2xx response
// returns *APIError. RateLimit is returned alongside an *APIError too.
// A 429 or 503 answer is retried as Config.MaxRetries and MaxBackoff
// allow, never waiting past ctx's deadline.
func (c *Client) Call(ctx context.Context, method, path string, in, out any) (RateLimit, error) {
	if !strings.HasPrefix(path, "/") {
		return RateLimit{}, fmt.Errorf("evade: %s %q: path must begin with /", method, path)
	}
	// Encoded once so every attempt sends the identical bytes.
	var payload []byte
	if in != nil {
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(in); err != nil {
			return RateLimit{}, fmt.Errorf("evade: encode %s %s request: %w", method, path, err)
		}
		payload = encoded.Bytes()
	}
	for attempt := 1; ; attempt++ {
		limit, err := c.send(ctx, method, path, payload, out)
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			return limit, err
		}
		apiErr.Attempts = attempt
		if attempt > c.maxRetries {
			return limit, err
		}
		delay, retry := c.retryDelay(apiErr, attempt)
		if !retry {
			return limit, err
		}
		// Waiting into the deadline only to fail with a context error would
		// hide the server's answer, so the last refusal is returned instead.
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Add(delay).Before(deadline) {
			return limit, err
		}
		if waitErr := c.wait(ctx, delay); waitErr != nil {
			return limit, fmt.Errorf("evade: %s %s: retry wait: %w: %w", method, path, waitErr, err)
		}
	}
}

// retryDelay is the wait before retrying apiErr's request after attempt
// attempts; false means the refusal is not retried.
func (c *Client) retryDelay(apiErr *APIError, attempt int) (time.Duration, bool) {
	if apiErr.Status != http.StatusTooManyRequests && apiErr.Status != http.StatusServiceUnavailable {
		return 0, false
	}
	if hint := apiErr.RateLimit.RetryAfter; hint > 0 {
		return hint, hint <= c.maxBackoff
	}
	// An exhausted balance only refills when credits are bought, which is
	// why the server sends no Retry-After for it: no wait can succeed.
	if apiErr.Status == http.StatusTooManyRequests && apiErr.Code == CodeQuotaExceeded {
		return 0, false
	}
	// Full jitter over a doubling ceiling spreads a crowd of clients refused
	// at the same instant instead of having them return in lockstep.
	ceiling := min(backoffBase, c.maxBackoff)
	for range attempt - 1 {
		if ceiling > c.maxBackoff/2 {
			ceiling = c.maxBackoff
			break
		}
		ceiling *= 2
	}
	return rand.N(ceiling), true
}

func sleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// send makes one attempt; payload nil sends no body.
func (c *Client) send(ctx context.Context, method, path string, payload []byte, out any) (RateLimit, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return RateLimit{}, fmt.Errorf("evade: build %s %s request: %w", method, path, err)
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return RateLimit{}, fmt.Errorf("evade: %s %s: %w", method, path, err)
	}
	defer response.Body.Close()

	limit, err := parseRateLimit(response.Header, time.Now())
	if err != nil {
		return RateLimit{}, err
	}
	// One byte past the cap, so a body of exactly MaxResponseBytes is accepted.
	raw, err := io.ReadAll(io.LimitReader(response.Body, c.maxBytes+1))
	if err != nil {
		return limit, fmt.Errorf("evade: read %s %s response: %w", method, path, err)
	}
	if int64(len(raw)) > c.maxBytes {
		return limit, &ResponseTooLargeError{Status: response.StatusCode, Limit: c.maxBytes}
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return limit, apiError(response.StatusCode, raw, limit)
	}
	if _, ok := out.(NoContent); ok {
		if response.StatusCode != http.StatusNoContent {
			return limit, &APIError{Status: response.StatusCode, RateLimit: limit,
				Message: fmt.Sprintf("expected 204 No Content, got %d", response.StatusCode)}
		}
		return limit, nil
	}
	if out == nil {
		return limit, nil
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return limit, fmt.Errorf("evade: %s %s: %d response has an empty body", method, path, response.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return limit, fmt.Errorf("evade: decode %s %s response: %w", method, path, err)
	}
	return limit, nil
}

func apiError(status int, raw []byte, limit RateLimit) *APIError {
	failure := &APIError{Status: status, RateLimit: limit}
	text := bytes.TrimSpace(raw)
	if len(text) == 0 {
		return failure
	}
	var envelope ErrorEnvelope
	if json.Unmarshal(text, &envelope) != nil || envelope.Error.Code == "" {
		failure.Message = string(text)
		return failure
	}
	failure.Code = Code(envelope.Error.Code)
	failure.Message = envelope.Error.Message
	failure.ChallengeVariantID = envelope.Error.ChallengeVariantID
	if envelope.Debug != nil && envelope.Debug.Stage != "" {
		failure.Stop = envelope.Debug
	}
	return failure
}
