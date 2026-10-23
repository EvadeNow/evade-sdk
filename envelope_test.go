package evade

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

func TestAPIErrorFromEachTargetEnvelope(t *testing.T) {
	tests := []struct {
		target string
		status int
		header http.Header
		body   string
		want   APIError
	}{
		{
			target: "shape", status: http.StatusInternalServerError,
			body: `{"success":false,"error":{"code":"solve_failed","message":"The challenge could not be solved. The failure was logged for us to look into.","challenge_variant_id":"variant-7f3a"}}`,
			want: APIError{Status: 500, Code: CodeSolveFailed,
				Message:            "The challenge could not be solved. The failure was logged for us to look into.",
				ChallengeVariantID: "variant-7f3a"},
		},
		{
			target: "shape-debug-without-stage", status: http.StatusBadRequest,
			body: `{"success":false,"error":{"code":"invalid_request","message":"bad"},"debug":{}}`,
			want: APIError{Status: 400, Code: CodeInvalidRequest, Message: "bad"},
		},
		{
			target: "datadome", status: http.StatusBadRequest,
			body: `{"error":{"code":"invalid_session","message":"session_id is unknown or expired"},"success":false}`,
			want: APIError{Status: 400, Code: CodeInvalidSession, Message: "session_id is unknown or expired"},
		},
		{
			target: "datadome-rate-limited", status: http.StatusTooManyRequests,
			header: http.Header{
				"Retry-After":           {"7"},
				"X-Ratelimit-Limit":     {"100"},
				"X-Ratelimit-Remaining": {"0"},
				"X-Ratelimit-Reset":     {"1800000000"},
			},
			body: `{"error":{"code":"rate_limited","message":"too many requests for this account; slow down and retry after the Retry-After seconds"},"success":false}` + "\n",
			want: APIError{Status: 429, Code: CodeRateLimited,
				Message: "too many requests for this account; slow down and retry after the Retry-After seconds",
				RateLimit: RateLimit{Limit: 100, Remaining: 0,
					Reset: time.Unix(1_800_000_000, 0).UTC(), RetryAfter: 7 * time.Second}},
		},
		{
			target: "cloudflare", status: http.StatusGatewayTimeout,
			body: `{"success":false,"error":{"code":"solve_timeout","message":"context deadline exceeded"}}` + "\n",
			want: APIError{Status: 504, Code: CodeSolveTimeout, Message: "context deadline exceeded"},
		},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			server, _ := testServer(t, test.status, test.body, test.header)
			client := newTestClient(t, Config{BaseURL: server.URL, MaxRetries: new(0)})
			limit, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &struct{}{})
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %v, want *APIError", err)
			}
			want := test.want
			want.Attempts = 1 // retries are disabled, so every failure is the first answer
			if *apiErr != want {
				t.Fatalf("APIError = %#v\nwant       %#v", *apiErr, want)
			}
			if limit != test.want.RateLimit {
				t.Fatalf("returned RateLimit = %+v, want the error's %+v", limit, test.want.RateLimit)
			}
		})
	}
}

func TestErrorEnvelopeEncodesCurrentWire(t *testing.T) {
	tests := []struct {
		body ErrorBody
		want string
	}{
		{
			ErrorBody{Code: "invalid_request", Message: "session_id is invalid"},
			`{"success":false,"error":{"code":"invalid_request","message":"session_id is invalid"}}`,
		},
		{
			ErrorBody{Code: "solve_failed", Message: "failed", ChallengeVariantID: "variant-7f3a"},
			`{"success":false,"error":{"code":"solve_failed","message":"failed","challenge_variant_id":"variant-7f3a"}}`,
		},
	}
	for _, test := range tests {
		got, err := json.Marshal(ErrorEnvelope{Error: test.body})
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != test.want {
			t.Fatalf("ErrorEnvelope = %s, want %s", got, test.want)
		}
	}
}

func TestParseRateLimit(t *testing.T) {
	now := time.Date(2027, time.January, 15, 7, 58, 30, 0, time.UTC)
	tests := []struct {
		name      string
		header    http.Header
		want      RateLimit
		badHeader string
	}{
		{name: "absent", header: http.Header{}, want: RateLimit{}},
		{
			name: "quota headers on success",
			header: http.Header{
				"X-Ratelimit-Limit":     {"5000"},
				"X-Ratelimit-Remaining": {"4999"},
				"X-Ratelimit-Reset":     {"1800003600"},
			},
			want: RateLimit{Limit: 5000, Remaining: 4999, Reset: time.Unix(1_800_003_600, 0).UTC()},
		},
		{
			name:   "retry-after alone",
			header: http.Header{"Retry-After": {"30"}},
			want:   RateLimit{RetryAfter: 30 * time.Second},
		},
		{
			name:   "http-date retry-after is the delay from now",
			header: http.Header{"Retry-After": {"Fri, 15 Jan 2027 08:00:00 GMT"}},
			want:   RateLimit{RetryAfter: 90 * time.Second},
		},
		{
			name:   "past http-date retry-after is no delay",
			header: http.Header{"Retry-After": {"Fri, 15 Jan 2027 07:00:00 GMT"}},
			want:   RateLimit{},
		},
		{
			name:   "zero remaining is reported, not treated as absent",
			header: http.Header{"X-Ratelimit-Limit": {"10"}, "X-Ratelimit-Remaining": {"0"}},
			want:   RateLimit{Limit: 10},
		},
		{name: "non-integer limit", header: http.Header{"X-Ratelimit-Limit": {"ten"}}, badHeader: "X-RateLimit-Limit"},
		{name: "fractional remaining", header: http.Header{"X-Ratelimit-Remaining": {"1.5"}}, badHeader: "X-RateLimit-Remaining"},
		{name: "rfc3339 reset", header: http.Header{"X-Ratelimit-Reset": {"2027-01-15T08:00:00Z"}}, badHeader: "X-RateLimit-Reset"},
		{name: "rfc3339 retry-after", header: http.Header{"Retry-After": {"2027-01-15T08:00:00Z"}}, badHeader: "Retry-After"},
		{name: "fractional retry-after", header: http.Header{"Retry-After": {"1.5"}}, badHeader: "Retry-After"},
		{name: "negative retry-after", header: http.Header{"Retry-After": {"-1"}}, badHeader: "Retry-After"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseRateLimit(fhttp.Header(test.header), now)
			if test.badHeader != "" {
				var headerErr *HeaderError
				if !errors.As(err, &headerErr) || headerErr.Header != test.badHeader {
					t.Fatalf("error = %v, want *HeaderError on %s", err, test.badHeader)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("RateLimit = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestCallReturnsRateLimitOnSuccess(t *testing.T) {
	server, _ := testServer(t, http.StatusOK, `{}`, http.Header{
		"X-Ratelimit-Limit": {"3"}, "X-Ratelimit-Remaining": {"2"}, "X-Ratelimit-Reset": {"1800000060"},
	})
	client := newTestClient(t, Config{BaseURL: server.URL})
	limit, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if want := (RateLimit{Limit: 3, Remaining: 2, Reset: time.Unix(1_800_000_060, 0).UTC()}); limit != want {
		t.Fatalf("RateLimit = %+v, want %+v", limit, want)
	}
}

func TestCallFailsClosedOnMalformedRateLimitHeader(t *testing.T) {
	server, _ := testServer(t, http.StatusOK, `{}`, http.Header{"X-Ratelimit-Remaining": {"many"}})
	client := newTestClient(t, Config{BaseURL: server.URL})
	_, err := client.Call(context.Background(), http.MethodPost, "/solve", map[string]string{}, &struct{}{})
	var headerErr *HeaderError
	if !errors.As(err, &headerErr) || headerErr.Value != "many" {
		t.Fatalf("error = %v, want *HeaderError for the malformed value", err)
	}
}
