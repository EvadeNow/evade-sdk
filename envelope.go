package evade

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// ErrorEnvelope is the body every solve server writes on a non-2xx response.
type ErrorEnvelope struct {
	Success bool      `json:"success"`
	Error   ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code               string `json:"code"`
	Message            string `json:"message"`
	ChallengeVariantID string `json:"challenge_variant_id,omitempty"` // shape only
}

// Code is ErrorBody.Code. The catalog is the solvers' shared one (the
// storage.ErrorCodes list, in its order: caller codes, then ours); each
// constant's comment names the targets whose /solve, /user-agents or
// /solve/outcome answer it today. "every target" is recaptcha, shape,
// datadome, akamai and cloudflare. Akamai's own /solve failures are not
// this envelope (see akamai.ErrorResponse); only its auth, quota and
// /user-agents refusals are.
type Code string

// Caller codes: the request, the key, the session, the proxy or the target
// site; the caller fixes or retries them away.
const (
	CodeInvalidRequest    Code = "invalid_request"    // recaptcha, shape, datadome, cloudflare
	CodeMethodNotAllowed  Code = "method_not_allowed" // cloudflare
	CodeMissingAPIKey     Code = "missing_api_key"    // every target
	CodeInvalidAPIKey     Code = "invalid_api_key"    // every target
	CodeInsufficientScope Code = "insufficient_scope" // every target
	CodeQuotaExceeded     Code = "quota_exceeded"     // every target
	CodeRateLimited       Code = "rate_limited"       // every target; Retry-After is set
	CodeSessionExpired    Code = "session_expired"    // shape, datadome: the session is unknown, evicted or expired
	CodeSessionBusy       Code = "session_busy"       // shape
	CodeSendTooEarly      Code = "send_too_early"     // shape
	CodeSendTooLate       Code = "send_too_late"      // shape
	CodeProxyFailed       Code = "proxy_failed"       // recaptcha, shape, cloudflare
	CodeProxyTimeout      Code = "proxy_timeout"      // recaptcha, shape, cloudflare
	CodeTargetError       Code = "target_error"       // recaptcha, shape
	CodeSolveCanceled     Code = "solve_canceled"     // recaptcha, shape, datadome, cloudflare
	CodeSolveNotFound     Code = "solve_not_found"    // shape /solve/outcome
)

// Our codes: only a change to the solver, its data or its infrastructure
// fixes them; the *_unavailable ones and challenge_rotating clear on retry.
const (
	CodeChallengeUnsupported Code = "challenge_unsupported" // shape, datadome, cloudflare
	CodeChallengeRotating    Code = "challenge_rotating"    // datadome
	CodeDeviceUnsupported    Code = "device_unsupported"    // recaptcha, shape, datadome, cloudflare
	CodeSiteUnsupported      Code = "site_unsupported"      // recaptcha, shape, cloudflare
	CodeGenerationFailed     Code = "generation_failed"     // recaptcha, shape, datadome, cloudflare
	CodeSolveTimeout         Code = "solve_timeout"         // shape, datadome, cloudflare
	CodeStorageUnavailable   Code = "storage_unavailable"   // every target
	CodeAuthUnavailable      Code = "auth_unavailable"      // cloudflare
	CodeQuotaUnavailable     Code = "quota_unavailable"     // every target
	CodeUsageUnavailable     Code = "usage_unavailable"     // shape, datadome
	CodeOutcomesUnavailable  Code = "outcomes_unavailable"  // shape /solve/outcome
	CodeServerBusy           Code = "server_busy"           // in the catalog; no target answers it yet
	CodeInternalError        Code = "internal_error"        // shape, datadome, cloudflare
)

// reCAPTCHA codes outside the shared catalog.
const (
	CodeSolveFailed       Code = "solve_failed"       // recaptcha: a failure no other code classifies
	CodeChallenged        Code = "challenged"         // recaptcha: the server demanded a challenge the flow has no solver for
	CodeChallengeUnsolved Code = "challenge_unsolved" // recaptcha: the image challenge was not solved
)

// APIError is a non-2xx response. When the body is not an ErrorEnvelope,
// Code is empty and Message holds the raw body. Attempts counts the requests
// Call sent, so above 1 the 429/503 answers were already retried and
// retrying again at once only adds load.
type APIError struct {
	Status             int
	Code               Code
	Message            string
	ChallengeVariantID string
	RateLimit          RateLimit
	Attempts           int
}

func (e *APIError) Error() string {
	var text string
	switch {
	case e.Code == "":
		text = fmt.Sprintf("evade: %d: %s", e.Status, e.Message)
	default:
		text = fmt.Sprintf("evade: %d %s: %s", e.Status, e.Code, e.Message)
	}
	if e.Attempts > 1 {
		text += fmt.Sprintf(" (after %d attempts)", e.Attempts)
	}
	return text
}

// RateLimit is the X-RateLimit-*/Retry-After state. A zero value means no
// limit was reported, not that no quota is left.
type RateLimit struct {
	Limit, Remaining int64
	Reset            time.Time
	RetryAfter       time.Duration
}

// HeaderError reports a malformed rate-limit header; the call fails rather
// than report a guessed quota.
type HeaderError struct {
	Header string
	Value  string
	Err    error
}

func (e *HeaderError) Error() string {
	return fmt.Sprintf("evade: header %s=%q: %v", e.Header, e.Value, e.Err)
}

func (e *HeaderError) Unwrap() error { return e.Err }

// Retry-After is integer seconds from the solve servers, but a proxy or load
// balancer in front of them may send an HTTP-date; a date already past is a
// zero delay.
func parseRateLimit(h http.Header, now time.Time) (RateLimit, error) {
	var limit RateLimit
	var err error
	if limit.Limit, err = headerInt(h, "X-RateLimit-Limit"); err != nil {
		return RateLimit{}, err
	}
	if limit.Remaining, err = headerInt(h, "X-RateLimit-Remaining"); err != nil {
		return RateLimit{}, err
	}
	reset, err := headerInt(h, "X-RateLimit-Reset")
	if err != nil {
		return RateLimit{}, err
	}
	if h.Get("X-RateLimit-Reset") != "" {
		limit.Reset = time.Unix(reset, 0).UTC()
	}
	raw := h.Get("Retry-After")
	if raw == "" {
		return limit, nil
	}
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if seconds < 0 {
			return RateLimit{}, &HeaderError{Header: "Retry-After", Value: raw, Err: errors.New("negative delay")}
		}
		limit.RetryAfter = time.Duration(seconds) * time.Second
		return limit, nil
	}
	date, err := http.ParseTime(raw)
	if err != nil {
		return RateLimit{}, &HeaderError{Header: "Retry-After", Value: raw,
			Err: errors.New("neither delay-seconds nor an HTTP-date")}
	}
	limit.RetryAfter = max(date.Sub(now), 0)
	return limit, nil
}

func headerInt(h http.Header, name string) (int64, error) {
	raw := h.Get(name)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, &HeaderError{Header: name, Value: raw, Err: err}
	}
	return value, nil
}
