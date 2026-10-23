package evade

import (
	"encoding/json"
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
	Debug   *Stop     `json:"debug,omitempty"` // shape, debug requests only
}

type ErrorBody struct {
	Code               string `json:"code"`
	Message            string `json:"message"`
	ChallengeVariantID string `json:"challenge_variant_id,omitempty"` // shape only
}

// Stop is the typed stop a Shape debug request's error body carries: where
// the solve stopped and why. Stage and Reason are stable, machine-readable
// names; Label and Field name the law or parameter a generation stopped on.
type Stop struct {
	Stage              string              `json:"stage"`
	Reason             string              `json:"reason"`
	Label              string              `json:"label,omitempty"`
	Field              string              `json:"field,omitempty"`
	Detail             string              `json:"detail"`
	ExtractionFailures []ExtractionFailure `json:"extraction_failures,omitempty"`
	// Partial is the solve's result as far as it got, undecoded: its
	// members are the target's own diagnostics.
	Partial json.RawMessage `json:"partial,omitempty"`
	// Internal marks the server's own bug (500), Upstream a failing proxy
	// or target (503); neither is a deterministic refusal.
	Internal bool `json:"internal,omitempty"`
	Upstream bool `json:"upstream,omitempty"`
	NotFound bool `json:"not_found,omitempty"` // stored evidence is absent
	// NotBeforeUnixMS is the earliest instant a session continuation sent
	// too early (Reason send_too_early) may be sent again.
	NotBeforeUnixMS float64 `json:"not_before_unix_ms,omitempty"`
}

// ExtractionFailure is one fail-closed extractor class of the challenge build.
type ExtractionFailure struct {
	Class  string `json:"class"`
	Param  string `json:"param"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Code is ErrorBody.Code; each constant's comment names the targets that emit it.
type Code string

const (
	CodeMissingAPIKey     Code = "missing_api_key"    // shape, datadome
	CodeInvalidAPIKey     Code = "invalid_api_key"    // shape, datadome
	CodeInsufficientScope Code = "insufficient_scope" // shape, datadome
	CodeRateLimited       Code = "rate_limited"       // shape, datadome; Retry-After is set
	CodeQuotaExceeded     Code = "quota_exceeded"     // shape, datadome
	CodeQuotaUnavailable  Code = "quota_unavailable"  // shape, datadome
	CodeUsageUnavailable  Code = "usage_unavailable"  // shape
	CodeAuthUnavailable   Code = "auth_unavailable"   // cloudflare
)

const (
	CodeMethodNotAllowed   Code = "method_not_allowed"  // cloudflare
	CodeSolverUnavailable  Code = "solver_unavailable"  // cloudflare
	CodeInvalidRequest     Code = "invalid_request"     // shape, datadome, cloudflare
	CodeBadRequest         Code = "bad_request"         // datadome
	CodeSolveFailed        Code = "solve_failed"        // shape, cloudflare
	CodeSolveTimeout       Code = "solve_timeout"       // shape, cloudflare
	CodeSolveCanceled      Code = "solve_canceled"      // shape, cloudflare
	CodeSessionUnavailable Code = "session_unavailable" // shape, datadome
)

// DataDome solve codes.
const (
	CodeInvalidSession             Code = "invalid_session"
	CodeSessionFailed              Code = "session_failed"
	CodeInterstitialFailed         Code = "interstitial_failed"
	CodeCaptchaFailed              Code = "captcha_failed"
	CodeFingerprintSelectionFailed Code = "fingerprint_selection_failed"
	CodePicassoSelectionFailed     Code = "picasso_selection_failed"
)

// APIError is a non-2xx response. When the body is not an ErrorEnvelope,
// Code is empty and Message holds the raw body. Stop is the envelope's typed
// debug stop, nil when the body carries none. Attempts counts the requests
// Call sent, so above 1 the 429/503 answers were already retried and
// retrying again at once only adds load.
type APIError struct {
	Status             int
	Code               Code
	Message            string
	ChallengeVariantID string
	Stop               *Stop
	RateLimit          RateLimit
	Attempts           int
}

func (e *APIError) Error() string {
	var text string
	switch {
	case e.Stop != nil:
		where := e.Stop.Stage + "/" + e.Stop.Reason
		if e.Stop.Label != "" {
			where += " label=" + e.Stop.Label
		}
		if e.Stop.Field != "" {
			where += " field=" + e.Stop.Field
		}
		text = fmt.Sprintf("evade: %d %s: %s: %s", e.Status, e.Code, where, e.Stop.Detail)
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
