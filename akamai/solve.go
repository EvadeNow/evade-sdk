package akamai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	evade "github.com/EvadeNow/evade-sdk"
)

const Task = "akamai"

// One wire struct per mode: Go cannot embed a type parameter.
type (
	sensorWire struct {
		Task string `json:"task"`
		Mode Mode   `json:"mode"`
		SensorRequest
	}
	sbsdWire struct {
		Task string `json:"task"`
		Mode Mode   `json:"mode"`
		SBSDRequest
	}
	openWire struct {
		Task string `json:"task"`
		Mode Mode   `json:"mode"`
		OpenRequest
	}
)

// SolveSensor, SolveSBSD and SolveOpen are the raw /solve calls; Session
// drives them in the order a page sends its posts. A refusal is an *Error.
func SolveSensor(ctx context.Context, c *evade.Client, r SensorRequest) (SensorResponse, error) {
	return solve[SensorResponse](ctx, c, sensorWire{Task: Task, Mode: ModeSensor, SensorRequest: r})
}

func SolveSBSD(ctx context.Context, c *evade.Client, r SBSDRequest) (SBSDResponse, error) {
	return solve[SBSDResponse](ctx, c, sbsdWire{Task: Task, Mode: ModeSBSD, SBSDRequest: r})
}

// SolveOpen opens a session without a post, or stages a script on one; it
// is not billed (its 201 is not a solve).
func SolveOpen(ctx context.Context, c *evade.Client, r OpenRequest) (OpenResponse, error) {
	return solve[OpenResponse](ctx, c, openWire{Task: Task, Mode: ModeOpen, OpenRequest: r})
}

func solve[T SensorResponse | SBSDResponse | OpenResponse](ctx context.Context, c *evade.Client, wire any) (T, error) {
	var response T
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wire, &response); err != nil {
		var zero T
		return zero, typed(err)
	}
	return response, nil
}

// The /solve error codes (error_code). Auth and quota refusals carry the
// shared evade.Code* values instead.
const (
	CodeInvalidJSON          evade.Code = "invalid_json"
	CodeInvalidTask          evade.Code = "invalid_task"
	CodeInvalidMode          evade.Code = "invalid_mode"
	CodeInvalidRequest       evade.Code = "invalid_request"
	CodeInvalidScriptID      evade.Code = "invalid_script_id"
	CodeMissingScript        evade.Code = "missing_script"
	CodeScriptIDMismatch     evade.Code = "script_id_mismatch"
	CodeScriptTooLarge       evade.Code = "script_too_large"
	CodePayloadTooLarge      evade.Code = "payload_too_large"
	CodeScriptCacheMiss      evade.Code = "script_cache_miss" // resend with the script source (Session does)
	CodeExitRegionMissing    evade.Code = "exit_region_missing"
	CodeInvalidLocale        evade.Code = "invalid_locale"
	CodeInvalidSession       evade.Code = "invalid_session" // unknown or expired, or the request disagrees with it: open a new one
	CodeUnsupportedUserAgent evade.Code = "unsupported_user_agent"
	CodeUnsupportedScript    evade.Code = "unsupported_script"
	CodeDeviceUnavailable    evade.Code = "device_unavailable"
	CodeDeviceUncovered      evade.Code = "device_uncovered"
	CodeDeviceIncomplete     evade.Code = "device_incomplete"
	CodeDeviceHiddenTab      evade.Code = "device_hidden_tab"
	CodeInputTriggerMissing  evade.Code = "input_trigger_missing"
	CodeRequestCancelled     evade.Code = "request_cancelled"
	// CodeSendInstantPassed: the post's trigger instant passed before the
	// request arrived; the session cannot send it any more.
	CodeSendInstantPassed evade.Code = "send_instant_passed"
	// The 409 telemetry answers; Reason says which. Session.SBSDTelemetry
	// returns *Done for the complete and not-due ones.
	CodeTelemetryNeedsFingerprint evade.Code = "sbsd_telemetry_needs_fingerprint"
	CodeTelemetryComplete         evade.Code = "sbsd_telemetry_complete"
	CodeTelemetryNotDue           evade.Code = "sbsd_telemetry_not_due"
	CodeInternalError             evade.Code = "internal_error"
)

// Error is every refusal a call returns. Code is /solve's error_code, or
// the shared envelope's code for auth and quota refusals; Stage names the
// server stage that refused, and Reason is set by the 409 telemetry
// answers (complete, no_input, second_post_input, no_fingerprint).
// Retryable means the same call may succeed later (device_unavailable,
// request_cancelled, rate_limited, storage_unavailable,
// quota_unavailable); the client already retried 429 and 503 answers as
// evade.Config allows. Error unwraps to the *evade.APIError carrying the
// status and rate limit.
type Error struct {
	Status    int
	Code      evade.Code
	Message   string
	Stage     string
	Reason    string
	Retryable bool
	api       *evade.APIError
}

func (e *Error) Error() string {
	text := fmt.Sprintf("akamai: %d %s", e.Status, e.Code)
	if e.Stage != "" {
		text += " at " + e.Stage
	}
	if e.Reason != "" {
		text += " (" + e.Reason + ")"
	}
	if e.Message != "" {
		text += ": " + e.Message
	}
	return text
}

func (e *Error) Unwrap() error { return e.api }

// typed turns an *evade.APIError into an *Error: /solve's own body
// (error_code) is not the shared envelope, so it arrives whole in Message.
func typed(err error) error {
	var api *evade.APIError
	if !errors.As(err, &api) {
		return err
	}
	failure := &Error{Status: api.Status, Code: api.Code, Message: api.Message, api: api}
	if failure.Code == "" {
		var body struct {
			ErrorCode string `json:"error_code"`
			Message   string `json:"message"`
			Stage     string `json:"stage"`
			Reason    string `json:"reason"`
		}
		if json.Unmarshal([]byte(api.Message), &body) != nil || body.ErrorCode == "" {
			return err
		}
		failure.Code, failure.Message, failure.Stage, failure.Reason = evade.Code(body.ErrorCode), body.Message, body.Stage, body.Reason
	}
	switch failure.Code {
	case CodeDeviceUnavailable, CodeRequestCancelled, evade.CodeRateLimited, evade.CodeStorageUnavailable, evade.CodeQuotaUnavailable:
		failure.Retryable = true
	}
	return failure
}
