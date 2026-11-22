package recaptcha

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	evade "github.com/EvadeNow/evade-sdk"
)

// Task is the solver's one task name: the widget and surface are Request
// fields (Version, Enterprise), never the name.
const Task = "recaptcha"

type wireRequest struct {
	Task string `json:"task"`
	Request
}

// Solve validates r (Request.Validate), then runs the whole reCAPTCHA flow
// on the server (loader, release, anchor, reload, clr, bcn; the v2
// invisible bframe and userverify, an image challenge solved server-side)
// over r.Proxy as r.UserAgent and answers the token synchronously. Submit
// the token where the page does (the g-recaptcha-response form field, or
// the header or JSON member the page's own call carries) from the same
// proxy exit as the same UserAgent, within the token's two-minute life.
// A refusal is an *Error.
func Solve(ctx context.Context, c *evade.Client, r Request) (Response, error) {
	if err := r.Validate(); err != nil {
		return Response{}, err
	}
	var response Response
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wireRequest{Task: Task, Request: r}, &response); err != nil {
		var api *evade.APIError
		if !errors.As(err, &api) {
			return Response{}, err
		}
		failure := &Error{Status: api.Status, Code: api.Code, Message: api.Message, api: api}
		switch failure.Code {
		case evade.CodeProxyFailed, evade.CodeProxyTimeout, evade.CodeStorageUnavailable, evade.CodeQuotaUnavailable, evade.CodeRateLimited:
			failure.Retryable = true
		}
		return Response{}, failure
	}
	return response, nil
}

// Error is every refusal Solve returns. Code is the server's:
//   - invalid_request: a malformed field (Validate raises the server's own
//     refusals before any request, with Status 0), an unknown version or
//     host, a non-boolean enterprise;
//   - device_unsupported: no stored device for UserAgent;
//   - site_unsupported: the page's widget or loader is not one the solver
//     runs, or PageScripts is missing;
//   - generation_failed: the token failed the solver's own decode or came
//     out short;
//   - challenged: Google demanded a challenge the flow has no solver for;
//   - challenge_unsolved: the image challenge was not solved;
//   - proxy_failed, proxy_timeout: the proxy could not carry the flow;
//   - target_error: a Google endpoint answered an unexpected status;
//   - solve_canceled, solve_failed, storage_unavailable, and the shared
//     auth and quota codes (rate_limited carries RateLimit.RetryAfter on
//     the unwrapped *evade.APIError).
//
// Retryable means another solve may succeed (proxy_failed and
// proxy_timeout with a fresh proxy endpoint, storage_unavailable,
// quota_unavailable, rate_limited); a challenge or a refused request is
// never retried. Error unwraps to the *evade.APIError of a server refusal.
type Error struct {
	Status    int
	Code      evade.Code
	Message   string
	Retryable bool
	api       *evade.APIError
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("recaptcha: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("recaptcha: %d %s: %s", e.Status, e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	if e.api == nil {
		return nil
	}
	return e.api
}
