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

// Solve validates r, then runs the reCAPTCHA flow through r.Proxy as the
// full supported r.UserAgent and returns the token in one HTTP response.
// The server's clr/bcn telemetry can finish after that response. Visible
// image challenges are refused; the public route attaches no image solver.
// Submit the token where the page does, from the same proxy exit as the
// same UserAgent, promptly and only once (normally within two minutes).
// Issuance does not establish site acceptance or a Google-verified score.
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
//   - site_unsupported: an unsupported widget or page law; not proof
//     that switching versions is correct;
//   - generation_failed: the token failed the solver's own decode or came
//     out short;
//   - challenged, challenge_unsupported: a challenge the public flow
//     does not support; challenge_unsolved is also a recognized server code;
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
