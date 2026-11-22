package recaptcha

import (
	"context"
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

// Solve runs the whole reCAPTCHA flow on the server (loader, release,
// anchor, reload, clr, bcn; the v2 invisible bframe and userverify, an
// image challenge solved server-side) over r.Proxy as r.UserAgent and
// answers the token synchronously. A refusal is an *evade.APIError with
// its code: invalid_request, device_unsupported, site_unsupported,
// generation_failed, challenged (the server demanded a challenge the flow
// has no solver for), challenge_unsolved, storage_unavailable, proxy_failed,
// proxy_timeout, target_error, solve_canceled, solve_failed, and the auth
// and quota codes (rate_limited carries Retry-After).
func Solve(ctx context.Context, c *evade.Client, r Request) (Response, error) {
	var response Response
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wireRequest{Task: Task, Request: r}, &response); err != nil {
		return Response{}, err
	}
	return response, nil
}
