package recaptcha

import (
	"context"
	"net/http"

	evade "github.com/EvadeNow/evade-sdk"
)

type wireRequest struct {
	Task Task `json:"task"`
	Request
}

// Solve runs the whole v3 flow on the server (page, loader, release,
// anchor, reload, clr, bcn) over r.Proxy as r.UserAgent and answers the
// token synchronously. A refusal is an *evade.APIError with its catalog
// code: invalid_request, device_unsupported, site_unsupported,
// generation_failed, proxy_failed, proxy_timeout, target_error,
// solve_canceled, solve_failed, and the auth and quota codes
// (rate_limited carries Retry-After).
func Solve(ctx context.Context, c *evade.Client, task Task, r Request) (Response, error) {
	var response Response
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wireRequest{Task: task, Request: r}, &response); err != nil {
		return Response{}, err
	}
	return response, nil
}
