package cloudflare

import (
	"context"
	"net/http"

	evade "github.com/EvadeNow/evade-sdk"
)

const Task = "cloudflare"

type wireRequest struct {
	Task string `json:"task"`
	Request
}

// Solve reports solve_failed as an HTTP 502 *evade.APIError.
func Solve(ctx context.Context, c *evade.Client, r Request) (Response, error) {
	var response Response
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wireRequest{Task: Task, Request: r}, &response); err != nil {
		return Response{}, err
	}
	return response, nil
}
