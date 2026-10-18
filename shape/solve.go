package shape

import (
	"context"
	"net/http"
	"net/url"

	evade "github.com/EvadeNow/evade-sdk"
)

const Task = "shape"

type wireRequest struct {
	Task string `json:"task"`
	Request
}

// Solve fails with *evade.APIError; a solve_failed may carry ChallengeVariantID,
// and a Debug request's failure carries the typed evade.Stop.
func Solve(ctx context.Context, c *evade.Client, r Request) (Response, error) {
	var response Response
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wireRequest{Task: Task, Request: r}, &response); err != nil {
		return Response{}, err
	}
	return response, nil
}

// CloseSession succeeds even if the session is already closed or unknown.
func CloseSession(ctx context.Context, c *evade.Client, sessionID string) error {
	_, err := c.Call(ctx, http.MethodDelete, "/solve/session/"+url.PathEscape(sessionID), nil, evade.NoContent{})
	return err
}

// ReportOutcome records r on its solve; repeated reports replace earlier ones.
// Report after the target has responded: a solve is recorded asynchronously,
// so a 404 solve_not_found shortly after Solve may clear on retry.
func ReportOutcome(ctx context.Context, c *evade.Client, r OutcomeReport) (*OutcomeResponse, error) {
	var response OutcomeResponse
	if _, err := c.Call(ctx, http.MethodPost, "/solve/outcome", r, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
