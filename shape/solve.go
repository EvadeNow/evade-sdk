package shape

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"unicode/utf8"

	evade "github.com/EvadeNow/evade-sdk"
)

const Task = "shape"

type wireRequest struct {
	Task string `json:"task"`
	Request
}

// Solve fails with *evade.APIError; a solve_failed may carry ChallengeVariantID,
// and a Debug request's failure carries the typed evade.Stop. A source body
// JSON cannot carry byte for byte fails with *NotUTF8Error before any request.
func Solve(ctx context.Context, c *evade.Client, r Request) (Response, error) {
	for _, source := range [...]struct{ field, body string }{
		{"page_html", r.PageHTML}, {"loader_source", r.LoaderSource}, {"challenge_source", r.ChallengeSource},
	} {
		if !utf8.ValidString(source.body) {
			return Response{}, &NotUTF8Error{Field: source.field, Offset: invalidUTF8Offset(source.body)}
		}
	}
	var response Response
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wireRequest{Task: Task, Request: r}, &response); err != nil {
		return Response{}, err
	}
	return response, nil
}

// NotUTF8Error is a source body (page_html, loader_source,
// challenge_source) holding a byte that is not UTF-8. JSON text is UTF-8,
// so the encoder would replace the byte and the solver would read another
// body than the browser received; Solve refuses it instead. A page served
// in another charset must be sent as the text the browser decoded, which
// is the same bytes only when they are all ASCII.
type NotUTF8Error struct {
	Field  string
	Offset int // the first invalid byte
}

func (e *NotUTF8Error) Error() string {
	return fmt.Sprintf("shape: %s is not valid UTF-8 at byte %d: JSON cannot carry it byte for byte", e.Field, e.Offset)
}

func invalidUTF8Offset(s string) int {
	for i, r := range s {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				return i
			}
		}
	}
	return len(s)
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
