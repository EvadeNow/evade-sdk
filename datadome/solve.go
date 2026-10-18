package datadome

import (
	"context"
	"net/http"

	evade "github.com/EvadeNow/evade-sdk"
)

const Task = "datadome"

// One wire struct per stage: Go cannot embed a type parameter.
type (
	tagsWire struct {
		Task string `json:"task"`
		Mode Mode   `json:"mode"`
		TagsRequest
	}
	interstitialWire struct {
		Task string `json:"task"`
		Mode Mode   `json:"mode"`
		InterstitialRequest
	}
	captchaWire struct {
		Task string `json:"task"`
		Mode Mode   `json:"mode"`
		CaptchaRequest
	}
)

func SolveTags(ctx context.Context, c *evade.Client, r TagsRequest) (TagsResponse, error) {
	return solve[TagsResponse](ctx, c, tagsWire{Task: Task, Mode: ModeTags, TagsRequest: r})
}

func SolveInterstitial(ctx context.Context, c *evade.Client, r InterstitialRequest) (InterstitialResponse, error) {
	return solve[InterstitialResponse](ctx, c,
		interstitialWire{Task: Task, Mode: ModeInterstitial, InterstitialRequest: r})
}

func SolveCaptcha(ctx context.Context, c *evade.Client, r CaptchaRequest) (CaptchaResponse, error) {
	return solve[CaptchaResponse](ctx, c, captchaWire{Task: Task, Mode: ModeCaptcha, CaptchaRequest: r})
}

func solve[T TagsResponse | InterstitialResponse | CaptchaResponse](ctx context.Context, c *evade.Client, wire any) (T, error) {
	var response T
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wire, &response); err != nil {
		var zero T
		return zero, err
	}
	return response, nil
}
