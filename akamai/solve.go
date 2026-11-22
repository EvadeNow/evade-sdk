package akamai

import (
	"context"
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

// SolveSensor, SolveSBSD and Open fail with *evade.APIError: auth and quota
// refusals carry its Code, /solve's own failures an ErrorResponse body in
// Message.
func SolveSensor(ctx context.Context, c *evade.Client, r SensorRequest) (SensorResponse, error) {
	return solve[SensorResponse](ctx, c, sensorWire{Task: Task, Mode: ModeSensor, SensorRequest: r})
}

func SolveSBSD(ctx context.Context, c *evade.Client, r SBSDRequest) (SBSDResponse, error) {
	return solve[SBSDResponse](ctx, c, sbsdWire{Task: Task, Mode: ModeSBSD, SBSDRequest: r})
}

// Open opens a session without a post, or stages a script on one; it is
// not billed (its 201 is not a solve).
func Open(ctx context.Context, c *evade.Client, r OpenRequest) (OpenResponse, error) {
	return solve[OpenResponse](ctx, c, openWire{Task: Task, Mode: ModeOpen, OpenRequest: r})
}

func solve[T SensorResponse | SBSDResponse | OpenResponse](ctx context.Context, c *evade.Client, wire any) (T, error) {
	var response T
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wire, &response); err != nil {
		var zero T
		return zero, err
	}
	return response, nil
}
