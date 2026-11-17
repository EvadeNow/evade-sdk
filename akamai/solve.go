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
)

// SolveSensor and SolveSBSD fail with *evade.APIError: auth and quota
// refusals carry its Code, /solve's own failures an ErrorResponse body in
// Message.
func SolveSensor(ctx context.Context, c *evade.Client, r SensorRequest) (SensorResponse, error) {
	return solve[SensorResponse](ctx, c, sensorWire{Task: Task, Mode: ModeSensor, SensorRequest: r})
}

func SolveSBSD(ctx context.Context, c *evade.Client, r SBSDRequest) (SBSDResponse, error) {
	return solve[SBSDResponse](ctx, c, sbsdWire{Task: Task, Mode: ModeSBSD, SBSDRequest: r})
}

func solve[T SensorResponse | SBSDResponse](ctx context.Context, c *evade.Client, wire any) (T, error) {
	var response T
	if _, err := c.Call(ctx, http.MethodPost, "/solve", wire, &response); err != nil {
		var zero T
		return zero, err
	}
	return response, nil
}
