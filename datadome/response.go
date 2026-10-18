package datadome

type TagsResponse struct {
	Payload   string `json:"payload"` // form body for DataDome's /js/ endpoint
	SessionID string `json:"session_id"`
	// ExpiresInSeconds, ClientHints and DeviceMemory are sent only by the session-opening solve.
	ExpiresInSeconds int64        `json:"expires_in_seconds,omitempty"`
	ClientHints      *ClientHints `json:"client_hints,omitempty"`
	DeviceMemory     int          `json:"device_memory,omitempty"` // -1 when the browser does not expose it
}

// ClientHints are the pinned fingerprint's UA client hints; the caller's requests must match them.
type ClientHints struct {
	Architecture    string `json:"architecture"`
	Bitness         string `json:"bitness"`
	Mobile          bool   `json:"mobile"`
	Model           string `json:"model"`
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platformVersion"`
	UAFullVersion   string `json:"uaFullVersion"`
	Wow64           bool   `json:"wow64"`
}

type InterstitialResponse struct {
	Payload string `json:"payload"` // form body for the device-check endpoint
	// Headers are the sec-ch-* headers the submission must carry; empty for Safari and Firefox.
	Headers map[string]string `json:"headers"`
}

type CaptchaResponse struct {
	Payload string            `json:"payload"` // captcha check URL to request
	Headers map[string]string `json:"headers"` // as InterstitialResponse.Headers
}
