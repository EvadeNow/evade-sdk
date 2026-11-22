package akamai

type SensorResponse struct {
	Success    bool   `json:"success"`
	SensorData string `json:"sensor_data"` // the sensor post's sensor_data value
	UA         string `json:"ua"`
	Session    string `json:"session"`
	Language   string `json:"language"` // the device's Accept-Language header value
	// AcceptEncoding is the device's Accept-Encoding header value, the
	// one transport.NewBrowser binds for UA.
	AcceptEncoding string `json:"accept_encoding"`
	ScriptID       string `json:"script_id"`
	// ClientHints are the device's UA-CH header values; the caller's
	// requests must carry them.
	ClientHints ClientHints `json:"client_hints"`
	Telemetry   string      `json:"telemetry,omitempty"` // a=...&&&e=...&&&sensor_data=<base64>, when asked
	PacedMS     int64       `json:"paced_ms,omitempty"`  // how long Pace held the post
}

// ClientHints are keyed by header name; each value is the header's own:
// sec-ch-ua, -mobile, -platform, -platform-version, -arch, -bitness, -model,
// -full-version-list and -wow64 byte-exact as Chrome sends them
// (transport.ClientHints.Values), and -full-version and -form-factors.
// Every value is empty on an engine without UA-CH, which sends none.
type ClientHints struct {
	UA              string `json:"sec-ch-ua"`
	Mobile          string `json:"sec-ch-ua-mobile"`
	FullVersion     string `json:"sec-ch-ua-full-version"`
	Architecture    string `json:"sec-ch-ua-arch"`
	Platform        string `json:"sec-ch-ua-platform"`
	PlatformVersion string `json:"sec-ch-ua-platform-version"`
	Model           string `json:"sec-ch-ua-model"`
	Bitness         string `json:"sec-ch-ua-bitness"`
	Wow64           string `json:"sec-ch-ua-wow64"`
	FullVersionList string `json:"sec-ch-ua-full-version-list"`
	FormFactors     string `json:"sec-ch-ua-form-factors"`
}

type SBSDResponse struct {
	Success        bool        `json:"success"`
	Body           string      `json:"body"` // the encrypted SBSD post body
	Session        string      `json:"session"`
	ScriptID       string      `json:"script_id"`
	AcceptEncoding string      `json:"accept_encoding"` // as SensorResponse's
	ClientHints    ClientHints `json:"client_hints"`
	// SBSDPost, Index, WaitMS and Trigger are sent only by telemetry posts.
	SBSDPost string `json:"sbsd_post,omitempty"`
	Index    int64  `json:"ind,omitempty"`
	WaitMS   *int64 `json:"wait_ms,omitempty"`      // ms until the next telemetry post is due; 0 after the last
	Trigger  string `json:"sbsd_trigger,omitempty"` // "click" or "timer"
	// FingerprintMS is sent only by fingerprint posts: the browser's SBSD
	// fingerprint stage in ms; send the post no earlier than this after the
	// SBSD script loaded.
	FingerprintMS *int64 `json:"fingerprint_ms,omitempty"`
}

// OpenResponse answers Open (201): the opened session, or the one a
// staging Open named.
type OpenResponse struct {
	Success bool   `json:"success"`
	Session string `json:"session"`
}

// ErrorResponse is the body of /solve's own failures. It is not the shared
// evade.ErrorEnvelope, so it arrives as an *evade.APIError with an empty
// Code and this JSON in Message. Reason is set by 409 sbsd_telemetry_* only.
type ErrorResponse struct {
	Success   bool   `json:"success"`
	ErrorCode string `json:"error_code"`
	Message   string `json:"message,omitempty"`
	Stage     string `json:"stage,omitempty"`
	Reason    string `json:"reason,omitempty"`
}
