// Package datadome is the client for the DataDome solve API, whose tags,
// interstitial and captcha stages share one session.
package datadome

type Mode string

const (
	ModeTags         Mode = "tags"
	ModeInterstitial Mode = "interstitial"
	ModeCaptcha      Mode = "captcha"
)

// Session is SessionID alone, or UserAgent, AcceptLanguage and IP to open one; repeated identity must match.
type Session struct {
	SessionID      string `json:"session_id,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	AcceptLanguage string `json:"accept_language,omitempty"`
	IP             string `json:"ip,omitempty"` // egress IP the target sees; sets the session time zone
}

type TagsRequest struct {
	Session
	CID      string `json:"cid"`
	DDK      string `json:"ddk"`
	Referer  string `json:"referer"`
	TagsType string `json:"tags_type"`
	Script   string `json:"script"`
	HSV      any    `json:"hsv"` // window._hsv (string or number); nil sends null
	// CorrelationID: nil if the page callback had not run, "" if it published null, else the cookie.
	CorrelationID *string `json:"correlation_id,omitempty"`
	// LocalStorageSession: localStorage holds the DataDome session item and sessionByHeader is off.
	LocalStorageSession bool `json:"local_storage_session"`
}

type InterstitialRequest struct {
	Session
	DeviceLink string `json:"device_link"` // from the /js/ response
	HTML       string `json:"html"`
	Script     string `json:"script,omitempty"`
}

// CaptchaRequest without SessionID opens a session with a captcha-capable fingerprint.
type CaptchaRequest struct {
	Session
	Page        string `json:"page"`
	Script      string `json:"script,omitempty"`
	DocumentURL string `json:"document_url"`
	ParentURL   string `json:"parent_url"`
}
