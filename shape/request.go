// Package shape is the client for the Shape (F5 Bot Defense) solve API, which
// generates the protected-request headers for one target API call.
package shape

type Request struct {
	// SessionID continues a retained session; repeated session-fixed fields must match its opening values.
	SessionID       string `json:"session_id,omitempty"`
	Proxy           string `json:"proxy"`
	TargetURL       string `json:"target_url"`
	ShapeJSURL      string `json:"shape_js_url"`
	TargetAPI       string `json:"target_api"`
	TargetAPIMethod string `json:"target_api_method"` // GET, POST or PUT
	Referer         string `json:"referer,omitempty"`
	// PageHTML is the exact body the caller's browser received for TargetURL
	// when that navigation was answered with a Shape interstitial (an inline
	// VM and a replay script). The protected
	// request is then TargetURL's own GET replay (TargetAPI = TargetURL),
	// ShapeJSURL and LoaderSource stay empty, and Cookies are the browser's
	// for TargetURL. The solver reads the challenge from it and fetches
	// nothing; without it the solver navigates to TargetURL itself. Fresh
	// solves only; refused beside ShapeJSURL or a stored page profile. It
	// must be valid UTF-8 (Solve refuses other bytes: see NotUTF8Error).
	PageHTML string `json:"page_html,omitempty"`
	// LoaderSource is the exact body of ShapeJSURL the caller's browser
	// fetched, sent instead of the solver's own GET (a body that does not
	// parse as a loader is fetched as without it); valid UTF-8 only.
	LoaderSource string `json:"loader_source,omitempty"`
	// ChallengeReadyUnixMS is when LoaderSource finished arriving on the
	// caller's Unix-ms wall clock. All caller timing fields use this clock.
	ChallengeReadyUnixMS float64 `json:"challenge_ready_unix_ms,omitempty"`
	// LoaderRequestStartUnixMS is when the caller handed the LoaderSource GET
	// to its HTTP client. With ChallengeReadyUnixMS it is a complete interval.
	LoaderRequestStartUnixMS float64 `json:"loader_request_start_unix_ms,omitempty"`
	// NavigationStartUnixMS is when the caller began the top-level
	// navigation. It requires DocumentRequestUnixMS.
	NavigationStartUnixMS float64 `json:"navigation_start_unix_ms,omitempty"`
	// DocumentRequestUnixMS is when the caller began the final document
	// request after redirects.
	DocumentRequestUnixMS float64 `json:"document_request_unix_ms,omitempty"`
	// UA is an exact User-Agent or an OS selector (OSIOS, ...); empty selects the iOS pool.
	UA string `json:"ua,omitempty"`
	// FingerprintRecordID pins the solve to one stored device record; UA, when set, must name its User-Agent or OS.
	FingerprintRecordID string          `json:"fingerprint_record_id,omitempty"`
	Locale              string          `json:"locale,omitempty"` // BCP 47 tag
	AcceptLanguage      string          `json:"accept_language,omitempty"`
	TimeZone            string          `json:"time_zone,omitempty"` // IANA zone of the proxy exit, e.g. America/New_York; required on a fresh solve
	Cookies             Cookies         `json:"cookies,omitempty"`
	RequestTransport    HeaderTransport `json:"request_transport,omitempty"`
	RetainSession       bool            `json:"retain_session,omitempty"`
	SkipZeronaught      *bool           `json:"skip_zeronaught,omitempty"` // nil leaves the server default; never true on a retained Target authentication session
	Debug               bool            `json:"debug,omitempty"`           // needs a debug- or internal-scope key
	// TargetDeviceInfo asks a fresh solve for the target's device_info
	// capture its device record pairs with (Response.TargetDeviceInfo), so a
	// caller sends the target's own fingerprint object from the same device
	// the Shape payload states. It is required on the opening Target sign-in
	// solve; a continuation refuses it.
	TargetDeviceInfo bool `json:"target_device_info,omitempty"`
}

// Cookie is one cookie the caller's browser sends with the challenge script GET.
type Cookie struct {
	Name  string
	Value string
}

// Cookies are the browser's Cookie header pairs in its own order; they are
// sent as one JSON object whose members keep that order, repeated names included.
type Cookies []Cookie

func (c Cookies) MarshalJSON() ([]byte, error) {
	return orderedObject(len(c), func(i int) (string, string) { return c[i].Name, c[i].Value })
}

const (
	OSIOS     = "ios"
	OSAndroid = "android"
	OSWindows = "windows"
	OSMacOS   = "macos"
	OSLinux   = "linux"
)

// HeaderTransport must match the API the real page uses; empty takes the
// stored page's or contract's transport, else XMLHttpRequest. A navigation
// ("direct") is refused (invalid_request).
type HeaderTransport string

const (
	HeaderTransportXMLHttpRequest HeaderTransport = "xhr"
	HeaderTransportFetch          HeaderTransport = "fetch"
)

// OutcomeReport tells the API whether the target accepted the request sent
// with a solve's headers, so solves can be reviewed by outcome.
type OutcomeReport struct {
	SolveID      string  `json:"solve_id"` // Response.SolveID
	Outcome      Outcome `json:"outcome"`
	TargetStatus int     `json:"target_status,omitempty"` // the target's HTTP status, 100-599
	Note         string  `json:"note,omitempty"`          // at most 500 bytes
}

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeBlocked Outcome = "blocked"
)
