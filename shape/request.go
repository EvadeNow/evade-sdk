// Package shape is the client for the Shape (F5 Bot Defense) solve API, which
// generates the protected-request headers for one target API call.
package shape

type Request struct {
	// SessionID continues a retained session; repeated session-fixed fields must match its opening values.
	SessionID            string          `json:"session_id,omitempty"`
	Proxy                string          `json:"proxy"`
	TargetURL            string          `json:"target_url"`
	ShapeJSURL           string          `json:"shape_js_url"`
	TargetAPI            string          `json:"target_api"`
	TargetAPIMethod      string          `json:"target_api_method"` // GET, POST or PUT
	TargetAPIContentType string          `json:"target_api_content_type,omitempty"`
	InteractionMode      InteractionMode `json:"interaction_mode,omitempty"`
	// InteractionBody is the protected request's exact body. Optional: the solver
	// types each field the page's statement types in the shape of its value (never
	// keeping the value); send it only to a solver whose GET /solve/fields lists
	// interaction_body, since an older one refuses unknown members.
	InteractionBody      string               `json:"interaction_body,omitempty"`
	AuxiliaryNetworkMode AuxiliaryNetworkMode `json:"auxiliary_network_mode,omitempty"`
	Referer              string               `json:"referer,omitempty"`
	ReferrerPolicy       string               `json:"referrer_policy,omitempty"`
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
	LoaderSource    string `json:"loader_source,omitempty"`
	ChallengeSource string `json:"challenge_source,omitempty"`
	DocumentRequestUnixMS float64 `json:"document_request_unix_ms,omitempty"`
	// UA is an exact User-Agent or an OS selector (OSIOS, ...); empty selects the iOS pool.
	UA string `json:"ua,omitempty"`
	// FingerprintRecordID pins the solve to one stored device record; UA, when set, must name its User-Agent or OS.
	FingerprintRecordID      string          `json:"fingerprint_record_id,omitempty"`
	Locale                   string          `json:"locale,omitempty"`
	AcceptLanguage           string          `json:"accept_language,omitempty"`
	TimeZone                 string          `json:"time_zone,omitempty"` // IANA zone, e.g. America/New_York
	Cookies                  Cookies         `json:"cookies,omitempty"`
	RequestTransport         HeaderTransport `json:"request_transport,omitempty"`
	FetchLoaderThroughProxy  bool            `json:"fetch_loader_through_proxy,omitempty"` // session-opening request only
	RetainSession            bool            `json:"retain_session,omitempty"`
	SkipZeronaught           *bool           `json:"skip_zeronaught,omitempty"`            // nil leaves the server default
	Debug                    bool            `json:"debug,omitempty"`                      // needs a debug- or internal-scope key
	IncludeInteractionTiming bool            `json:"include_interaction_timing,omitempty"` // with Debug only
	// PageProfile: empty infers it from TargetURL, "none" disables it; session-opening request only.
	PageProfile string `json:"page_profile,omitempty"`
	// TargetDeviceInfo asks a fresh solve for the target's device_info
	// capture its device record pairs with (Response.TargetDeviceInfo), so a
	// caller sends the target's own fingerprint object from the same device
	// the Shape payload states; a continuation refuses it. Send it only to a solver
	// whose GET /solve/fields lists target_device_info.
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

// InteractionMode controls synthetic page input; empty behaves as InteractionModeAppend.
type InteractionMode string

const (
	InteractionModeAppend   InteractionMode = "append"
	InteractionModePreserve InteractionMode = "preserve"
	// InteractionModeActivation is one tap or click with no text entry.
	InteractionModeActivation InteractionMode = "activation"
	// InteractionModeAutomatic is for requests the page issues on its own, without user input.
	InteractionModeAutomatic InteractionMode = "automatic"
)

type AuxiliaryNetworkMode string

// AuxiliaryNetworkPending holds page-owned responses until the protected request's headers are captured.
const AuxiliaryNetworkPending AuxiliaryNetworkMode = "pending"

// HeaderTransport must match the API the real page uses; empty means XMLHttpRequest.
type HeaderTransport string

const (
	HeaderTransportXMLHttpRequest HeaderTransport = "xhr"
	HeaderTransportFetch          HeaderTransport = "fetch"
	HeaderTransportDirect         HeaderTransport = "direct"
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
