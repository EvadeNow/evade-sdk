// Package shape is the client for the Shape (F5 Bot Defense) solve API, which
// generates the protected-request headers for one target API call.
package shape

type Request struct {
	// SessionID continues a retained session; repeated session-fixed fields must match its opening values.
	SessionID            string               `json:"session_id,omitempty"`
	Proxy                string               `json:"proxy"`
	TargetURL            string               `json:"target_url"`
	ShapeJSURL           string               `json:"shape_js_url"`
	TargetAPI            string               `json:"target_api"`
	TargetAPIMethod      string               `json:"target_api_method"` // GET, POST or PUT
	TargetAPIContentType string               `json:"target_api_content_type,omitempty"`
	InteractionMode      InteractionMode      `json:"interaction_mode,omitempty"`
	InteractionBody      string               `json:"interaction_body,omitempty"`
	AuxiliaryNetworkMode AuxiliaryNetworkMode `json:"auxiliary_network_mode,omitempty"`
	Referer              string               `json:"referer,omitempty"`
	ReferrerPolicy       string               `json:"referrer_policy,omitempty"`
	PageHTML             string               `json:"page_html,omitempty"` // embedding the challenge skips fetching ShapeJSURL
	LoaderSource         string               `json:"loader_source,omitempty"`
	ChallengeSource      string               `json:"challenge_source,omitempty"`
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
