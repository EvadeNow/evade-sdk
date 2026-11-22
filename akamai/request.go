// Package akamai is the client for the Akamai Bot Manager solve API, whose
// sensor and SBSD posts share one session on one device.
package akamai

type Mode string

const (
	ModeSensor Mode = "sensor"
	ModeSBSD   Mode = "sbsd"
	ModeOpen   Mode = "open"
)

// SensorRequest without Session opens a session; opening needs ExitCountry
// and Timezone, the proxy exit's region (geo.Reader.Locate through the
// proxy gives both), or the solve is refused exit_region_missing. A
// session's first sensor post needs ScriptID or Script. Session continues either mode's
// session: URL and UA must match its opening values and ScriptURL its
// sensor script's; Language and Timezone, when set, must equal the
// session's, and ExitCountry is not read. AcceptLanguage and Language are
// optional: unset, the session's language follows the site and the exit.
type SensorRequest struct {
	URL  string `json:"url"`   // the page's absolute http(s) URL, no credentials or fragment
	UA   string `json:"ua"`    // as GET /user-agents lists it
	Abck string `json:"abck"`  // the _abck cookie value
	BmSz string `json:"bm_sz"` // the bm_sz cookie value
	// ScriptID is the lower-case hex SHA-256 of the script source. Sent
	// alone, a 409 script_cache_miss means the server does not hold the
	// script: resend with Script.
	ScriptID  string `json:"script_id,omitempty"`
	Script    []byte `json:"script,omitempty"` // the sensor script source, at most 1 MiB
	ScriptURL string `json:"script_url"`       // absolute http(s), as URL
	// SBSDSource is accepted only before the session's first sensor post.
	SBSDSource     *SBSDSource `json:"sbsd_source,omitempty"`
	AcceptLanguage string      `json:"accept_language,omitempty"`
	Language       string      `json:"language,omitempty"`     // navigator.language
	Timezone       string      `json:"timezone,omitempty"`     // IANA zone of the proxy exit
	ExitCountry    string      `json:"exit_country,omitempty"` // ISO 3166-1 alpha-2 country of the proxy exit
	Session        string      `json:"session,omitempty"`
	// Pace: nil or true holds a continued post until 1s after the session's
	// previous sensor post (SensorResponse.PacedMS); false never holds.
	Pace      *bool `json:"pace,omitempty"`
	Telemetry bool  `json:"telemetry,omitempty"` // asks for SensorResponse.Telemetry
}

// SBSDSource stages the page's SBSD script before the first sensor post.
type SBSDSource struct {
	ScriptURL string `json:"script_url"`
	Script    []byte `json:"script"` // at most 1 MiB
}

// OpenRequest without Session opens a session with no post: URL and UA are
// required, the locale fields are as in SensorRequest (ExitCountry and
// Timezone required), and no script rides it. With Session it stages a
// script on that open session: Script (with its ScriptURL; ScriptID, when
// set, must match it) or SBSDSource, at least one.
type OpenRequest struct {
	URL            string      `json:"url"`
	UA             string      `json:"ua"`
	ScriptID       string      `json:"script_id,omitempty"`
	Script         []byte      `json:"script,omitempty"`
	ScriptURL      string      `json:"script_url,omitempty"`
	SBSDSource     *SBSDSource `json:"sbsd_source,omitempty"`
	AcceptLanguage string      `json:"accept_language,omitempty"`
	Language       string      `json:"language,omitempty"`
	Timezone       string      `json:"timezone,omitempty"`
	ExitCountry    string      `json:"exit_country,omitempty"`
	Session        string      `json:"session,omitempty"`
}

// SBSDRequest without Session opens a session, its locale fields as in
// SensorRequest (ExitCountry and Timezone required). A session's first SBSD
// post needs ScriptID or Script unless SensorRequest.SBSDSource staged it;
// later posts may omit both while ScriptURL is unchanged.
type SBSDRequest struct {
	URL       string `json:"url"` // absolute
	UA        string `json:"ua"`
	ScriptID  string `json:"script_id,omitempty"` // as SensorRequest.ScriptID
	Script    []byte `json:"script,omitempty"`    // the SBSD script source, at most 1 MiB
	ScriptURL string `json:"script_url"`          // absolute
	SBSDo     string `json:"sbsd_o"`              // the bm_so cookie value (sbsd_o on some hosts)
	Session   string `json:"session,omitempty"`   // URL and UA must match its opening values
	// SBSDPost is "telemetry" for a telemetry post; empty is the fingerprint post.
	SBSDPost       string `json:"sbsd_post,omitempty"`
	AcceptLanguage string `json:"accept_language,omitempty"`
	Language       string `json:"language,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	ExitCountry    string `json:"exit_country,omitempty"`
	// UUID pins the tab id on the session's first SBSD post (empty draws
	// one); later posts must repeat or omit it.
	UUID string `json:"uuid,omitempty"`
	// Pace: nil or true holds a telemetry post until its send instant; false never holds.
	Pace *bool `json:"pace,omitempty"`
	// PageResources is read by fingerprint posts only.
	PageResources *PageResources `json:"page_resources,omitempty"`
}

// PageResources: PageURL must equal SBSDRequest.URL and both lists be
// non-nil, in browser order, at most 2048 entries each.
type PageResources struct {
	PageURL     string        `json:"page_url"`
	DOM         []ResourceURL `json:"dom"`
	Performance []ResourceURL `json:"performance"`
}

// ResourceURL has no JSON tags: the server's keys are Kind and URL.
type ResourceURL struct {
	Kind string // link, img or script
	URL  string // at most 8192 bytes
}
