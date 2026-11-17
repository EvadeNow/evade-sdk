// Package akamai is the client for the Akamai Bot Manager solve API, whose
// sensor and SBSD posts share one session on one device.
package akamai

type Mode string

const (
	ModeSensor Mode = "sensor"
	ModeSBSD   Mode = "sbsd"
)

// SensorRequest without Session opens a session. A session's first sensor
// post needs ScriptID or Script. Session continues either mode's session:
// URL and UA must match its opening values and ScriptURL its sensor
// script's. AcceptLanguage, Language and Timezone are optional; each, when
// set, must equal the device's own.
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
	// SBSDSource, PageLayout and PageClickTargets open a session only.
	SBSDSource     *SBSDSource `json:"sbsd_source,omitempty"`
	PageLayout     *PageLayout `json:"page_layout,omitempty"`
	AcceptLanguage string      `json:"accept_language,omitempty"`
	Language       string      `json:"language,omitempty"` // navigator.language
	Timezone       string      `json:"timezone,omitempty"` // IANA zone
	Session        string      `json:"session,omitempty"`
	// Pace: nil or true holds a continued post until 1s after the session's
	// previous sensor post (SensorResponse.PacedMS); false never holds.
	Pace      *bool `json:"pace,omitempty"`
	Telemetry bool  `json:"telemetry,omitempty"` // asks for SensorResponse.Telemetry
	// PageClickTargets are the page elements the input model clicks, in
	// order; without them it never clicks.
	PageClickTargets []PageClickTarget `json:"page_click_targets,omitempty"`
}

// SBSDSource stages the page's SBSD script before the first sensor post.
type SBSDSource struct {
	ScriptURL string `json:"script_url"`
	Script    []byte `json:"script"` // at most 1 MiB
}

// PageLayout is the page document and, in document order, every stylesheet
// linked before the sensor script, each followed by its @imports.
type PageLayout struct {
	Document    string       `json:"document"`
	Stylesheets []Stylesheet `json:"stylesheets"`
}

type Stylesheet struct {
	URL  string `json:"url"`
	Text string `json:"text"`
}

// PageClickTarget: Name and ID are nil when the attribute is absent, "" when
// it is empty; XPath is absolute (/html[1]/body[1]/...).
type PageClickTarget struct {
	Name  *string       `json:"name"`
	ID    *string       `json:"id"`
	XPath string        `json:"xpath"`
	Box   *PageClickBox `json:"box"` // must lie inside the device's viewport
}

// PageClickBox is the element's border box in viewport CSS pixels.
type PageClickBox struct {
	Left   float64 `json:"left"`
	Top    float64 `json:"top"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// SBSDRequest without Session opens a session. A session's first SBSD post
// needs ScriptID or Script unless SensorRequest.SBSDSource staged it; later
// posts may omit both while ScriptURL is unchanged. AcceptLanguage, Language
// and Timezone are as in SensorRequest.
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
