package recaptcha

// The widget versions Request.Version names: VersionV3 a score key (the
// reload token is the token), VersionV2Invisible an invisible key (the
// token is the bframe's userverify answer).
const (
	VersionV3          = "v3"
	VersionV2Invisible = "v2-invisible"
)

// Request is one reCAPTCHA solve. The surface is the enterprise surface
// (loader enterprise.js on www.google.com or www.recaptcha.net) or the
// api2 surface (loader api.js on recaptcha.net or www.google.com); the
// solver resolves it in this order:
//  1. the loader the page states, when the page is supplied to the solver
//     and its loader is discoverable (a <script src> rendering the sitekey,
//     or one distinct loader literal in the page's scripts) — that wins;
//  2. else Enterprise, when set;
//  3. else a hypothesis: a request carrying an Action is enterprise, one
//     without api2. api2 sites with an action exist (myanimelist), so set
//     Enterprise whenever you know the page's loader.
//
// Version v2-invisible on the api2 surface has no witness capture yet and
// is refused by the solver (no_witness).
type Request struct {
	URL       string `json:"url"`       // the page the token is for, absolute HTTPS (never fetched)
	SiteKey   string `json:"sitekey"`   // the sitekey the page renders
	Action    string `json:"action"`    // the execute action the page passes
	UserAgent string `json:"userAgent"` // one of client.UserAgents(ctx, recaptcha.Task)
	Proxy     string `json:"proxy"`     // scheme://user:pass@host:port, or host:port:user:pass
	// Version is the widget: VersionV3 (the default when empty) or
	// VersionV2Invisible; any other value is refused (invalid_request).
	Version string `json:"version,omitempty"`
	// Enterprise states the surface (true: enterprise.js, false: api.js)
	// when the page's own loader is not discoverable; nil leaves it to the
	// action rule above.
	Enterprise *bool  `json:"enterprise,omitempty"`
	Host       string `json:"host,omitempty"` // API host the loader is fetched from: www.google.com (default) or recaptcha.net
}
