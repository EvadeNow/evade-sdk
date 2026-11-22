package recaptcha

// The widget versions Request.Version names: VersionV3 a score key (the
// reload token is the token), VersionV2Invisible an invisible key (the
// token is the bframe's userverify answer, an image challenge solved
// server-side when one is served), VersionV2Checkbox the checkbox widget.
// The checkbox is witnessed only on the www.google.com/sorry first-party
// page, which Solve does not run: a checkbox request fails (solve_failed).
const (
	VersionV3          = "v3"
	VersionV2Invisible = "v2-invisible"
	VersionV2Checkbox  = "v2-checkbox"
)

// Request is one reCAPTCHA solve. The surface is the enterprise surface
// (loader enterprise.js on www.google.com or www.recaptcha.net) or the
// api2 surface (loader api.js on recaptcha.net or www.google.com); the
// solver resolves it in this order:
//  1. the loader the page states, when PageHTML or PageScripts carry it
//     (a <script src> rendering the sitekey, or one distinct loader literal
//     across the page's HTML and scripts) — that wins;
//  2. else Enterprise, when set;
//  3. else a hypothesis: a request carrying an Action is enterprise, one
//     without api2. api2 sites with an action exist (myanimelist), so set
//     Enterprise whenever you know the page's loader.
//
// The page fields (PageHTML through PageNavigationMS) are optional facts
// about the page the token is minted for; the solver never fetches the
// page itself.
type Request struct {
	URL       string `json:"url"`       // the page the token is for, absolute HTTPS (never fetched)
	SiteKey   string `json:"sitekey"`   // the sitekey the page renders
	Action    string `json:"action"`    // the execute action the page passes
	UserAgent string `json:"userAgent"` // one of client.UserAgents(ctx, recaptcha.Task)
	// Proxy is scheme://user:pass@host:port, scheme one of http, https,
	// socks4, socks4a, socks5, socks5h; or host:port:user:pass (http, or the
	// scheme prefixing it).
	Proxy string `json:"proxy"`
	// Version is the widget: VersionV3 (the default when empty),
	// VersionV2Invisible or VersionV2Checkbox; any other value is refused
	// (invalid_request).
	Version string `json:"version,omitempty"`
	// Enterprise states the surface (true: enterprise.js, false: api.js)
	// when the page's own loader is not discoverable; nil leaves it to the
	// action rule above.
	Enterprise *bool  `json:"enterprise,omitempty"`
	Host       string `json:"host,omitempty"` // API host the loader is fetched from: www.google.com (default) or recaptcha.net
	// PageScripts are the page's classic scripts in execution order, read
	// for the token's page share; the solver appends the loader it fetched.
	PageScripts []PageScript `json:"pageScripts,omitempty"`
	// Popup is the window.open size when the widget runs in a popup.
	Popup *PopupWindow `json:"popup,omitempty"`
	// PageHTML is the page's document as served; empty is the no-page mint.
	PageHTML string `json:"pageHTML,omitempty"`
	// Referrer is the page navigation's referrer.
	Referrer string `json:"referrer,omitempty"`
	// PageNavigationMS is how long before the solve the page navigation
	// started, in milliseconds.
	PageNavigationMS int64 `json:"pageNavigationMs,omitempty"`
}

// PageScript is one classic script of the page: Name its URL or an inline
// label, Body its source (base64 on the wire, as encoding/json writes a
// []byte).
type PageScript struct {
	Name string `json:"name"`
	Body []byte `json:"body"`
}

// PopupWindow is the width and height window.open was given.
type PopupWindow struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}
