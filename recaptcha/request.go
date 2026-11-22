package recaptcha

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	evade "github.com/EvadeNow/evade-sdk"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

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
// The page fields (PageHTML through PageNavigationMS) are facts about the
// page the token is minted for; the solver never fetches the page itself.
// PageHTML and PageScripts are what the solver reads the token's page
// share from: send both (PageScripts lists the scripts to fetch), as every
// live flow does; a v3 solve without PageScripts fails site_unsupported.
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
	Enterprise *bool `json:"enterprise,omitempty"`
	// Host is the API host the loader is fetched from: www.google.com (the
	// default), recaptcha.net or www.recaptcha.net.
	Host string `json:"host,omitempty"`
	// PageScripts are the page's classic scripts in execution order, read
	// for the token's page share (see PageScripts); the solver appends the
	// loader it fetched.
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

// PageScript is one classic script of the page: Name its absolute URL or
// an inline label (inline#1, inline#2, ...), Body its source (base64 on
// the wire, as encoding/json writes a []byte).
type PageScript struct {
	Name string `json:"name"`
	Body []byte `json:"body"`
}

// PopupWindow is the width and height window.open was given.
type PopupWindow struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// hosts are the API hosts the server accepts (gman v3.Hosts).
var hosts = map[string]bool{"www.google.com": true, "recaptcha.net": true, "www.recaptcha.net": true}

// Validate refuses what the server's FlowInput.Validate refuses, with its
// messages: an unknown Version, an empty URL, SiteKey, UserAgent or Proxy,
// a URL that is not an https page, an unknown Host. It also refuses, before
// any request, a PageScript without a Body (PageScripts leaves external
// scripts for the caller to fetch). A refusal is an *Error with
// Code invalid_request and Status 0.
func (r Request) Validate() error {
	switch r.Version {
	case "", VersionV3, VersionV2Invisible, VersionV2Checkbox:
	default:
		return invalid("version %q is not %q, %q or %q", r.Version, VersionV3, VersionV2Invisible, VersionV2Checkbox)
	}
	for _, f := range []struct{ name, value string }{{"url", r.URL}, {"sitekey", r.SiteKey}, {"userAgent", r.UserAgent}, {"proxy", r.Proxy}} {
		if strings.TrimSpace(f.value) == "" {
			return invalid("%s is required", f.name)
		}
	}
	if u, err := url.Parse(r.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return invalid("url %q is not an https page URL", r.URL)
	}
	if r.Host != "" && !hosts[r.Host] {
		return invalid("host %q is not www.google.com or recaptcha.net", r.Host)
	}
	for i, script := range r.PageScripts {
		if script.Body == nil {
			return invalid("pageScripts[%d] %s has no body: fetch it", i, script.Name)
		}
	}
	return nil
}

func invalid(format string, args ...any) error {
	return &Error{Code: evade.CodeInvalidRequest, Message: fmt.Sprintf(format, args...)}
}

// PageScripts lists the classic scripts of page, the HTML served at
// pageURL, in document order as Request.PageScripts wants them: inline
// ones (named inline#1, inline#2, ... skipping empty ones) with their
// Body, external ones named by their absolute URL with a nil Body the
// caller fills by fetching it (through the solve's proxy, as its
// UserAgent, following redirects). Module and non-JavaScript scripts are
// left out, and so is the reCAPTCHA loader rendering siteKey: the solver
// fetches its own.
func PageScripts(pageURL, page, siteKey string) ([]PageScript, error) {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("recaptcha: page URL: %w", err)
	}
	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		return nil, fmt.Errorf("recaptcha: page scripts: %w", err)
	}
	var scripts []PageScript
	inline := 0
	var walk func(*html.Node) error
	walk = func(n *html.Node) error {
		if n.Type == html.ElementNode && n.DataAtom == atom.Script {
			src, classic := "", true
			for _, a := range n.Attr {
				switch strings.ToLower(a.Key) {
				case "src":
					src = strings.TrimSpace(a.Val)
				case "type":
					switch strings.ToLower(strings.TrimSpace(a.Val)) {
					case "", "text/javascript", "application/javascript", "application/x-javascript":
					default:
						classic = false
					}
				}
			}
			switch {
			case !classic:
			case src == "":
				var body bytes.Buffer
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						body.WriteString(c.Data)
					}
				}
				if len(bytes.TrimSpace(body.Bytes())) != 0 {
					inline++
					scripts = append(scripts, PageScript{Name: fmt.Sprintf("inline#%d", inline), Body: body.Bytes()})
				}
			default:
				ref, err := url.Parse(src)
				if err != nil {
					return fmt.Errorf("recaptcha: script src %q: %w", src, err)
				}
				resolved := base.ResolveReference(ref)
				if !strings.Contains(resolved.Path, "/recaptcha/") || resolved.Query().Get("render") != siteKey {
					scripts = append(scripts, PageScript{Name: resolved.String()})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(doc); err != nil {
		return nil, err
	}
	return scripts, nil
}
