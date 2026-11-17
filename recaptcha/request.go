package recaptcha

// Task names the reCAPTCHA v3 surface a page uses: the enterprise surface
// (loader enterprise.js on www.google.com) or the api2 surface (loader
// api.js on recaptcha.net or www.google.com). The page's own loader URL
// states the host; the task must name the surface the page uses.
type Task string

const (
	TaskV3Enterprise Task = "ReCaptchaV3EnterpriseTask"
	TaskV3           Task = "ReCaptchaV3Task"
)

type Request struct {
	URL       string `json:"url"`       // the landed page, absolute HTTPS; redirects are not followed
	SiteKey   string `json:"sitekey"`   // the sitekey the page renders (render=)
	Action    string `json:"action"`    // the execute action the page passes
	UserAgent string `json:"userAgent"` // one of client.UserAgents(ctx, "botguard")
	Proxy     string `json:"proxy"`     // scheme://user:pass@host:port, or host:port:user:pass
}
