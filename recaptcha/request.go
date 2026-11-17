package recaptcha

// Task names the reCAPTCHA surface and widget a page uses: the enterprise
// surface (loader enterprise.js on www.google.com or www.recaptcha.net) or
// the api2 surface (loader api.js on recaptcha.net or www.google.com); the
// v3 tasks run a score key (the reload token is the token), the v2
// invisible tasks an invisible key (the token is the bframe's userverify
// answer). The page's own loader URL states the host; the task must name
// the surface and widget the page uses. ReCaptchaV2InvisibleTask (api2)
// has no witness capture yet and is refused by the solver (no_witness).
type Task string

const (
	TaskV3Enterprise          Task = "ReCaptchaV3EnterpriseTask"
	TaskV3                    Task = "ReCaptchaV3Task"
	TaskV2InvisibleEnterprise Task = "ReCaptchaV2InvisibleEnterpriseTask"
	TaskV2Invisible           Task = "ReCaptchaV2InvisibleTask"
)

type Request struct {
	URL       string `json:"url"`            // the page the token is for, absolute HTTPS (never fetched)
	SiteKey   string `json:"sitekey"`        // the sitekey the page renders
	Action    string `json:"action"`         // the execute action the page passes
	UserAgent string `json:"userAgent"`      // one of client.UserAgents(ctx, "botguard")
	Proxy     string `json:"proxy"`          // scheme://user:pass@host:port, or host:port:user:pass
	Host      string `json:"host,omitempty"` // API host the loader is fetched from: www.google.com (default) or recaptcha.net
}
