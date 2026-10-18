package cloudflare

type Request struct {
	WebsiteURL string `json:"websiteURL"` // absolute HTTPS, no credentials or fragment
	UserAgent  string `json:"userAgent"`  // required
	HTML       string `json:"html"`
	Proxy      string `json:"proxy"` // required
	WebsiteKey string `json:"websiteKey"`
	Action     string `json:"action,omitempty"` // Turnstile only
	CData      string `json:"cdata,omitempty"`  // Turnstile only
}
