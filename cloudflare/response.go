package cloudflare

type Response struct {
	Success   bool     `json:"success"`
	Token     string   `json:"token,omitempty"`     // Turnstile only
	Cookies   []Cookie `json:"cookies,omitempty"`   // challenge page only
	UserAgent string   `json:"userAgent,omitempty"` // later requests carrying Cookies must reuse it
	GenMS     float64  `json:"genMs"`
}

type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}
