package recaptcha

type Response struct {
	Success bool   `json:"success"`
	Task    string `json:"task"` // Task
	Token   string `json:"token"` // the reload's rresp token, for the page's form or API call
	// Score is always nil: the score is not observable client-side, only
	// the site's own server-side siteverify call sees it.
	Score *float64 `json:"score"`
	// Verification is nil until a consumer-side verdict exists.
	Verification *string `json:"verification"`
	GenMS        float64 `json:"genMs"` // the reload mint, generator entry to serialized bytes; network excluded
}
