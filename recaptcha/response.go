package recaptcha

type Response struct {
	Success bool   `json:"success"`
	Task    string `json:"task"`  // Task
	Token   string `json:"token"` // the reload's rresp token or the v2 userverify answer, for the page's form or API call
	// Score is always nil: the score is not observable client-side, only
	// the site's own server-side siteverify call sees it.
	Score *float64 `json:"score"`
	// Verification is nil unless the solve answered an image challenge.
	// It is informational (which challenge, how many rounds): Token is
	// already the answered challenge's token, and nothing else is sent.
	Verification *Verification `json:"verification"`
	GenMS        float64       `json:"genMs"`     // the reload mint, generator entry to serialized bytes; network excluded
	ProfileID    string        `json:"profileId"` // the stored device profile the solve ran as
}

// Verification reports the image challenge the solver answered server-side.
type Verification struct {
	Challenge *Challenge `json:"challenge,omitempty"`
}

// Challenge is one solved image challenge: its class, how many userverify
// rounds it took, the tiles answered per round, and one Step per round.
type Challenge struct {
	Type   string  `json:"type"`
	Rounds int     `json:"rounds"`
	Tiles  [][]int `json:"tiles"`
	Steps  []Step  `json:"steps,omitempty"`
}

// Step is one userverify round: its class, the tiles answered (one list
// per grid), the replaceimage calls inside it, whether a grid came back
// byte-identical to an earlier one, the server's answer (solved,
// next:<class> or rejected) and its duration.
type Step struct {
	Round        int     `json:"round"`
	Class        string  `json:"class"`
	Tiles        [][]int `json:"tiles,omitempty"`
	ReplaceImage int     `json:"replaceimage"`
	ReservedGrid bool    `json:"reserved_grid"`
	Answer       string  `json:"answer"`
	MS           int64   `json:"ms"`
}
