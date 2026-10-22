package shape

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// WarningSendTooEarly means the protected request was early: the headers
// are generated for a later instant, and the caller sends the request no
// earlier than Response.SendAfterUnixMS (Response.WaitForSend).
const WarningSendTooEarly = "send_too_early"

type Response struct {
	Success bool    `json:"success"`
	Headers Headers `json:"headers"`
	// UserAgent is the exact User-Agent the protected request must carry.
	UserAgent string  `json:"user_agent"`
	Timings   Timings `json:"timings"`
	// Warnings are non-fatal solve conditions. Callers may ignore values
	// they do not need to treat as diagnostics.
	Warnings []string `json:"warnings,omitempty"`
	// SendAfterUnixMS is the Unix ms instant an early request's headers
	// were generated for (WarningSendTooEarly): send the protected request
	// no earlier. 0 when the request was not early.
	SendAfterUnixMS int64  `json:"send_after_unix_ms,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	SessionReused   bool   `json:"session_reused,omitempty"`
	SessionStep     uint64 `json:"session_step,omitempty"`
	OneTime         bool   `json:"one_time,omitempty"` // interstitial challenge; the session cannot be continued
	FingerprintHash string `json:"fingerprint_hash,omitempty"`
	SolveID         string `json:"solve_id,omitempty"` // identifies this solve to ReportOutcome
	Debug           *Debug `json:"debug,omitempty"`    // Request.Debug only
}

// WaitForSend blocks until SendAfterUnixMS (at once when it is 0 or past)
// or until ctx is done, returning ctx's error then.
func (r Response) WaitForSend(ctx context.Context) error {
	wait := time.Until(time.UnixMilli(r.SendAfterUnixMS))
	if r.SendAfterUnixMS == 0 || wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Header is one generated header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Headers are the generated headers in emission order, which is the order
// the protected request must send them in. On the wire they are one JSON
// object whose members are in that order; a name appears once.
type Headers []Header

func (h *Headers) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("shape: headers is %v, not a JSON object", token)
	}
	decoded := Headers{}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name := token.(string)
		if token, err = decoder.Token(); err != nil {
			return err
		}
		value, ok := token.(string)
		if !ok {
			return fmt.Errorf("shape: header %q value is %v, not a string", name, token)
		}
		if seen[name] {
			return fmt.Errorf("shape: header %q appears twice", name)
		}
		seen[name] = true
		decoded = append(decoded, Header{Name: name, Value: value})
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	*h = decoded
	return nil
}

func (h Headers) MarshalJSON() ([]byte, error) {
	return orderedObject(len(h), func(i int) (string, string) { return h[i].Name, h[i].Value })
}

// orderedObject encodes n name/value string pairs as one JSON object whose
// members keep their order; encoding/json would sort a map's keys.
func orderedObject(n int, pair func(int) (string, string)) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	out.WriteByte('{')
	for i := range n {
		if i > 0 {
			out.WriteByte(',')
		}
		name, value := pair(i)
		if err := encoder.Encode(name); err != nil {
			return nil, err
		}
		out.Truncate(out.Len() - 1) // Encode's trailing newline
		out.WriteByte(':')
		if err := encoder.Encode(value); err != nil {
			return nil, err
		}
		out.Truncate(out.Len() - 1)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

type Timings struct {
	RequestTotalMS      int64 `json:"request_total_ms"`
	LoaderQueueHit      bool  `json:"loader_queue_hit"`
	LoaderQueueWaitMS   int64 `json:"loader_queue_wait_ms"`
	LoaderQueueCapacity int   `json:"loader_queue_capacity"`
	LoaderQueueReady    int   `json:"loader_queue_ready"`
	LoaderQueueInflight int   `json:"loader_queue_inflight"`
	LoaderProxyFallback bool  `json:"loader_proxy_fallback"`
	LoaderAgeMS         int64 `json:"loader_age_ms"`
	LoaderMS            int64 `json:"loader_ms"`
	ChallengeMS         int64 `json:"challenge_ms"`
	OtherNetworkMS      int64 `json:"other_network_ms"`
	GenerationMS        int64 `json:"generation_ms"`
	PayloadVerifyMS     int64 `json:"payload_verification_ms"`
	// NetworkMS is the solver's time on the wire (challenge fetch, ZeroNaught exchange); OtherMS is the rest, less Stages.ZeronaughtWaitMS.
	NetworkMS int64   `json:"network_ms"`
	OtherMS   int64   `json:"other_ms"`
	Stages    *Stages `json:"stages,omitempty"`
}

// Stages is the solve's own work split at its seams, in milliseconds
// (0.01 ms resolution), plus ZeronaughtWaitMS, the solver's hold until the
// document's ZeroNaught request's planned send instant, and
// ZeronaughtLateMS, how far past that instant the request left (0 when the
// solve sent none). Seams that stay under 2 ms are not reported.
type Stages struct {
	ChallengeFetchMS float64 `json:"challenge_fetch_ms"`
	FetchWallMS      float64 `json:"fetch_wall_ms"`
	FetchNetMS       float64 `json:"fetch_net_ms"`
	BuildMS          float64 `json:"build_ms"`
	SessionOpenMS    float64 `json:"session_open_ms"`
	GenerateMS       float64 `json:"generate_ms"`
	TailMS           float64 `json:"tail_ms"`
	ZeronaughtWaitMS float64 `json:"zeronaught_wait_ms"`
	ZeronaughtLateMS float64 `json:"zeronaught_late_ms"`
}

// Debug is a debug request's diagnostics of the generated request.
type Debug struct {
	DeviceRecord string   `json:"device_record"` // the stored device record the solve used
	ChallengeID  string   `json:"challenge_id,omitempty"`
	Build        *Build   `json:"build,omitempty"`
	TLSProfile   string   `json:"tls_profile,omitempty"`
	Slots        []Slot   `json:"slots,omitempty"`
	GenMS        *float64 `json:"gen_ms,omitempty"`
	// SetCookies are the Set-Cookie lines the solver's challenge fetch
	// received, in order, for the caller's browser jar.
	SetCookies  []SetCookie `json:"set_cookies,omitempty"`
	SessionStep int         `json:"session_step,omitempty"` // 1-based ordinal on the session's document
	// DocumentAnchor is how the solver placed the request's document
	// against its challenge token's issue.
	DocumentAnchor *DocumentAnchor `json:"document_anchor,omitempty"`
}

// DocumentAnchor is a document's start against its challenge token's
// issue: the path that placed it (token_issue: the laws' own draw admitted
// the send; token_issue_send_window: drawn on the part of the bands the
// send admits; token_issue_early_finalize: the page's early first send
// fixed the collector origin), the navigation-to-issue delay and the law
// it was drawn on, and the collector start lag and origin after the issue.
type DocumentAnchor struct {
	Path                    string  `json:"path"`
	IssuedUnixMS            float64 `json:"issued_unix_ms"`
	NavigationIssueDelayMS  float64 `json:"navigation_issue_delay_ms"`
	NavigationIssueDelayLaw string  `json:"navigation_issue_delay_law"`
	CollectorStartLagMS     float64 `json:"collector_start_lag_ms"`
	OriginAfterIssueMS      float64 `json:"origin_after_issue_ms"`
}

// Build identifies the challenge scripts a solve generated from.
type Build struct {
	VMProgramSHA256 string `json:"vm_program_sha256"`
	VMSHA256        string `json:"vm_sha256"`
	LoaderSHA256    string `json:"loader_sha256"`
	Runtime         string `json:"runtime"`
}

// Slot is one populated container slot of the generated headers.
type Slot struct {
	Index int    `json:"index"`
	Label string `json:"label"`
}

// SetCookie is one raw Set-Cookie line and the URL whose response carried it.
type SetCookie struct {
	URL       string `json:"url"`
	SetCookie string `json:"set_cookie"`
}

type OutcomeResponse struct {
	Success bool    `json:"success"`
	SolveID string  `json:"solve_id"`
	Outcome Outcome `json:"outcome"`
}
