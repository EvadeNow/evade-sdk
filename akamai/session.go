package akamai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	evade "github.com/EvadeNow/evade-sdk"
	"github.com/EvadeNow/evade-sdk/useragent"
	http "github.com/bogdanfinn/fhttp"
)

// Session is one solve-API session driving one page's Akamai posts in the
// page's order:
//
//	Open                         before or while the page loads
//	UploadSensorScript           once the sensor script is fetched
//	Sensor, SensorPost           the first sensor post
//	UploadSBSDScript             once the SBSD script is fetched
//	SBSDFingerprint, WaitForFingerprint, SBSDPost
//	Sensor, SensorPost           while NeedsSensor, up to three posts
//	SBSDTelemetry, SBSDPost      until it returns *Done
//
// It keeps the session token, the page URL and User-Agent every call must
// repeat, the staged scripts (resending a source the server's cache lost),
// and the device's header values the posts carry. It is not safe for
// concurrent use.
type Session struct {
	ID  string // the server's session token
	URL string
	UA  string
	// PageResources, when set, rides the SBSD fingerprint post.
	PageResources *PageResources

	client         *evade.Client
	sensor, sbsd   stagedScript
	sensorPosts    int
	acceptLanguage string
	acceptEncoding string
	hints          ClientHints
}

type stagedScript struct {
	url, id string
	source  []byte
	posted  bool // a post named it: later posts omit ScriptID
}

// Open opens a session on r's URL and UA (r.ExitCountry and r.Timezone,
// the proxy exit's region, are required; geo.Reader.Locate through the
// proxy gives both). r.Session and the script fields stay empty: the
// Upload methods stage the scripts.
func Open(ctx context.Context, c *evade.Client, r OpenRequest) (*Session, error) {
	if r.Session != "" || r.ScriptID != "" || len(r.Script) != 0 || r.ScriptURL != "" || r.SBSDSource != nil {
		return nil, errors.New("akamai: Open opens a fresh session: Session and the script fields stay empty (UploadSensorScript and UploadSBSDScript stage scripts)")
	}
	answer, err := SolveOpen(ctx, c, r)
	if err != nil {
		return nil, err
	}
	return &Session{ID: answer.Session, URL: r.URL, UA: r.UA, client: c}, nil
}

// UploadSensorScript stages the page's sensor script, scriptURL as the
// page fetched it (the sensor posts go there).
func (s *Session) UploadSensorScript(ctx context.Context, scriptURL string, source []byte) error {
	staged := stage(scriptURL, source)
	if _, err := SolveOpen(ctx, s.client, OpenRequest{URL: s.URL, UA: s.UA, ScriptID: staged.id, Script: source, ScriptURL: scriptURL, Session: s.ID}); err != nil {
		return err
	}
	s.sensor = staged
	return nil
}

// UploadSBSDScript stages the page's SBSD script, scriptURL as the page
// fetched it (the SBSD posts go there without its query).
func (s *Session) UploadSBSDScript(ctx context.Context, scriptURL string, source []byte) error {
	staged := stage(scriptURL, source)
	if _, err := SolveOpen(ctx, s.client, OpenRequest{URL: s.URL, UA: s.UA, SBSDSource: &SBSDSource{ScriptURL: scriptURL, Script: source}, Session: s.ID}); err != nil {
		return err
	}
	s.sbsd = staged
	return nil
}

func stage(scriptURL string, source []byte) stagedScript {
	digest := sha256.Sum256(source)
	return stagedScript{url: scriptURL, id: hex.EncodeToString(digest[:]), source: source}
}

// Sensor solves the next sensor post from the page's current _abck and
// bm_sz cookies. The server holds a later post until 1s after the previous
// one (SensorResponse.PacedMS): send SensorPost(answer.SensorData) at once.
func (s *Session) Sensor(ctx context.Context, abck, bmSz string) (SensorResponse, error) {
	if s.sensor.url == "" {
		return SensorResponse{}, errors.New("akamai: Sensor before UploadSensorScript")
	}
	r := SensorRequest{URL: s.URL, UA: s.UA, Abck: abck, BmSz: bmSz, ScriptURL: s.sensor.url, Session: s.ID}
	if !s.sensor.posted {
		r.ScriptID = s.sensor.id
	}
	answer, err := SolveSensor(ctx, s.client, r)
	if cacheMiss(err) && r.ScriptID != "" {
		r.Script = s.sensor.source
		answer, err = SolveSensor(ctx, s.client, r)
	}
	if err != nil {
		return SensorResponse{}, err
	}
	if answer.SensorData == "" || answer.UA != s.UA || answer.Language == "" || answer.AcceptEncoding == "" {
		return SensorResponse{}, errors.New("akamai: the sensor answer lacks sensor_data, the session's ua, its language or its accept_encoding")
	}
	agent, err := useragent.Parse(s.UA)
	if err != nil {
		return SensorResponse{}, err
	}
	if agent.Family.Blink() && (answer.ClientHints.UA == "" || answer.ClientHints.Mobile == "" || answer.ClientHints.Platform == "") {
		return SensorResponse{}, errors.New("akamai: the sensor answer lacks the Chromium device's client hints")
	}
	s.sensor.posted = true
	s.sensorPosts++
	s.ID = answer.Session
	s.acceptLanguage, s.acceptEncoding, s.hints = answer.Language, answer.AcceptEncoding, answer.ClientHints
	return answer, nil
}

// NeedsSensor reports whether the page sends another sensor post: the
// _abck cookie's second ~-separated field is 0 once Akamai wants none, and
// a page sends at most three.
func (s *Session) NeedsSensor(abck string) (bool, error) {
	parts := strings.Split(abck, "~")
	if len(parts) < 2 {
		return false, errors.New("akamai: _abck has no post-count field")
	}
	count, err := strconv.Atoi(parts[1])
	if err != nil || count < -1 {
		return false, fmt.Errorf("akamai: _abck post-count field %q is invalid", parts[1])
	}
	return count != 0 && s.sensorPosts < 3, nil
}

// SBSDFingerprint solves the SBSD fingerprint post from the bm_so cookie
// (sbsd_o on some hosts). Send it with SBSDPost(answer.Body) after
// WaitForFingerprint.
func (s *Session) SBSDFingerprint(ctx context.Context, sbsdO string) (SBSDResponse, error) {
	if s.sbsd.url == "" {
		return SBSDResponse{}, errors.New("akamai: SBSDFingerprint before UploadSBSDScript")
	}
	r := SBSDRequest{URL: s.URL, UA: s.UA, ScriptURL: s.sbsd.url, SBSDo: sbsdO, Session: s.ID, PageResources: s.PageResources}
	if !s.sbsd.posted {
		r.ScriptID = s.sbsd.id
	}
	answer, err := SolveSBSD(ctx, s.client, r)
	if cacheMiss(err) && r.ScriptID != "" {
		r.Script = s.sbsd.source
		answer, err = SolveSBSD(ctx, s.client, r)
	}
	if err != nil {
		return SBSDResponse{}, err
	}
	if answer.Body == "" {
		return SBSDResponse{}, errors.New("akamai: the SBSD answer lacks body")
	}
	s.sbsd.posted = true
	s.ID = answer.Session
	return answer, nil
}

// Done ends the telemetry loop: the server answered 409
// sbsd_telemetry_complete (Reason complete) or sbsd_telemetry_not_due
// (Reason no_input or second_post_input), so the page sends no further
// telemetry post. It is an error so the loop stops on errors.As.
type Done struct {
	Code   evade.Code
	Reason string
}

func (d *Done) Error() string {
	return fmt.Sprintf("akamai: SBSD telemetry done: %s (%s)", d.Code, d.Reason)
}

// SBSDTelemetry solves the next SBSD telemetry post, after the fingerprint
// post. The server holds the answer until the post's send instant: send
// SBSDPost(answer.Body) at once. It returns *Done when the page sends no
// more.
func (s *Session) SBSDTelemetry(ctx context.Context, sbsdO string) (SBSDResponse, error) {
	if !s.sbsd.posted {
		return SBSDResponse{}, errors.New("akamai: SBSDTelemetry before SBSDFingerprint")
	}
	answer, err := SolveSBSD(ctx, s.client, SBSDRequest{URL: s.URL, UA: s.UA, ScriptURL: s.sbsd.url, SBSDo: sbsdO, Session: s.ID, SBSDPost: "telemetry"})
	var failure *Error
	if errors.As(err, &failure) && failure.Status == http.StatusConflict &&
		(failure.Code == CodeTelemetryComplete && failure.Reason == "complete" ||
			failure.Code == CodeTelemetryNotDue && (failure.Reason == "no_input" || failure.Reason == "second_post_input")) {
		return SBSDResponse{}, &Done{Code: failure.Code, Reason: failure.Reason}
	}
	if err != nil {
		return SBSDResponse{}, err
	}
	if answer.Body == "" {
		return SBSDResponse{}, errors.New("akamai: the SBSD answer lacks body")
	}
	s.ID = answer.Session
	return answer, nil
}

func cacheMiss(err error) bool {
	var failure *Error
	return errors.As(err, &failure) && failure.Code == CodeScriptCacheMiss
}

// SensorPost is the page's sensor POST to the sensor script URL: body
// {"sensor_data":…} as JSON.stringify writes it, Content-Type
// text/plain;charset=UTF-8, and the device's User-Agent, Accept-Language,
// Accept-Encoding and low-entropy sec-ch-ua, sec-ch-ua-mobile and
// sec-ch-ua-platform. The caller adds what its page's XHR sends besides
// (origin, referer, sec-fetch-*, priority, cookies) and the header order
// (transport.OrderUniversal for transport.ClassXHR with Calls
// ["content-type"], then transport.ApplyWireOrder). Setting
// Accept-Encoding means the caller's client must not add its own
// (transport.Config.DisableCompression) and decodes the answer itself.
func (s *Session) SensorPost(sensorData string) (*http.Request, error) {
	return s.post(s.sensor.url, "sensor_data", sensorData, "text/plain;charset=UTF-8")
}

// SBSDPost is the page's SBSD POST to the SBSD script URL without its
// query: body {"body":…}, Content-Type application/json, and the headers
// SensorPost sets.
func (s *Session) SBSDPost(body string) (*http.Request, error) {
	target, err := url.Parse(s.sbsd.url)
	if err != nil || s.sbsd.url == "" {
		return nil, fmt.Errorf("akamai: SBSD script URL %q is not staged or invalid", s.sbsd.url)
	}
	target.RawQuery, target.Fragment = "", ""
	return s.post(target.String(), "body", body, "application/json")
}

func (s *Session) post(target, field, value, contentType string) (*http.Request, error) {
	if s.acceptLanguage == "" {
		return nil, errors.New("akamai: no sensor answer yet; the device's Accept-Language arrives with it")
	}
	request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(envelope(field, value)))
	if err != nil {
		return nil, fmt.Errorf("akamai: build POST %s: %w", target, err)
	}
	header := http.Header{
		"content-type": {contentType}, "user-agent": {s.UA},
		"accept-language": {s.acceptLanguage}, "accept-encoding": {s.acceptEncoding},
	}
	for name, value := range map[string]string{"sec-ch-ua": s.hints.UA, "sec-ch-ua-mobile": s.hints.Mobile, "sec-ch-ua-platform": s.hints.Platform} {
		if value != "" {
			header[name] = []string{value}
		}
	}
	request.Header = header
	return request, nil
}

// envelope is the one-member JSON object a page posts, escaped as
// JSON.stringify escapes: no HTML escaping, U+2028 and U+2029 verbatim,
// control characters as \uXXXX (encoding/json escapes all three).
func envelope(field, value string) []byte {
	out := make([]byte, 0, len(field)+len(value)+7)
	out = append(out, '{')
	out = appendJSONString(out, field)
	out = append(out, ':')
	out = appendJSONString(out, value)
	return append(out, '}')
}

func appendJSONString(out []byte, value string) []byte {
	const hex = "0123456789abcdef"
	out = append(out, '"')
	for i := range len(value) {
		switch b := value[i]; b {
		case '"', '\\':
			out = append(out, '\\', b)
		case '\b':
			out = append(out, `\b`...)
		case '\f':
			out = append(out, `\f`...)
		case '\n':
			out = append(out, `\n`...)
		case '\r':
			out = append(out, `\r`...)
		case '\t':
			out = append(out, `\t`...)
		default:
			if b < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hex[b>>4], hex[b&0x0f])
			} else {
				out = append(out, b)
			}
		}
	}
	return append(out, '"')
}

// WaitUntil returns at the instant at, or with ctx's error. A caller that
// sends a post with Pace false paces it itself: a sensor post no earlier
// than 1s after the previous one.
func WaitUntil(ctx context.Context, at time.Time) error {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// WaitForFingerprint returns fingerprint_ms after scriptLoaded, the instant
// the page finished loading the SBSD script: the browser's fingerprint
// stage ends then, and its post must not reach the site earlier.
func WaitForFingerprint(ctx context.Context, scriptLoaded time.Time, r SBSDResponse) error {
	if r.FingerprintMS == nil {
		return errors.New("akamai: the SBSD answer carries no fingerprint_ms (not a fingerprint post)")
	}
	return WaitUntil(ctx, scriptLoaded.Add(time.Duration(*r.FingerprintMS)*time.Millisecond))
}
