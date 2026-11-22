package recaptcha_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	evade "github.com/EvadeNow/evade-sdk"
	"github.com/EvadeNow/evade-sdk/recaptcha"
)

func encode(t *testing.T, v any) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
}

func checkoutRequest() recaptcha.Request {
	return recaptcha.Request{
		URL: "https://www.example.com", SiteKey: "6LcExampleSiteKey", Action: "checkout",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
		Proxy:     "http://user:pass@host:port",
	}
}

const goldenRequest = `{"url":"https://www.example.com","sitekey":"6LcExampleSiteKey","action":"checkout","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36","proxy":"http://user:pass@host:port"}`

func TestRequestMatchesGolden(t *testing.T) {
	if got, want := encode(t, checkoutRequest()), []byte(goldenRequest); !bytes.Equal(got, want) {
		t.Fatalf("request\n got %s\nwant %s", got, want)
	}
}

const goldenResponse = `{"success":true,"task":"recaptcha","token":"03AFcWeA-token","score":null,"verification":null,"genMs":12.5,"profileId":"profile-7"}`

func wantResponse() recaptcha.Response {
	return recaptcha.Response{Success: true, Task: recaptcha.Task, Token: "03AFcWeA-token", GenMS: 12.5, ProfileID: "profile-7"}
}

// score is null on the wire and nil here: it is not observable
// client-side; verification is null when no image challenge was served.
func TestResponseGoldenDecodesEveryField(t *testing.T) {
	var got recaptcha.Response
	if err := json.Unmarshal([]byte(goldenResponse), &got); err != nil {
		t.Fatal(err)
	}
	if want := wantResponse(); !reflect.DeepEqual(got, want) {
		t.Fatalf("response\n got %+v\nwant %+v", got, want)
	}
	if got.Score != nil || got.Verification != nil {
		t.Fatalf("score %v verification %v, want nil", got.Score, got.Verification)
	}
	if encoded := encode(t, got); string(encoded) != goldenResponse {
		t.Fatalf("re-encoded response\n got %s\nwant %s", encoded, goldenResponse)
	}
}

// The solved image challenge rides as verification.challenge in gman's
// ChallengeSolve/ChallengeRound shape (gman/core/recaptcha/challenge.go).
const goldenChallengeResponse = `{"success":true,"task":"recaptcha","token":"03AFcWeA-token","score":null,"verification":{"challenge":{"type":"dynamic","rounds":2,"tiles":[[1,4],[2]],"steps":[{"round":1,"class":"dynamic","tiles":[[1,4]],"replaceimage":2,"reserved_grid":false,"answer":"next:dynamic","ms":5400},{"round":2,"class":"dynamic","replaceimage":0,"reserved_grid":true,"answer":"solved","ms":3100}]}},"genMs":12.5,"profileId":"profile-7"}`

func TestResponseDecodesChallengeVerification(t *testing.T) {
	var got recaptcha.Response
	if err := json.Unmarshal([]byte(goldenChallengeResponse), &got); err != nil {
		t.Fatal(err)
	}
	want := wantResponse()
	want.Verification = &recaptcha.Verification{Challenge: &recaptcha.Challenge{
		Type: "dynamic", Rounds: 2, Tiles: [][]int{{1, 4}, {2}},
		Steps: []recaptcha.Step{
			{Round: 1, Class: "dynamic", Tiles: [][]int{{1, 4}}, ReplaceImage: 2, Answer: "next:dynamic", MS: 5400},
			{Round: 2, Class: "dynamic", ReservedGrid: true, Answer: "solved", MS: 3100},
		},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response\n got %+v\nwant %+v", got, want)
	}
	if encoded := encode(t, got); string(encoded) != goldenChallengeResponse {
		t.Fatalf("re-encoded response\n got %s\nwant %s", encoded, goldenChallengeResponse)
	}
}

func server(t *testing.T, status int, header http.Header, body []byte) (*evade.Client, *string, *[]byte) {
	t.Helper()
	var line string
	var sent []byte
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line = r.Method + " " + r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		sent = bytes.TrimSuffix(raw, []byte("\n"))
		for name, values := range header {
			w.Header()[name] = values
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	client, err := evade.NewClient(evade.Config{BaseURL: s.URL, MaxRetries: new(int)})
	if err != nil {
		t.Fatal(err)
	}
	return client, &line, &sent
}

// The one task name rides first on the wire, the widget, surface and page
// fields after proxy in gman's FlowInput order (absent when unset);
// unknown response keys are tolerated.
func TestSolveSendsTaskAndToleratesUnknownResponseKeys(t *testing.T) {
	const proxyEnd = `"proxy":"http://user:pass@host:port"`
	for _, test := range []struct {
		name   string
		set    func(*recaptcha.Request)
		fields string
	}{
		{"v3 surface unstated", func(*recaptcha.Request) {}, ""},
		{"v3 api2", func(r *recaptcha.Request) { r.Version, r.Enterprise = recaptcha.VersionV3, new(false) }, `,"version":"v3","enterprise":false`},
		{"v2-invisible enterprise", func(r *recaptcha.Request) { r.Version, r.Enterprise = recaptcha.VersionV2Invisible, new(true) }, `,"version":"v2-invisible","enterprise":true`},
		{"v2-checkbox", func(r *recaptcha.Request) { r.Version = recaptcha.VersionV2Checkbox }, `,"version":"v2-checkbox"`},
		{"page facts", func(r *recaptcha.Request) {
			r.PageScripts = []recaptcha.PageScript{{Name: "inline#1", Body: []byte("var a=1;")}}
			r.Popup = &recaptcha.PopupWindow{Width: 500, Height: 600}
			r.PageHTML, r.Referrer, r.PageNavigationMS = "<html></html>", "https://www.example.com/cart", 1500
		}, `,"pageScripts":[{"name":"inline#1","body":"dmFyIGE9MTs="}],"popup":{"width":500,"height":600},"pageHTML":"<html></html>","referrer":"https://www.example.com/cart","pageNavigationMs":1500`},
		{"every field", func(r *recaptcha.Request) {
			r.Version, r.Enterprise, r.Host = recaptcha.VersionV3, new(true), "recaptcha.net"
			r.PageScripts = []recaptcha.PageScript{{Name: "https://www.example.com/app.js", Body: []byte("x()")}}
			r.Popup = &recaptcha.PopupWindow{Width: 500, Height: 600}
			r.PageHTML, r.Referrer, r.PageNavigationMS = "<p>&</p>", "https://www.example.com/", 900
		}, `,"version":"v3","enterprise":true,"host":"recaptcha.net","pageScripts":[{"name":"https://www.example.com/app.js","body":"eCgp"}],"popup":{"width":500,"height":600},"pageHTML":"<p>&</p>","referrer":"https://www.example.com/","pageNavigationMs":900`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, line, sent := server(t, http.StatusOK, nil, []byte(`{"stages":[{"name":"reload","status":200}],"success":true,"task":"recaptcha","token":"03AFcWeA-token","score":null,"verification":null,"genMs":12.5,"profileId":"profile-7"}`))
			request := checkoutRequest()
			test.set(&request)
			got, err := recaptcha.Solve(context.Background(), client, request)
			if err != nil {
				t.Fatalf("Solve: %v", err)
			}
			if *line != "POST /solve" {
				t.Fatalf("request line = %s", *line)
			}
			want := []byte(`{"task":"recaptcha",` + strings.Replace(goldenRequest[1:], proxyEnd, proxyEnd+test.fields, 1))
			if !bytes.Equal(*sent, want) {
				t.Fatalf("wire body\n got %s\nwant %s", *sent, want)
			}
			if !reflect.DeepEqual(got, wantResponse()) {
				t.Fatalf("response = %+v", got)
			}
		})
	}
}

// Every refusal is the shared envelope with its catalog code, surfaced as
// *recaptcha.Error unwrapping to the *evade.APIError; a rate limit carries
// Retry-After.
func TestSolveFailuresReturnZeroAndTypedError(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		header    http.Header
		body      string
		code      evade.Code
		retryable bool
		retry     time.Duration
	}{
		{"device", http.StatusUnprocessableEntity, nil, `{"success":false,"error":{"code":"device_unsupported","message":"no admitted Record for \"Mozilla/5.0 …\" on the running collector bundle"}}`, evade.CodeDeviceUnsupported, false, 0},
		{"page", http.StatusBadRequest, nil, `{"success":false,"error":{"code":"invalid_request","message":"page https://www.example.com has no enterprise v3 loader"}}`, evade.CodeInvalidRequest, false, 0},
		{"site", http.StatusUnprocessableEntity, nil, `{"success":false,"error":{"code":"site_unsupported","message":"v3: no J page laws for https://www.example.com"}}`, evade.CodeSiteUnsupported, false, 0},
		{"short", http.StatusUnprocessableEntity, nil, `{"success":false,"error":{"code":"generation_failed","message":"reload token is SHORT (2001 bytes, NORMAL is at least 2100)"}}`, evade.CodeGenerationFailed, false, 0},
		{"challenged", http.StatusUnprocessableEntity, nil, `{"success":false,"error":{"code":"challenged","message":"userverify demanded an audio challenge"}}`, evade.CodeChallenged, false, 0},
		{"unsolved", http.StatusUnprocessableEntity, nil, `{"success":false,"error":{"code":"challenge_unsolved","message":"dynamic challenge rejected after 3 rounds"}}`, evade.CodeChallengeUnsolved, false, 0},
		{"target", http.StatusServiceUnavailable, nil, `{"success":false,"error":{"code":"target_error","message":"reload answered 403"}}`, evade.CodeTargetError, false, 0},
		{"failed", http.StatusBadGateway, nil, `{"success":false,"error":{"code":"solve_failed","message":"checkbox flow is not run"}}`, evade.CodeSolveFailed, false, 0},
		{"proxy", http.StatusServiceUnavailable, nil, `{"success":false,"error":{"code":"proxy_failed","message":"recaptcha exit: dial tcp: connection refused"}}`, evade.CodeProxyFailed, true, 0},
		{"proxy_timeout", http.StatusGatewayTimeout, nil, `{"success":false,"error":{"code":"proxy_timeout","message":"anchor: context deadline exceeded"}}`, evade.CodeProxyTimeout, true, 0},
		{"rate", http.StatusTooManyRequests, http.Header{"Retry-After": {"7"}}, `{"success":false,"error":{"code":"rate_limited","message":"too many requests for this account"}}`, evade.CodeRateLimited, true, 7 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _, _ := server(t, test.status, test.header, []byte(test.body+"\n"))
			got, err := recaptcha.Solve(context.Background(), client, checkoutRequest())
			var failure *recaptcha.Error
			if !errors.As(err, &failure) || failure.Status != test.status || failure.Code != test.code || failure.Message == "" ||
				failure.Retryable != test.retryable {
				t.Fatalf("error = %#v", err)
			}
			var apiErr *evade.APIError
			if !errors.As(err, &apiErr) || apiErr.RateLimit.RetryAfter != test.retry {
				t.Fatalf("unwrapped *evade.APIError = %#v, want Retry-After %s", apiErr, test.retry)
			}
			if !reflect.DeepEqual(got, recaptcha.Response{}) {
				t.Fatalf("failed Solve returned %+v", got)
			}
		})
	}
}

// TestValidateMirrorsServer: each refusal carries the message gman's
// FlowInput.Validate (core/recaptcha/flow.go) answers, and Solve sends
// nothing.
func TestValidateMirrorsServer(t *testing.T) {
	for _, test := range []struct {
		name    string
		set     func(*recaptcha.Request)
		message string
	}{
		{"empty url", func(r *recaptcha.Request) { r.URL = "" }, "url is required"},
		{"blank sitekey", func(r *recaptcha.Request) { r.SiteKey = " " }, "sitekey is required"},
		{"empty userAgent", func(r *recaptcha.Request) { r.UserAgent = "" }, "userAgent is required"},
		{"empty proxy", func(r *recaptcha.Request) { r.Proxy = "" }, "proxy is required"},
		{"non-https url", func(r *recaptcha.Request) { r.URL = "http://www.example.com/login" }, `url "http://www.example.com/login" is not an https page URL`},
		{"hostless url", func(r *recaptcha.Request) { r.URL = "https:///login" }, `url "https:///login" is not an https page URL`},
		{"unknown version", func(r *recaptcha.Request) { r.Version = "v4" }, `version "v4" is not "v3", "v2-invisible" or "v2-checkbox"`},
		{"version before fields", func(r *recaptcha.Request) { r.Version, r.URL = "enterprise", "" }, `version "enterprise" is not "v3", "v2-invisible" or "v2-checkbox"`},
		{"unknown host", func(r *recaptcha.Request) { r.Host = "www.gstatic.com" }, `host "www.gstatic.com" is not www.google.com or recaptcha.net`},
		{"unfetched script", func(r *recaptcha.Request) {
			r.PageScripts = []recaptcha.PageScript{{Name: "https://www.example.com/app.js"}}
		}, "pageScripts[0] https://www.example.com/app.js has no body: fetch it"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, line, _ := server(t, http.StatusOK, nil, []byte(goldenResponse))
			request := checkoutRequest()
			test.set(&request)
			_, err := recaptcha.Solve(context.Background(), client, request)
			var failure *recaptcha.Error
			if !errors.As(err, &failure) || failure.Code != evade.CodeInvalidRequest || failure.Status != 0 || failure.Message != test.message {
				t.Fatalf("error = %#v, want invalid_request %q", err, test.message)
			}
			if *line != "" {
				t.Fatalf("an invalid request was sent: %s", *line)
			}
		})
	}
	for _, host := range []string{"", "www.google.com", "recaptcha.net", "www.recaptcha.net"} {
		request := checkoutRequest()
		request.Host = host
		if err := request.Validate(); err != nil {
			t.Fatalf("host %q: %v", host, err)
		}
	}
}

// A non-boolean enterprise is a JSON error on the server (FlowInput's
// *bool) and on this type alike.
func TestEnterpriseNonBoolIsJSONError(t *testing.T) {
	var request recaptcha.Request
	var typeErr *json.UnmarshalTypeError
	if err := json.Unmarshal([]byte(`{"enterprise":"true"}`), &request); !errors.As(err, &typeErr) || typeErr.Field != "enterprise" {
		t.Fatalf("decode = %v, want a JSON type error on enterprise", err)
	}
}

// TestPageScripts mirrors g-live's sitePageScripts
// (cmds/g-live/flow_recaptchademo.go): classic scripts in document order,
// non-empty inline ones numbered, external ones by absolute URL to fetch,
// module and data scripts and the sitekey's loader left out.
func TestPageScripts(t *testing.T) {
	const page = `<!doctype html><html><head>
<script src="https://www.google.com/recaptcha/enterprise.js?render=6LcKey"></script>
<script>var a = 1;</script>
<script src="/static/app.js?v=3" defer></script>
<script type="module" src="/static/mod.js"></script>
<script type="application/ld+json">{"@type":"Organization"}</script>
<script>   </script>
</head><body>
<script type="text/javascript">grecaptcha.enterprise.ready(go);</script>
<script src="https://cdn.example.net/lib.js" async></script>
<script src="https://www.google.com/recaptcha/api.js?render=6LcOther"></script>
</body></html>`
	got, err := recaptcha.PageScripts("https://www.example.com/login/", page, "6LcKey")
	if err != nil {
		t.Fatal(err)
	}
	want := []recaptcha.PageScript{
		{Name: "inline#1", Body: []byte("var a = 1;")},
		{Name: "https://www.example.com/static/app.js?v=3"},
		{Name: "inline#2", Body: []byte("grecaptcha.enterprise.ready(go);")},
		{Name: "https://cdn.example.net/lib.js"},
		{Name: "https://www.google.com/recaptcha/api.js?render=6LcOther"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PageScripts\n got %q\nwant %q", got, want)
	}
}
