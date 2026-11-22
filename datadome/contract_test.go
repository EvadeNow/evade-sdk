package datadome_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	evade "github.com/EvadeNow/evade-sdk"
	"github.com/EvadeNow/evade-sdk/datadome"
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

func tagsRequest() datadome.TagsRequest {
	empty := ""
	return datadome.TagsRequest{
		Session: datadome.Session{
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
			AcceptLanguage: "en-US,en;q=0.9",
			IP:             "203.0.113.9",
		},
		CID: "abc123", DDK: "0123456789ABCDEF0123456789ABCD", Referer: "https://www.example.test/",
		TagsType: "le", Script: "if(dd&&dd.k<1){dd.init()}", ScriptURL: "https://js.example.test/tags.js", HSV: 7, CorrelationID: &empty,
		LocalStorageSession: true,
	}
}

func interstitialRequest() datadome.InterstitialRequest {
	return datadome.InterstitialRequest{
		Session:    datadome.Session{SessionID: "s"},
		DeviceLink: "https://example.test/interstitial/", HTML: "page", Script: "external interstitial script",
	}
}

func captchaRequest() datadome.CaptchaRequest {
	return datadome.CaptchaRequest{
		Session: datadome.Session{SessionID: "missing"},
		Page:    "page", Script: "external bundle",
		DocumentURL: "https://challenge.example/captcha/", ParentURL: "https://example.test/",
	}
}

func TestRequestsMatchGolden(t *testing.T) {
	tests := []struct {
		name    string
		request any
		want    string
	}{
		{"tags", tagsRequest(), tagsGolden},
		{"tags_page_counters", datadome.TagsRequest{
			Session: datadome.Session{SessionID: "s"}, TagsType: "le",
			DataDomeCookieCount: new(2), NavigationTiming: map[string]any{"nt_dns": 0.0, "nt_ttrd": nil}, BeaconPayloadCount: new(3),
		}, `{"session_id":"s","cid":"","ddk":"","referer":"","tags_type":"le","script":"","hsv":null,"local_storage_session":false,"datadome_cookie_count":2,"navigation_timing":{"nt_dns":0,"nt_ttrd":null},"beacon_payload_count":3}`},
		{"tags_continuation", datadome.TagsRequest{
			Session: datadome.Session{SessionID: "s"}, TagsType: "ch",
		}, `{"session_id":"s","cid":"","ddk":"","referer":"","tags_type":"ch","script":"","hsv":null,"local_storage_session":false}`},
		{"interstitial", interstitialRequest(), `{"session_id":"s","device_link":"https://example.test/interstitial/","html":"page","script":"external interstitial script"}`},
		{"captcha", captchaRequest(), `{"session_id":"missing","page":"page","script":"external bundle","document_url":"https://challenge.example/captcha/","parent_url":"https://example.test/"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := encode(t, test.request), []byte(test.want); !bytes.Equal(got, want) {
				t.Fatalf("request\n got %s\nwant %s", got, want)
			}
		})
	}
}

// tagsGolden is tagsRequest's wire form.
const tagsGolden = `{"user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36","accept_language":"en-US,en;q=0.9","ip":"203.0.113.9","cid":"abc123","ddk":"0123456789ABCDEF0123456789ABCD","referer":"https://www.example.test/","tags_type":"le","script":"if(dd&&dd.k<1){dd.init()}","script_url":"https://js.example.test/tags.js","hsv":7,"correlation_id":"","local_storage_session":true}`

// Response goldens: every solve answers its session (addSolveSessionResponse
// in datadome/sessions.go), the opening one with its client hints;
// interstitial and captcha add solve_warnings when there are any.
const (
	tagsResponseGolden         = `{"client_hints":{"architecture":"x86","bitness":"64","mobile":false,"model":"","platform":"Windows","platformVersion":"19.0.0","uaFullVersion":"151.0.7103.114","wow64":true},"device_memory":8,"expires_in_seconds":600,"payload":"jsData=%7B%7D&eventCounters=%5B%5D&cid=abc123","session_id":"b3f1c2d4e5a6978812345678"}`
	interstitialResponseGolden = `{"headers":{"sec-ch-device-memory":"8","sec-ch-ua-arch":"\"x86\"","sec-ch-ua-mobile":"?0","sec-ch-ua-model":"\"\"","sec-ch-ua-platform":"\"Windows\""},"payload":"cid=abc123&icid=xyz&ccid=&dm=cd&hash=8E2F","session_id":"s","solve_warnings":["HYPOTHESIS(pvl2_stated_order)"]}`
	captchaResponseGolden      = `{"headers":{},"payload":"https://geo.captcha-delivery.com/captcha/check?cid=abc123&icid=xyz","session_id":"missing"}`
)

func wantTags() datadome.TagsResponse {
	return datadome.TagsResponse{
		Payload: "jsData=%7B%7D&eventCounters=%5B%5D&cid=abc123",
		SessionResponse: datadome.SessionResponse{
			SessionID:        "b3f1c2d4e5a6978812345678",
			ExpiresInSeconds: 600,
			ClientHints: &datadome.ClientHints{
				Architecture: "x86", Bitness: "64", Mobile: false, Model: "", Platform: "Windows",
				PlatformVersion: "19.0.0", UAFullVersion: "151.0.7103.114", Wow64: true,
			},
			DeviceMemory: 8,
		},
	}
}

func wantInterstitial() datadome.InterstitialResponse {
	return datadome.InterstitialResponse{
		Payload: "cid=abc123&icid=xyz&ccid=&dm=cd&hash=8E2F",
		Headers: map[string]string{
			"sec-ch-device-memory": "8", "sec-ch-ua-arch": `"x86"`, "sec-ch-ua-mobile": "?0",
			"sec-ch-ua-model": `""`, "sec-ch-ua-platform": `"Windows"`,
		},
		SessionResponse: datadome.SessionResponse{SessionID: "s"},
		SolveWarnings:   []string{"HYPOTHESIS(pvl2_stated_order)"},
	}
}

func wantCaptcha() datadome.CaptchaResponse {
	return datadome.CaptchaResponse{
		Payload:         "https://geo.captcha-delivery.com/captcha/check?cid=abc123&icid=xyz",
		Headers:         map[string]string{},
		SessionResponse: datadome.SessionResponse{SessionID: "missing"},
	}
}

func TestResponseGoldensDecodeEveryField(t *testing.T) {
	var tags datadome.TagsResponse
	var interstitial datadome.InterstitialResponse
	var captcha datadome.CaptchaResponse
	tests := []struct {
		name      string
		body      string
		got, want any
	}{
		{"tags", tagsResponseGolden, &tags, wantTags()},
		{"interstitial", interstitialResponseGolden, &interstitial, wantInterstitial()},
		{"captcha", captchaResponseGolden, &captcha, wantCaptcha()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(test.body), test.got); err != nil {
				t.Fatal(err)
			}
			if got := reflect.ValueOf(test.got).Elem().Interface(); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("response\n got %+v\nwant %+v", got, test.want)
			}
		})
	}
}

func solveServer(t *testing.T, status int, body []byte) (*evade.Client, *[]byte, *string) {
	t.Helper()
	var sent []byte
	var line string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line = r.Method + " " + r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		sent = bytes.TrimSuffix(raw, []byte("\n"))
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	return client, &sent, &line
}

func withUnknownKey(body []byte) []byte {
	return append([]byte(`{"success":true,"warnings":["future"],`), body[1:]...)
}

func TestSolveStagesSendTaskAndModeAndDecode(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		mode     datadome.Mode
		request  string
		response string
		solve    func(*evade.Client) (any, error)
		want     any
	}{
		{datadome.ModeTags, tagsGolden, tagsResponseGolden,
			func(c *evade.Client) (any, error) { return datadome.SolveTags(ctx, c, tagsRequest()) }, wantTags()},
		{datadome.ModeInterstitial, `{"session_id":"s","device_link":"https://example.test/interstitial/","html":"page","script":"external interstitial script"}`, interstitialResponseGolden,
			func(c *evade.Client) (any, error) { return datadome.SolveInterstitial(ctx, c, interstitialRequest()) },
			wantInterstitial()},
		{datadome.ModeCaptcha, `{"session_id":"missing","page":"page","script":"external bundle","document_url":"https://challenge.example/captcha/","parent_url":"https://example.test/"}`, captchaResponseGolden,
			func(c *evade.Client) (any, error) { return datadome.SolveCaptcha(ctx, c, captchaRequest()) }, wantCaptcha()},
	}
	for _, test := range tests {
		t.Run(string(test.mode), func(t *testing.T) {
			client, sent, line := solveServer(t, http.StatusOK, withUnknownKey([]byte(test.response)))
			got, err := test.solve(client)
			if err != nil {
				t.Fatalf("solve: %v", err)
			}
			if *line != "POST /solve" {
				t.Fatalf("request line = %s", *line)
			}
			want := []byte(`{"task":"datadome","mode":"` + string(test.mode) + `",` + test.request[1:])
			if !bytes.Equal(*sent, want) {
				t.Fatalf("wire body\n got %s\nwant %s", *sent, want)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("response\n got %+v\nwant %+v", got, test.want)
			}
		})
	}
}

func TestSolveFailureReturnsZeroAndAPIError(t *testing.T) {
	client, _, _ := solveServer(t, http.StatusUnprocessableEntity,
		[]byte(`{"error":{"code":"challenge_unsupported","message":"bundle has no PVL2 worker"},"success":false}`))
	got, err := datadome.SolveCaptcha(context.Background(), client, captchaRequest())
	var apiErr *evade.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != evade.CodeChallengeUnsupported || apiErr.Message != "bundle has no PVL2 worker" {
		t.Fatalf("error = %v", err)
	}
	if !reflect.DeepEqual(got, datadome.CaptchaResponse{}) {
		t.Fatalf("failed solve returned %+v", got)
	}
}
