package shape_test

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
	"github.com/EvadeNow/evade-sdk/shape"
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

func fullRequest() shape.Request {
	skip := false
	return shape.Request{
		SessionID:                "0123456789abcdef0123456789abcdef",
		Proxy:                    "http://username:password@127.0.0.1:8080",
		TargetURL:                "https://www.southwest.com/air/booking/select-depart.html",
		ShapeJSURL:               "https://www.southwest.com/assets/app/scripts/swa-common.js",
		TargetAPI:                "https://www.southwest.com/api/air-booking/v1/air-booking/page/air/booking/shopping",
		TargetAPIMethod:          "POST",
		TargetAPIContentType:     "application/json",
		InteractionMode:          shape.InteractionModeActivation,
		InteractionBody:          `{"originationAirportCode":"DAL"}`,
		AuxiliaryNetworkMode:     shape.AuxiliaryNetworkPending,
		Referer:                  "https://www.southwest.com/",
		ReferrerPolicy:           "strict-origin-when-cross-origin",
		PageHTML:                 "<html><head><title>Fares & Deals</title></head></html>",
		LoaderSource:             "exact session loader",
		ChallengeSource:          "exact interstitial challenge",
		UA:                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36",
		FingerprintRecordID:      "rec-0123",
		Locale:                   "en-US",
		AcceptLanguage:           "en-US,en;q=0.9",
		TimeZone:                 "America/New_York",
		Cookies:                  shape.Cookies{{Name: "z_session", Value: "opaque-browser-cookie"}, {Name: "authenticated_session", Value: "first-party"}},
		RequestTransport:         shape.HeaderTransportFetch,
		FetchLoaderThroughProxy:  true,
		RetainSession:            true,
		SkipZeronaught:           &skip,
		Debug:                    true,
		IncludeInteractionTiming: true,
		PageProfile:              "none",
	}
}

// fullRequestGolden is fullRequest's wire form: cookies keep the browser's
// order, not encoding/json's sorted map order.
const fullRequestGolden = `{"session_id":"0123456789abcdef0123456789abcdef","proxy":"http://username:password@127.0.0.1:8080","target_url":"https://www.southwest.com/air/booking/select-depart.html","shape_js_url":"https://www.southwest.com/assets/app/scripts/swa-common.js","target_api":"https://www.southwest.com/api/air-booking/v1/air-booking/page/air/booking/shopping","target_api_method":"POST","target_api_content_type":"application/json","interaction_mode":"activation","interaction_body":"{\"originationAirportCode\":\"DAL\"}","auxiliary_network_mode":"pending","referer":"https://www.southwest.com/","referrer_policy":"strict-origin-when-cross-origin","page_html":"<html><head><title>Fares & Deals</title></head></html>","loader_source":"exact session loader","challenge_source":"exact interstitial challenge","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36","fingerprint_record_id":"rec-0123","locale":"en-US","accept_language":"en-US,en;q=0.9","time_zone":"America/New_York","cookies":{"z_session":"opaque-browser-cookie","authenticated_session":"first-party"},"request_transport":"fetch","fetch_loader_through_proxy":true,"retain_session":true,"skip_zeronaught":false,"debug":true,"include_interaction_timing":true,"page_profile":"none"}`

func TestRequestMatchesGolden(t *testing.T) {
	tests := []struct {
		name    string
		request shape.Request
		want    string
	}{
		{"full", fullRequest(), fullRequestGolden},
		{"minimal", shape.Request{
			Proxy:           "http://username:password@127.0.0.1:8080",
			TargetURL:       "https://www.southwest.com/air/booking/select-depart.html",
			ShapeJSURL:      "https://www.southwest.com/assets/app/scripts/swa-common.js",
			LoaderSource:    "exact session loader",
			ChallengeSource: "exact interstitial challenge",
			TargetAPI:       "https://www.southwest.com/api/air-booking/v1/air-booking/page/air/booking/shopping",
			TargetAPIMethod: "POST",
			Referer:         "https://www.southwest.com/",
			UA:              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36",
		}, `{"proxy":"http://username:password@127.0.0.1:8080","target_url":"https://www.southwest.com/air/booking/select-depart.html","shape_js_url":"https://www.southwest.com/assets/app/scripts/swa-common.js","target_api":"https://www.southwest.com/api/air-booking/v1/air-booking/page/air/booking/shopping","target_api_method":"POST","referer":"https://www.southwest.com/","loader_source":"exact session loader","challenge_source":"exact interstitial challenge","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36"}`},
		{"empty", shape.Request{}, `{"proxy":"","target_url":"","shape_js_url":"","target_api":"","target_api_method":""}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := encode(t, test.request), []byte(test.want); !bytes.Equal(got, want) {
				t.Fatalf("request\n got %s\nwant %s", got, want)
			}
		})
	}
}

func wantResponse() shape.Response {
	genMS := 41.5
	return shape.Response{
		Success:   true,
		Headers:   shape.Headers{{Name: "Cookie", Value: "session=cookie"}, {Name: "challenge-specific-name", Value: "generated"}},
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
		Timings: shape.Timings{
			RequestTotalMS: 112, LoaderQueueHit: true, LoaderQueueWaitMS: 9,
			LoaderQueueCapacity: 4, LoaderQueueReady: 3, LoaderQueueInflight: 1,
			LoaderProxyFallback: true, LoaderAgeMS: 1500, LoaderMS: 20, ChallengeMS: 5,
			OtherNetworkMS: 2, GenerationMS: 60, PayloadVerifyMS: 5, NetworkMS: 40, OtherMS: 8,
			Stages: &shape.Stages{
				ChallengeFetchMS: 0.68, FetchWallMS: 1494.32, FetchNetMS: 1493.64, BuildMS: 0.39,
				SessionOpenMS: 0.28, GenerateMS: 2.59, TailMS: 0.01, ZeronaughtWaitMS: 1210.5, ZeronaughtLateMS: 1.25,
			},
		},
		Warnings:        []string{shape.WarningSendTooEarly},
		SendAfterUnixMS: 1700000003410,
		SetCookies:      []shape.SetCookie{{URL: "https://www.southwest.com/assets/app/scripts/swa-common.js", SetCookie: "bm=1; Path=/; Secure"}},
		SessionID:       "0123456789abcdef0123456789abcdef",
		SessionReused:   true,
		SessionStep:     2,
		OneTime:         true,
		FingerprintHash: "profile123456789",
		SolveID:         "0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f",
		Debug: &shape.Debug{
			DeviceRecord: "rec-0123", ChallengeID: "challenge-7f3a",
			Build:       &shape.Build{VMProgramSHA256: "vm-program-digest", VMSHA256: "vm-digest", LoaderSHA256: "loader-digest", Runtime: "wasm-dispatch"},
			TLSProfile:  "safari_ios_18_5",
			Slots:       []shape.Slot{{Index: 3, Label: "canvas"}},
			GenMS:       &genMS,
			SessionStep: 2,
			DocumentAnchor: &shape.DocumentAnchor{Path: "token_issue_early_finalize", IssuedUnixMS: 1700000000000, NavigationIssueDelayMS: 1031.25,
				NavigationIssueDelayLaw: "HYPOTHESIS(navigation-issue-delay-band) morerewards.ca webkit/ios", CollectorStartLagMS: 1955.5, OriginAfterIssueMS: 924},
		},
	}
}

// responseGolden carries every member a /solve 200 body can hold; its
// headers object is in emission order, which Headers keeps.
const responseGolden = `{"success":true,"headers":{"Cookie":"session=cookie","challenge-specific-name":"generated"},"user_agent":"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1","timings":{"request_total_ms":112,"loader_queue_hit":true,"loader_queue_wait_ms":9,"loader_queue_capacity":4,"loader_queue_ready":3,"loader_queue_inflight":1,"loader_proxy_fallback":true,"loader_age_ms":1500,"loader_ms":20,"challenge_ms":5,"other_network_ms":2,"generation_ms":60,"payload_verification_ms":5,"network_ms":40,"other_ms":8,"stages":{"challenge_fetch_ms":0.68,"fetch_wall_ms":1494.32,"fetch_net_ms":1493.64,"build_ms":0.39,"session_open_ms":0.28,"generate_ms":2.59,"tail_ms":0.01,"zeronaught_wait_ms":1210.5,"zeronaught_late_ms":1.25}},"warnings":["send_too_early"],"send_after_unix_ms":1700000003410,"set_cookies":[{"url":"https://www.southwest.com/assets/app/scripts/swa-common.js","set_cookie":"bm=1; Path=/; Secure"}],"session_id":"0123456789abcdef0123456789abcdef","session_reused":true,"session_step":2,"one_time":true,"fingerprint_hash":"profile123456789","solve_id":"0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f","debug":{"device_record":"rec-0123","challenge_id":"challenge-7f3a","build":{"vm_program_sha256":"vm-program-digest","vm_sha256":"vm-digest","loader_sha256":"loader-digest","runtime":"wasm-dispatch"},"tls_profile":"safari_ios_18_5","slots":[{"index":3,"label":"canvas"}],"gen_ms":41.5,"session_step":2,"document_anchor":{"path":"token_issue_early_finalize","issued_unix_ms":1700000000000,"navigation_issue_delay_ms":1031.25,"navigation_issue_delay_law":"HYPOTHESIS(navigation-issue-delay-band) morerewards.ca webkit/ios","collector_start_lag_ms":1955.5,"origin_after_issue_ms":924}}}`

// TestResponseGoldenDecodesEveryField decodes strictly: a member the golden
// carries without a Response field fails here, so the types cover the wire.
func TestResponseGoldenDecodesEveryField(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(responseGolden))
	decoder.DisallowUnknownFields()
	var got shape.Response
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if want := wantResponse(); !reflect.DeepEqual(got, want) {
		t.Fatalf("response\n got %+v\nwant %+v", got, want)
	}
	encoded, err := json.Marshal(got.Headers)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"Cookie":"session=cookie","challenge-specific-name":"generated"}`; string(encoded) != want {
		t.Fatalf("headers encode as %s, want the emission-ordered object %s", encoded, want)
	}
}

// TestWaitForSendHoldsUntilSendAfter: an early response holds the caller
// until its send_after_unix_ms, a response without one does not hold, and a
// done context ends the hold with its error.
func TestWaitForSendHoldsUntilSendAfter(t *testing.T) {
	after := time.Now().Add(120 * time.Millisecond).UnixMilli()
	if err := (shape.Response{SendAfterUnixMS: after}).WaitForSend(context.Background()); err != nil {
		t.Fatal(err)
	}
	if now := time.Now().UnixMilli(); now < after {
		t.Fatalf("returned at %d, before send_after_unix_ms %d", now, after)
	}
	started := time.Now()
	if err := (shape.Response{}).WaitForSend(context.Background()); err != nil || time.Since(started) > 20*time.Millisecond {
		t.Fatalf("no send_after_unix_ms held %v (%v)", time.Since(started), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	far := shape.Response{SendAfterUnixMS: time.Now().Add(time.Hour).UnixMilli()}
	if err := far.WaitForSend(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled hold returned %v, want the context's deadline", err)
	}
}

func TestHeadersRefuseWhatHasNoOrderedForm(t *testing.T) {
	for _, test := range []struct{ body, want string }{
		{`{"x-a":"1","x-a":"2"}`, `header "x-a" appears twice`},
		{`{"x-a":1}`, `header "x-a" value is 1, not a string`},
		{`[{"name":"x-a","value":"1"}]`, "not a JSON object"},
	} {
		var headers shape.Headers
		if err := json.Unmarshal([]byte(test.body), &headers); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("headers %s: error = %v, want %q", test.body, err, test.want)
		}
	}
}

func TestSolveSendsTaskAndToleratesUnknownResponseKeys(t *testing.T) {
	body := []byte(`{"payload_decode":{"decode_source":"x"},"vm_url":"https://example.test/vm.js",` + responseGolden[1:])
	var method, path string
	var sent []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		sent, _ = io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := shape.Solve(context.Background(), client, fullRequest())
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if method != http.MethodPost || path != "/solve" {
		t.Fatalf("request line = %s %s", method, path)
	}
	want := []byte(`{"task":"shape",` + fullRequestGolden[1:])
	if sent = bytes.TrimSuffix(sent, []byte("\n")); !bytes.Equal(sent, want) {
		t.Fatalf("wire body\n got %s\nwant %s", sent, want)
	}
	if !reflect.DeepEqual(got, wantResponse()) {
		t.Fatalf("response = %+v", got)
	}
}

// TestSolveSendsPageHTMLByteForByte: an interstitial document (markup,
// script operators, entities, a raw U+2028) reaches the solver as
// page_html with no HTML escaping and decodes to the same bytes.
func TestSolveSendsPageHTMLByteForByte(t *testing.T) {
	page := "<!doctype html>\n<html><head><title></title></head><body>\r\n<script>if (a < b && c > d) { s = '&amp;' + \"\u2028\"; }</script>\n" +
		"<script>var originalHeaders = [\"Accept\", \"text/html\"];</script></body></html>\n"
	var sent []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(responseGolden))
	}))
	defer server.Close()
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	request := shape.Request{TargetURL: "https://p-bandai.jp/item/item-1/", TargetAPI: "https://p-bandai.jp/item/item-1/",
		TargetAPIMethod: http.MethodGet, PageHTML: page}
	if _, err := shape.Solve(context.Background(), client, request); err != nil {
		t.Fatalf("Solve: %v", err)
	}
	for _, escaped := range []string{`\u003c`, `\u003e`, `\u0026`} {
		if bytes.Contains(sent, []byte(escaped)) {
			t.Errorf("wire body HTML-escapes the page (%s): %s", escaped, sent)
		}
	}
	var got struct {
		PageHTML string `json:"page_html"`
	}
	if err := json.Unmarshal(sent, &got); err != nil {
		t.Fatal(err)
	}
	if got.PageHTML != page {
		t.Fatalf("page_html decodes to %q, want %q", got.PageHTML, page)
	}
}

// TestSolveRefusesSourcesJSONCannotCarry: a source body with a byte that
// is not UTF-8 (a Shift_JIS page's own bytes) would reach the solver
// replaced; Solve refuses it, naming the field and byte, and sends nothing.
func TestSolveRefusesSourcesJSONCannotCarry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a request with a non-UTF-8 source reached the server")
	}))
	defer server.Close()
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	const shiftJIS = "<title>\x82\xa0</title>"
	for _, test := range []struct {
		field   string
		request shape.Request
	}{
		{"page_html", shape.Request{PageHTML: shiftJIS}},
		{"loader_source", shape.Request{LoaderSource: shiftJIS}},
		{"challenge_source", shape.Request{ChallengeSource: shiftJIS}},
	} {
		got, err := shape.Solve(context.Background(), client, test.request)
		var refused *shape.NotUTF8Error
		if !errors.As(err, &refused) || refused.Field != test.field || refused.Offset != len("<title>") {
			t.Errorf("%s: error %v, want NotUTF8Error at byte %d", test.field, err, len("<title>"))
		}
		if !reflect.DeepEqual(got, shape.Response{}) {
			t.Errorf("%s: refused Solve returned %+v", test.field, got)
		}
	}
}

func TestSolveFailureReturnsZeroAndAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"success":false,"error":{"code":"solve_failed","message":"failed","challenge_variant_id":"v1"}}`)
	}))
	defer server.Close()
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := shape.Solve(context.Background(), client, shape.Request{})
	var apiErr *evade.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != evade.CodeSolveFailed || apiErr.ChallengeVariantID != "v1" {
		t.Fatalf("error = %v", err)
	}
	if !reflect.DeepEqual(got, shape.Response{}) {
		t.Fatalf("failed Solve returned %+v", got)
	}
}

// TestSolveDebugFailureCarriesStop: a debug request's failure body carries
// the typed stop under debug, beside the public error.
func TestSolveDebugFailureCarriesStop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"success":false,"solve_id":"0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f","error":{"code":"solve_failed","message":"generate: law_unresolved","challenge_variant_id":"challenge-7f3a"},`+
			`"debug":{"stage":"generate","reason":"law_unresolved","label":"canvas","field":"width","detail":"no law for the slot",`+
			`"extraction_failures":[{"class":"slot-map","param":"labels","reason":"slot-map.anchor_missing"}],`+
			`"partial":{"device_record":"rec-0123","challenge_id":"challenge-7f3a"},"not_found":true}}`)
	}))
	defer server.Close()
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = shape.Solve(context.Background(), client, shape.Request{Debug: true})
	var apiErr *evade.APIError
	if !errors.As(err, &apiErr) || apiErr.Stop == nil {
		t.Fatalf("error = %#v, want an *evade.APIError with a Stop", err)
	}
	want := evade.Stop{
		Stage: "generate", Reason: "law_unresolved", Label: "canvas", Field: "width", Detail: "no law for the slot",
		ExtractionFailures: []evade.ExtractionFailure{{Class: "slot-map", Param: "labels", Reason: "slot-map.anchor_missing"}},
		Partial:            json.RawMessage(`{"device_record":"rec-0123","challenge_id":"challenge-7f3a"}`),
		NotFound:           true,
	}
	if !reflect.DeepEqual(*apiErr.Stop, want) || apiErr.ChallengeVariantID != "challenge-7f3a" {
		t.Fatalf("stop = %+v, challenge %q", *apiErr.Stop, apiErr.ChallengeVariantID)
	}
	if text := err.Error(); text != "evade: 422 solve_failed: generate/law_unresolved label=canvas field=width: no law for the slot" {
		t.Fatalf("Error() = %q", text)
	}
}

func TestCloseSession(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		code   evade.Code
	}{
		{"closed", http.StatusNoContent, "", ""},
		{"lifecycle unavailable", http.StatusServiceUnavailable,
			`{"success":false,"error":{"code":"session_unavailable","message":"solve session lifecycle is unavailable"}}`,
			evade.CodeSessionUnavailable},
		{"unexpected 200", http.StatusOK, `{}`, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var method, rawPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method, rawPath = r.Method, r.URL.EscapedPath()
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client, err := evade.NewClient(evade.Config{BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			err = shape.CloseSession(context.Background(), client, "a/b c")
			if method != http.MethodDelete || rawPath != "/solve/session/a%2Fb%20c" {
				t.Fatalf("request line = %s %s", method, rawPath)
			}
			if test.status == http.StatusNoContent {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var apiErr *evade.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != test.status || apiErr.Code != test.code {
				t.Fatalf("error = %#v, want *APIError status %d code %q", err, test.status, test.code)
			}
		})
	}
}

func fullOutcomeReport() shape.OutcomeReport {
	return shape.OutcomeReport{
		SolveID:      "0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f",
		Outcome:      shape.OutcomeBlocked,
		TargetStatus: 403,
		Note:         "akamai & shape block page",
	}
}

func TestOutcomeReportMatchesGolden(t *testing.T) {
	tests := []struct {
		name   string
		report shape.OutcomeReport
		want   string
	}{
		{"full", fullOutcomeReport(), `{"solve_id":"0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f","outcome":"blocked","target_status":403,"note":"akamai & shape block page"}`},
		{"minimal", shape.OutcomeReport{
			SolveID: "0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f",
			Outcome: shape.OutcomeSuccess,
		}, `{"solve_id":"0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f","outcome":"success"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := encode(t, test.report), []byte(test.want); !bytes.Equal(got, want) {
				t.Fatalf("outcome report\n got %s\nwant %s", got, want)
			}
		})
	}
}

func wantOutcomeResponse() shape.OutcomeResponse {
	return shape.OutcomeResponse{
		Success: true,
		SolveID: "0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f",
		Outcome: shape.OutcomeBlocked,
	}
}

func TestOutcomeResponseGoldenDecodesEveryField(t *testing.T) {
	var got shape.OutcomeResponse
	if err := json.Unmarshal([]byte(`{"success":true,"solve_id":"0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f","outcome":"blocked"}`), &got); err != nil {
		t.Fatal(err)
	}
	if want := wantOutcomeResponse(); !reflect.DeepEqual(got, want) {
		t.Fatalf("outcome response\n got %+v\nwant %+v", got, want)
	}
}

func TestReportOutcomeSendsReportWithoutTask(t *testing.T) {
	body := []byte(`{"success":true,"solve_id":"0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f","outcome":"blocked"}`)
	var method, path string
	var sent []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		sent, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := shape.ReportOutcome(context.Background(), client, fullOutcomeReport())
	if err != nil {
		t.Fatalf("ReportOutcome: %v", err)
	}
	if method != http.MethodPost || path != "/solve/outcome" {
		t.Fatalf("request line = %s %s", method, path)
	}
	// The server rejects unknown fields, so the body is the report alone.
	want := []byte(`{"solve_id":"0199e2a4-5b1c-7d3e-8f40-1a2b3c4d5e6f","outcome":"blocked","target_status":403,"note":"akamai & shape block page"}`)
	if sent = bytes.TrimSuffix(sent, []byte("\n")); !bytes.Equal(sent, want) {
		t.Fatalf("wire body\n got %s\nwant %s", sent, want)
	}
	if want := wantOutcomeResponse(); got == nil || !reflect.DeepEqual(*got, want) {
		t.Fatalf("response = %+v", got)
	}
}

func TestReportOutcomeNotFoundReturnsNilAndAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"success":false,"error":{"code":"solve_not_found","message":"solve not found; if it just finished, retry in a few seconds"}}`)
	}))
	defer server.Close()
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := shape.ReportOutcome(context.Background(), client, fullOutcomeReport())
	var apiErr *evade.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound || apiErr.Code != "solve_not_found" {
		t.Fatalf("error = %#v", err)
	}
	if got != nil {
		t.Fatalf("failed ReportOutcome returned %+v", got)
	}
}
