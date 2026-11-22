package akamai_test

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

	evade "github.com/EvadeNow/evade-sdk"
	"github.com/EvadeNow/evade-sdk/akamai"
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

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"

func sensorRequest() akamai.SensorRequest {
	pace := false
	return akamai.SensorRequest{
		URL: "https://www.example.com/booking?from=SYD&to=MEL", UA: ua,
		Abck: "0123456789ABCDEF0123456789ABCDEF~-1~YAAQ~-1~-1~-1", BmSz: "0123ABCD~YAAQ",
		ScriptID:  "8fc7ebcf46557fffda26f3b5f193a5193e78a848a1ab88a56b077d2ffebe9a4c",
		Script:    []byte("bmak.sensor();"),
		ScriptURL: "https://www.example.com/aB3/cD4",
		SBSDSource: &akamai.SBSDSource{
			ScriptURL: "https://www.example.com/.well-known/sbsd/x1", Script: []byte("sbsd.init();"),
		},
		AcceptLanguage: "en-US,en;q=0.9", Language: "en-US", Timezone: "Australia/Sydney", ExitCountry: "AU",
		Pace: &pace, Telemetry: true,
	}
}

func sbsdRequest() akamai.SBSDRequest {
	return akamai.SBSDRequest{
		URL: "https://www.example.com/booking?from=SYD&to=MEL", UA: ua,
		ScriptID:  "a7059f940c71ddc5bc19ac8957fd41de115456750dc6e329e22a13d389c93524",
		Script:    []byte("sbsd.init();"),
		ScriptURL: "https://www.example.com/.well-known/sbsd/x1?v=2", SBSDo: "0A1B2C~-1~",
		AcceptLanguage: "en-US,en;q=0.9", Language: "en-US", Timezone: "Australia/Sydney", ExitCountry: "AU", UUID: "tab-0123",
		PageResources: &akamai.PageResources{
			PageURL: "https://www.example.com/booking?from=SYD&to=MEL",
			DOM: []akamai.ResourceURL{
				{Kind: "link", URL: "https://www.example.com/a.css"},
				{Kind: "script", URL: "https://www.example.com/aB3/cD4"},
			},
			Performance: []akamai.ResourceURL{},
		},
	}
}

func telemetryRequest() akamai.SBSDRequest {
	hold := true
	return akamai.SBSDRequest{
		URL: "https://www.example.com/booking?from=SYD&to=MEL", UA: ua,
		ScriptURL: "https://www.example.com/.well-known/sbsd/x1?v=2", SBSDo: "0A1B2C~-1~",
		Session: "c2Vzc2lvbi10b2tlbg", SBSDPost: "telemetry", Pace: &hold,
	}
}

// Goldens: script bytes travel base64, HTML and & unescaped, ResourceURL
// keys as the server's Kind and URL.
const (
	sensorGolden    = `{"url":"https://www.example.com/booking?from=SYD&to=MEL","ua":"` + ua + `","abck":"0123456789ABCDEF0123456789ABCDEF~-1~YAAQ~-1~-1~-1","bm_sz":"0123ABCD~YAAQ","script_id":"8fc7ebcf46557fffda26f3b5f193a5193e78a848a1ab88a56b077d2ffebe9a4c","script":"Ym1hay5zZW5zb3IoKTs=","script_url":"https://www.example.com/aB3/cD4","sbsd_source":{"script_url":"https://www.example.com/.well-known/sbsd/x1","script":"c2JzZC5pbml0KCk7"},"accept_language":"en-US,en;q=0.9","language":"en-US","timezone":"Australia/Sydney","exit_country":"AU","pace":false,"telemetry":true}`
	sbsdGolden      = `{"url":"https://www.example.com/booking?from=SYD&to=MEL","ua":"` + ua + `","script_id":"a7059f940c71ddc5bc19ac8957fd41de115456750dc6e329e22a13d389c93524","script":"c2JzZC5pbml0KCk7","script_url":"https://www.example.com/.well-known/sbsd/x1?v=2","sbsd_o":"0A1B2C~-1~","accept_language":"en-US,en;q=0.9","language":"en-US","timezone":"Australia/Sydney","exit_country":"AU","uuid":"tab-0123","page_resources":{"page_url":"https://www.example.com/booking?from=SYD&to=MEL","dom":[{"Kind":"link","URL":"https://www.example.com/a.css"},{"Kind":"script","URL":"https://www.example.com/aB3/cD4"}],"performance":[]}}`
	telemetryGolden = `{"url":"https://www.example.com/booking?from=SYD&to=MEL","ua":"` + ua + `","script_url":"https://www.example.com/.well-known/sbsd/x1?v=2","sbsd_o":"0A1B2C~-1~","session":"c2Vzc2lvbi10b2tlbg","sbsd_post":"telemetry","pace":true}`
	openGolden      = `{"url":"https://www.example.com/booking?from=SYD&to=MEL","ua":"` + ua + `","language":"en-US","timezone":"Australia/Sydney","exit_country":"AU"}`
)

func TestRequestsMatchGolden(t *testing.T) {
	tests := []struct {
		name    string
		request any
		want    string
	}{
		{"sensor", sensorRequest(), sensorGolden},
		{"sensor_continuation", akamai.SensorRequest{
			URL: "https://www.example.com/booking", UA: ua, Abck: "abck", BmSz: "bmsz",
			ScriptURL: "https://www.example.com/aB3/cD4", Session: "c2Vzc2lvbi10b2tlbg",
		}, `{"url":"https://www.example.com/booking","ua":"` + ua + `","abck":"abck","bm_sz":"bmsz","script_url":"https://www.example.com/aB3/cD4","session":"c2Vzc2lvbi10b2tlbg"}`},
		{"sbsd", sbsdRequest(), sbsdGolden},
		{"sbsd_telemetry", telemetryRequest(), telemetryGolden},
		{"open", openRequest(), openGolden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := encode(t, test.request), []byte(test.want); !bytes.Equal(got, want) {
				t.Fatalf("request\n got %s\nwant %s", got, want)
			}
		})
	}
}

const (
	hintsGolden             = `{"sec-ch-ua":"\"Chromium\";v=\"157\", \"Google Chrome\";v=\"157\"","sec-ch-ua-mobile":"?0","sec-ch-ua-full-version":"\"157.0.7390.55\"","sec-ch-ua-arch":"\"x86\"","sec-ch-ua-platform":"\"Windows\"","sec-ch-ua-platform-version":"\"19.0.0\"","sec-ch-ua-model":"\"\"","sec-ch-ua-bitness":"\"64\"","sec-ch-ua-wow64":"?0","sec-ch-ua-full-version-list":"\"Chromium\";v=\"157.0.7390.55\", \"Google Chrome\";v=\"157.0.7390.55\"","sec-ch-ua-form-factors":"\"Desktop\""}`
	sensorResponseGolden    = `{"success":true,"sensor_data":"3;0;1;2048;3684534;abc","ua":"` + ua + `","session":"c2Vzc2lvbi10b2tlbg","language":"en-US,en;q=0.9","accept_encoding":"gzip, deflate, br, zstd","script_id":"8fc7ebcf46557fffda26f3b5f193a5193e78a848a1ab88a56b077d2ffebe9a4c","client_hints":` + hintsGolden + `,"telemetry":"a=0123456789ABCDEF0123456789ABCDEF&&&e=0123ABCD~YAAQ&&&sensor_data=MzswOzE=","paced_ms":412}`
	sbsdResponseGolden      = `{"success":true,"body":"encrypted-fingerprint","session":"c2Vzc2lvbi10b2tlbg","script_id":"a7059f940c71ddc5bc19ac8957fd41de115456750dc6e329e22a13d389c93524","accept_encoding":"gzip, deflate, br, zstd","client_hints":` + hintsGolden + `,"fingerprint_ms":1840}`
	telemetryResponseGolden = `{"success":true,"body":"encrypted-telemetry","session":"c2Vzc2lvbi10b2tlbg","script_id":"a7059f940c71ddc5bc19ac8957fd41de115456750dc6e329e22a13d389c93524","accept_encoding":"gzip, deflate, br, zstd","client_hints":` + hintsGolden + `,"sbsd_post":"telemetry","ind":1,"wait_ms":0,"sbsd_trigger":"timer"}`
	openResponseGolden      = `{"success":true,"session":"c2Vzc2lvbi10b2tlbg"}`
	notDueGolden            = `{"success":false,"error_code":"sbsd_telemetry_not_due","message":"current-script telemetry input threshold is not met","stage":"telemetry","reason":"second_post_input"}`
)

func wantHints() akamai.ClientHints {
	return akamai.ClientHints{
		UA: `"Chromium";v="157", "Google Chrome";v="157"`, Mobile: "?0", FullVersion: `"157.0.7390.55"`,
		Architecture: `"x86"`, Platform: `"Windows"`, PlatformVersion: `"19.0.0"`, Model: `""`, Bitness: `"64"`,
		Wow64: "?0", FullVersionList: `"Chromium";v="157.0.7390.55", "Google Chrome";v="157.0.7390.55"`,
		FormFactors: `"Desktop"`,
	}
}

func wantSensor() akamai.SensorResponse {
	return akamai.SensorResponse{
		Success: true, SensorData: "3;0;1;2048;3684534;abc", UA: ua, Session: "c2Vzc2lvbi10b2tlbg",
		Language: "en-US,en;q=0.9", AcceptEncoding: "gzip, deflate, br, zstd",
		ScriptID:    "8fc7ebcf46557fffda26f3b5f193a5193e78a848a1ab88a56b077d2ffebe9a4c",
		ClientHints: wantHints(),
		Telemetry:   "a=0123456789ABCDEF0123456789ABCDEF&&&e=0123ABCD~YAAQ&&&sensor_data=MzswOzE=", PacedMS: 412,
	}
}

func wantSBSD() akamai.SBSDResponse {
	fingerprint := int64(1840)
	return akamai.SBSDResponse{
		Success: true, Body: "encrypted-fingerprint", Session: "c2Vzc2lvbi10b2tlbg",
		ScriptID: "a7059f940c71ddc5bc19ac8957fd41de115456750dc6e329e22a13d389c93524", AcceptEncoding: "gzip, deflate, br, zstd",
		ClientHints: wantHints(), FingerprintMS: &fingerprint,
	}
}

func openRequest() akamai.OpenRequest {
	return akamai.OpenRequest{
		URL: "https://www.example.com/booking?from=SYD&to=MEL", UA: ua,
		Language: "en-US", Timezone: "Australia/Sydney", ExitCountry: "AU",
	}
}

func wantOpen() akamai.OpenResponse {
	return akamai.OpenResponse{Success: true, Session: "c2Vzc2lvbi10b2tlbg"}
}

func wantTelemetry() akamai.SBSDResponse {
	var due int64
	return akamai.SBSDResponse{
		Success: true, Body: "encrypted-telemetry", Session: "c2Vzc2lvbi10b2tlbg",
		ScriptID: "a7059f940c71ddc5bc19ac8957fd41de115456750dc6e329e22a13d389c93524", AcceptEncoding: "gzip, deflate, br, zstd",
		ClientHints: wantHints(),
		SBSDPost:    "telemetry", Index: 1, WaitMS: &due, Trigger: "timer",
	}
}

// TestResponseGoldensDecodeEveryField decodes strictly: a member a golden
// carries without a field fails here, so the types cover the wire.
func TestResponseGoldensDecodeEveryField(t *testing.T) {
	var sensor akamai.SensorResponse
	var sbsd, telemetry akamai.SBSDResponse
	var failure akamai.ErrorResponse
	var open akamai.OpenResponse
	tests := []struct {
		name      string
		body      string
		got, want any
	}{
		{"sensor", sensorResponseGolden, &sensor, wantSensor()},
		{"sbsd", sbsdResponseGolden, &sbsd, wantSBSD()},
		{"sbsd_telemetry", telemetryResponseGolden, &telemetry, wantTelemetry()},
		{"open", openResponseGolden, &open, wantOpen()},
		{"error", notDueGolden, &failure, akamai.ErrorResponse{
			ErrorCode: "sbsd_telemetry_not_due", Message: "current-script telemetry input threshold is not met",
			Stage: "telemetry", Reason: "second_post_input",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := json.NewDecoder(strings.NewReader(test.body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(test.got); err != nil {
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

func withUnknownKey(body string) []byte {
	return []byte(`{"warnings":["future"],` + body[1:])
}

func TestSolveModesSendTaskAndModeAndDecode(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		mode     akamai.Mode
		status   int
		request  string
		response string
		solve    func(*evade.Client) (any, error)
		want     any
	}{
		{"sensor", akamai.ModeSensor, http.StatusOK, sensorGolden, sensorResponseGolden,
			func(c *evade.Client) (any, error) { return akamai.SolveSensor(ctx, c, sensorRequest()) }, wantSensor()},
		{"sbsd", akamai.ModeSBSD, http.StatusOK, sbsdGolden, sbsdResponseGolden,
			func(c *evade.Client) (any, error) { return akamai.SolveSBSD(ctx, c, sbsdRequest()) }, wantSBSD()},
		{"sbsd_telemetry", akamai.ModeSBSD, http.StatusOK, telemetryGolden, telemetryResponseGolden,
			func(c *evade.Client) (any, error) { return akamai.SolveSBSD(ctx, c, telemetryRequest()) }, wantTelemetry()},
		{"open", akamai.ModeOpen, http.StatusCreated, openGolden, openResponseGolden,
			func(c *evade.Client) (any, error) { return akamai.Open(ctx, c, openRequest()) }, wantOpen()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, sent, line := solveServer(t, test.status, withUnknownKey(test.response))
			got, err := test.solve(client)
			if err != nil {
				t.Fatalf("solve: %v", err)
			}
			if *line != "POST /solve" {
				t.Fatalf("request line = %s", *line)
			}
			want := []byte(`{"task":"akamai","mode":"` + string(test.mode) + `",` + test.request[1:])
			if !bytes.Equal(*sent, want) {
				t.Fatalf("wire body\n got %s\nwant %s", *sent, want)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("response\n got %+v\nwant %+v", got, test.want)
			}
		})
	}
}

// TestSolveFailureReturnsZeroAndAPIError: /solve's own failure body is not
// the shared envelope, so Message carries it whole (an ErrorResponse); an
// auth refusal is the envelope and carries Code.
func TestSolveFailureReturnsZeroAndAPIError(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		status  int
		body    string
		solve   func(*evade.Client) (any, error)
		zero    any
		code    evade.Code
		message string
	}{
		{"solve", http.StatusConflict, notDueGolden,
			func(c *evade.Client) (any, error) { return akamai.SolveSBSD(ctx, c, telemetryRequest()) },
			akamai.SBSDResponse{}, "", notDueGolden},
		{"auth", http.StatusForbidden, `{"success":false,"error":{"code":"insufficient_scope","message":"key lacks solver akamai"}}`,
			func(c *evade.Client) (any, error) { return akamai.SolveSensor(ctx, c, sensorRequest()) },
			akamai.SensorResponse{}, evade.CodeInsufficientScope, "key lacks solver akamai"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _, _ := solveServer(t, test.status, []byte(test.body+"\n"))
			got, err := test.solve(client)
			var apiErr *evade.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != test.status || apiErr.Code != test.code ||
				apiErr.Message != test.message {
				t.Fatalf("error = %#v", err)
			}
			if !reflect.DeepEqual(got, test.zero) {
				t.Fatalf("failed solve returned %+v", got)
			}
		})
	}
}
