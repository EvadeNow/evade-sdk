package akamai_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	evade "github.com/EvadeNow/evade-sdk"
	"github.com/EvadeNow/evade-sdk/akamai"
	fhttp "github.com/bogdanfinn/fhttp"
)

const (
	pageURL   = "https://www.example.com/booking?from=SYD&to=MEL"
	sensorURL = "https://www.example.com/aB3/cD4"
	sbsdURL   = "https://www.example.com/.well-known/sbsd/x1?v=2"
	token     = "c2Vzc2lvbi10b2tlbg"
)

var (
	sensorJS = []byte("bmak.sensor();")
	sbsdJS   = []byte("sbsd.init();")
)

func sha(b []byte) string {
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}

type exchange struct {
	want   string // the exact /solve body
	status int
	answer string
}

// scripted answers each /solve request with the next exchange, failing
// the test on a body other than the one the server expects.
func scripted(t *testing.T, steps []exchange) *evade.Client {
	t.Helper()
	var mu sync.Mutex
	next := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		i := next
		next++
		mu.Unlock()
		if i >= len(steps) {
			t.Errorf("unexpected request %s", raw)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if got := string(bytes.TrimSuffix(raw, []byte("\n"))); got != steps[i].want {
			t.Errorf("request %d\n got %s\nwant %s", i+1, got, steps[i].want)
		}
		w.WriteHeader(steps[i].status)
		_, _ = w.Write([]byte(steps[i].answer))
	}))
	t.Cleanup(func() {
		server.Close()
		if next != len(steps) {
			t.Errorf("served %d of %d exchanges", next, len(steps))
		}
	})
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL, APIKey: "k", MaxRetries: new(0)})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func head(mode string) string {
	return `{"task":"akamai","mode":"` + mode + `","url":"` + pageURL + `","ua":"` + ua + `"`
}

const (
	cacheMissGolden = `{"success":false,"error_code":"script_cache_miss","message":"script_id is not present in the script cache","stage":"script"}`
	completeGolden  = `{"success":false,"error_code":"sbsd_telemetry_complete","message":"SBSD telemetry is complete for this session","stage":"telemetry","reason":"complete"}`
)

// TestSessionLifecycle drives the runner's order (akamai/live/qantas.go,
// bypass_fast.go runAkamaiAPIProtection): open, sensor script upload,
// sensor 1 (a cache miss resent with the source), SBSD upload, the
// fingerprint post, sensors until the _abck field or the three-post cap
// stops them, telemetry until the 409 complete.
func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	sensorFirst := head("sensor") + `,"abck":"A~-1~YAAQ~-1","bm_sz":"B","script_id":"` + sha(sensorJS) + `"`
	sensorLater := func(abck string) string {
		return head("sensor") + `,"abck":"` + abck + `","bm_sz":"B","script_url":"` + sensorURL + `","session":"` + token + `"}`
	}
	telemetry := head("sbsd") + `,"script_url":"` + sbsdURL + `","sbsd_o":"O","session":"` + token + `","sbsd_post":"telemetry"}`
	client := scripted(t, []exchange{
		{head("open") + `,"language":"en-US","timezone":"Australia/Sydney","exit_country":"AU"}`, http.StatusCreated, openResponseGolden},
		{head("open") + `,"script_id":"` + sha(sensorJS) + `","script":"Ym1hay5zZW5zb3IoKTs=","script_url":"` + sensorURL + `","session":"` + token + `"}`, http.StatusCreated, openResponseGolden},
		{sensorFirst + `,"script_url":"` + sensorURL + `","session":"` + token + `"}`, http.StatusConflict, cacheMissGolden},
		{sensorFirst + `,"script":"Ym1hay5zZW5zb3IoKTs=","script_url":"` + sensorURL + `","session":"` + token + `"}`, http.StatusOK, sensorResponseGolden},
		{head("open") + `,"sbsd_source":{"script_url":"` + sbsdURL + `","script":"c2JzZC5pbml0KCk7"},"session":"` + token + `"}`, http.StatusCreated, openResponseGolden},
		{head("sbsd") + `,"script_id":"` + sha(sbsdJS) + `","script_url":"` + sbsdURL + `","sbsd_o":"O","session":"` + token + `","page_resources":{"page_url":"` + pageURL + `","dom":[{"Kind":"script","URL":"` + sensorURL + `"}],"performance":[]}}`, http.StatusOK, sbsdResponseGolden},
		{sensorLater("A~1~YAAQ~-1"), http.StatusOK, sensorResponseGolden},
		{sensorLater("A~1~YAAQ~-1"), http.StatusOK, sensorResponseGolden},
		{telemetry, http.StatusOK, telemetryResponseGolden},
		{telemetry, http.StatusConflict, completeGolden},
	})

	session, err := akamai.Open(ctx, client, openRequest())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if session.ID != token || session.URL != pageURL || session.UA != ua {
		t.Fatalf("session = %+v", session)
	}
	if err := session.UploadSensorScript(ctx, sensorURL, sensorJS); err != nil {
		t.Fatalf("UploadSensorScript: %v", err)
	}
	if _, err := session.SensorPost("x"); err == nil {
		t.Fatal("SensorPost before a sensor answer: want an error (no Accept-Language yet)")
	}
	needs(t, session, "A~-1~YAAQ~-1", true)
	if _, err := session.Sensor(ctx, "A~-1~YAAQ~-1", "B"); err != nil {
		t.Fatalf("Sensor 1: %v", err)
	}
	if err := session.UploadSBSDScript(ctx, sbsdURL, sbsdJS); err != nil {
		t.Fatalf("UploadSBSDScript: %v", err)
	}
	session.PageResources = &akamai.PageResources{PageURL: pageURL, DOM: []akamai.ResourceURL{{Kind: "script", URL: sensorURL}}, Performance: []akamai.ResourceURL{}}
	fingerprint, err := session.SBSDFingerprint(ctx, "O")
	if err != nil {
		t.Fatalf("SBSDFingerprint: %v", err)
	}
	if err := akamai.WaitForFingerprint(ctx, time.Now().Add(-time.Hour), fingerprint); err != nil {
		t.Fatalf("WaitForFingerprint: %v", err)
	}
	for posts := 1; ; posts++ {
		abck := "A~1~YAAQ~-1"
		if more, err := session.NeedsSensor(abck); err != nil || !more {
			if posts != 3 || err != nil {
				t.Fatalf("NeedsSensor after %d posts = %v, %v; want the three-post cap to stop at 3", posts, more, err)
			}
			break
		}
		needs(t, session, "A~0~YAAQ~-1", false)
		if _, err := session.Sensor(ctx, abck, "B"); err != nil {
			t.Fatalf("Sensor %d: %v", posts+1, err)
		}
	}
	answer, err := session.SBSDTelemetry(ctx, "O")
	if err != nil || answer.Body != "encrypted-telemetry" {
		t.Fatalf("SBSDTelemetry = %+v, %v", answer, err)
	}
	_, err = session.SBSDTelemetry(ctx, "O")
	var done *akamai.Done
	if !errors.As(err, &done) || done.Code != akamai.CodeTelemetryComplete || done.Reason != "complete" {
		t.Fatalf("SBSDTelemetry at the end = %#v, want *akamai.Done", err)
	}
}

func needs(t *testing.T, s *akamai.Session, abck string, want bool) {
	t.Helper()
	if got, err := s.NeedsSensor(abck); err != nil || got != want {
		t.Fatalf("NeedsSensor(%q) = %v, %v; want %v", abck, got, err, want)
	}
}

// mode answers by request mode: opens 201, sensor and fingerprint posts
// their goldens, the telemetry post telemetry.
func mode(t *testing.T, telemetry exchange) *evade.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Mode     string `json:"mode"`
			SBSDPost string `json:"sbsd_post"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		switch {
		case request.Mode == "sensor":
			_, _ = w.Write([]byte(sensorResponseGolden))
		case request.Mode == "open":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(openResponseGolden))
		case request.SBSDPost == "telemetry":
			w.WriteHeader(telemetry.status)
			_, _ = w.Write([]byte(telemetry.answer))
		default:
			_, _ = w.Write([]byte(sbsdResponseGolden))
		}
	}))
	t.Cleanup(server.Close)
	client, err := evade.NewClient(evade.Config{BaseURL: server.URL, MaxRetries: new(0)})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// The runner stops on 409 complete/complete and not_due/no_input or
// second_post_input (bypass_fast.go telemetryNotDue); every other 409 is a
// failure.
func TestSBSDTelemetryDoneMapping(t *testing.T) {
	tests := []struct {
		name, body string
		done       bool
	}{
		{"complete", completeGolden, true},
		{"no_input", `{"success":false,"error_code":"sbsd_telemetry_not_due","message":"no current-session input is available for SBSD telemetry","stage":"telemetry","reason":"no_input"}`, true},
		{"second_post_input", notDueGolden, true},
		{"needs_fingerprint", `{"success":false,"error_code":"sbsd_telemetry_needs_fingerprint","message":"SBSD telemetry requires a completed fingerprint post","stage":"telemetry","reason":"no_fingerprint"}`, false},
		{"not_due_unknown_reason", `{"success":false,"error_code":"sbsd_telemetry_not_due","message":"m","stage":"telemetry","reason":"later"}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			session, err := akamai.Open(ctx, mode(t, exchange{status: http.StatusConflict, answer: test.body}), openRequest())
			if err != nil {
				t.Fatal(err)
			}
			if err := session.UploadSBSDScript(ctx, sbsdURL, sbsdJS); err != nil {
				t.Fatal(err)
			}
			if _, err := session.SBSDFingerprint(ctx, "O"); err != nil {
				t.Fatal(err)
			}
			_, err = session.SBSDTelemetry(ctx, "O")
			var done *akamai.Done
			var failure *akamai.Error
			switch {
			case test.done && !errors.As(err, &done):
				t.Fatalf("err = %#v, want *akamai.Done", err)
			case !test.done && (errors.As(err, &done) || !errors.As(err, &failure) || failure.Status != http.StatusConflict):
				t.Fatalf("err = %#v, want a 409 *akamai.Error", err)
			}
		})
	}
}

// TestPostsCarryTheSessionHeaders: the sensor and SBSD posts as the page
// sends them (bypass_fast.go bypassFastHeaders, akamai/transport
// SubmitSensor/SubmitSBSD content types, sbsdPostURL), the envelope escaped
// as JSON.stringify escapes (U+2028 verbatim, control bytes as \u00XX).
func TestPostsCarryTheSessionHeaders(t *testing.T) {
	ctx := context.Background()
	session, err := akamai.Open(ctx, mode(t, exchange{}), openRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := session.UploadSensorScript(ctx, sensorURL, sensorJS); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Sensor(ctx, "A~-1~", "B"); err != nil {
		t.Fatal(err)
	}
	if err := session.UploadSBSDScript(ctx, sbsdURL, sbsdJS); err != nil {
		t.Fatal(err)
	}
	device := fhttp.Header{
		"user-agent": {ua}, "accept-language": {"en-US,en;q=0.9"}, "accept-encoding": {"gzip, deflate, br, zstd"},
		"sec-ch-ua": {`"Chromium";v="157", "Google Chrome";v="157"`}, "sec-ch-ua-mobile": {"?0"}, "sec-ch-ua-platform": {`"Windows"`},
	}
	sensor, err := session.SensorPost("3;<a>&\"\\\u2028\x01")
	if err != nil {
		t.Fatal(err)
	}
	checkPost(t, sensor, sensorURL, "{\"sensor_data\":\"3;<a>&\\\"\\\\\u2028\\u0001\"}", "text/plain;charset=UTF-8", device)
	sbsd, err := session.SBSDPost("enc")
	if err != nil {
		t.Fatal(err)
	}
	checkPost(t, sbsd, "https://www.example.com/.well-known/sbsd/x1", `{"body":"enc"}`, "application/json", device)
}

func checkPost(t *testing.T, r *fhttp.Request, target, body, contentType string, device fhttp.Header) {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := device.Clone()
	want["content-type"] = []string{contentType}
	if r.Method != http.MethodPost || r.URL.String() != target || string(raw) != body || !reflect.DeepEqual(r.Header, want) {
		t.Fatalf("post %s %s\nbody %s\nheaders %v\nwant POST %s\nbody %s\nheaders %v", r.Method, r.URL, raw, r.Header, target, body, want)
	}
}
