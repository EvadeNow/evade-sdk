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

const goldenResponse = `{"success":true,"task":"ReCaptchaV3EnterpriseTask","token":"03AFcWeA-token","score":null,"verification":null,"genMs":12.5}`

func wantResponse() recaptcha.Response {
	return recaptcha.Response{Success: true, Task: recaptcha.TaskV3Enterprise, Token: "03AFcWeA-token", GenMS: 12.5}
}

// score and verification are null on the wire and nil here: neither is
// observable client-side.
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

// The task rides first on the wire; unknown response keys are tolerated.
func TestSolveSendsTaskAndToleratesUnknownResponseKeys(t *testing.T) {
	for _, task := range []recaptcha.Task{recaptcha.TaskV3Enterprise, recaptcha.TaskV3} {
		t.Run(string(task), func(t *testing.T) {
			client, line, sent := server(t, http.StatusOK, nil, []byte(`{"stages":[{"name":"reload","status":200}],"success":true,"task":"`+string(task)+`","token":"03AFcWeA-token","score":null,"verification":null,"genMs":12.5}`))
			got, err := recaptcha.Solve(context.Background(), client, task, checkoutRequest())
			if err != nil {
				t.Fatalf("Solve: %v", err)
			}
			if *line != "POST /solve" {
				t.Fatalf("request line = %s", *line)
			}
			want := []byte(`{"task":"` + string(task) + `",` + goldenRequest[1:])
			if !bytes.Equal(*sent, want) {
				t.Fatalf("wire body\n got %s\nwant %s", *sent, want)
			}
			wanted := wantResponse()
			wanted.Task = task
			if !reflect.DeepEqual(got, wanted) {
				t.Fatalf("response = %+v", got)
			}
		})
	}
}

// Every refusal is the shared envelope with its catalog code; a rate
// limit carries Retry-After.
func TestSolveFailuresReturnZeroAndAPIError(t *testing.T) {
	tests := []struct {
		name   string
		status int
		header http.Header
		body   string
		code   evade.Code
		retry  time.Duration
	}{
		{"device", http.StatusUnprocessableEntity, nil, `{"success":false,"error":{"code":"device_unsupported","message":"no admitted Record for \"Mozilla/5.0 …\" on the running collector bundle"}}`, evade.CodeDeviceUnsupported, 0},
		{"page", http.StatusBadRequest, nil, `{"success":false,"error":{"code":"invalid_request","message":"page https://www.example.com has no enterprise v3 loader"}}`, evade.CodeInvalidRequest, 0},
		{"site", http.StatusUnprocessableEntity, nil, `{"success":false,"error":{"code":"site_unsupported","message":"v3: no J page laws for https://www.example.com"}}`, evade.CodeSiteUnsupported, 0},
		{"short", http.StatusUnprocessableEntity, nil, `{"success":false,"error":{"code":"generation_failed","message":"reload token is SHORT (2001 bytes, NORMAL is at least 2100)"}}`, evade.CodeGenerationFailed, 0},
		{"proxy", http.StatusServiceUnavailable, nil, `{"success":false,"error":{"code":"proxy_failed","message":"recaptcha exit: dial tcp: connection refused"}}`, evade.CodeProxyFailed, 0},
		{"rate", http.StatusTooManyRequests, http.Header{"Retry-After": {"7"}}, `{"success":false,"error":{"code":"rate_limited","message":"too many requests for this account"}}`, evade.CodeRateLimited, 7 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _, _ := server(t, test.status, test.header, []byte(test.body+"\n"))
			got, err := recaptcha.Solve(context.Background(), client, recaptcha.TaskV3, checkoutRequest())
			var apiErr *evade.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != test.status || apiErr.Code != test.code || apiErr.Message == "" {
				t.Fatalf("error = %v", err)
			}
			if apiErr.RateLimit.RetryAfter != test.retry {
				t.Fatalf("Retry-After = %s, want %s", apiErr.RateLimit.RetryAfter, test.retry)
			}
			if !reflect.DeepEqual(got, recaptcha.Response{}) {
				t.Fatalf("failed Solve returned %+v", got)
			}
		})
	}
}
