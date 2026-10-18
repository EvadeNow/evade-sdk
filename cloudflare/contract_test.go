package cloudflare_test

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
	"github.com/EvadeNow/evade-sdk/cloudflare"
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

func challengeRequest() cloudflare.Request {
	return cloudflare.Request{
		WebsiteURL: "https://www.example.com/path",
		UserAgent:  "Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36",
		HTML:       "<!doctype html><title>Just a moment...</title>",
		Proxy:      "127.0.0.1:8080:user:pass",
	}
}

func turnstileRequest() cloudflare.Request {
	return cloudflare.Request{
		WebsiteURL: "https://www.example.com/login",
		WebsiteKey: "0x4AAAAAAAAAAAAAAAAAAAAAA", Action: "login", CData: "0000-1111",
	}
}

func TestRequestsMatchGolden(t *testing.T) {
	tests := []struct {
		name    string
		request cloudflare.Request
		want    string
	}{
		{"challenge", challengeRequest(), `{"websiteURL":"https://www.example.com/path","userAgent":"Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36","html":"<!doctype html><title>Just a moment...</title>","proxy":"127.0.0.1:8080:user:pass","websiteKey":""}`},
		{"turnstile", turnstileRequest(), `{"websiteURL":"https://www.example.com/login","userAgent":"","html":"","proxy":"","websiteKey":"0x4AAAAAAAAAAAAAAAAAAAAAA","action":"login","cdata":"0000-1111"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, want := encode(t, test.request), []byte(test.want); !bytes.Equal(got, want) {
				t.Fatalf("request\n got %s\nwant %s", got, want)
			}
		})
	}
}

func wantResponse() cloudflare.Response {
	return cloudflare.Response{
		Success: true, Token: "token",
		Cookies: []cloudflare.Cookie{
			{Name: "cf_clearance", Value: "clearance-value", Domain: ".example.com", Path: "/"},
			{Name: "__cf_bm", Value: "bm-value"},
		},
		UserAgent: "Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36",
		GenMS:     1.25,
	}
}

func TestResponseGoldenDecodesEveryField(t *testing.T) {
	var got cloudflare.Response
	if err := json.Unmarshal([]byte(`{"success":true,"token":"token","cookies":[{"name":"cf_clearance","value":"clearance-value","domain":".example.com","path":"/"},{"name":"__cf_bm","value":"bm-value"}],"userAgent":"Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36","genMs":1.25}`), &got); err != nil {
		t.Fatal(err)
	}
	if want := wantResponse(); !reflect.DeepEqual(got, want) {
		t.Fatalf("response\n got %+v\nwant %+v", got, want)
	}
}

func server(t *testing.T, status int, body []byte) (*evade.Client, *string, *[]byte) {
	t.Helper()
	var line string
	var sent []byte
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line = r.Method + " " + r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		sent = bytes.TrimSuffix(raw, []byte("\n"))
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	client, err := evade.NewClient(evade.Config{BaseURL: s.URL})
	if err != nil {
		t.Fatal(err)
	}
	return client, &line, &sent
}

// The challenge HTML's < and > must reach the wire unescaped.
func TestSolveSendsTaskAndToleratesUnknownResponseKeys(t *testing.T) {
	client, line, sent := server(t, http.StatusOK, []byte(`{"kind":"challenge","cookies_ttl":1800,"success":true,"token":"token","cookies":[{"name":"cf_clearance","value":"clearance-value","domain":".example.com","path":"/"},{"name":"__cf_bm","value":"bm-value"}],"userAgent":"Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36","genMs":1.25}`))
	got, err := cloudflare.Solve(context.Background(), client, challengeRequest())
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if *line != "POST /solve" {
		t.Fatalf("request line = %s", *line)
	}
	want := []byte(`{"task":"cloudflare","websiteURL":"https://www.example.com/path","userAgent":"Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36","html":"<!doctype html><title>Just a moment...</title>","proxy":"127.0.0.1:8080:user:pass","websiteKey":""}`)
	if !bytes.Equal(*sent, want) {
		t.Fatalf("wire body\n got %s\nwant %s", *sent, want)
	}
	if !reflect.DeepEqual(got, wantResponse()) {
		t.Fatalf("response = %+v", got)
	}
}

func TestSolveFailureReturnsZeroAndAPIError(t *testing.T) {
	client, _, _ := server(t, http.StatusServiceUnavailable,
		[]byte(`{"success":false,"error":{"code":"solver_unavailable","message":"Cloudflare solve flow is unavailable"}}`+"\n"))
	got, err := cloudflare.Solve(context.Background(), client, turnstileRequest())
	var apiErr *evade.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != evade.CodeSolverUnavailable ||
		apiErr.Message != "Cloudflare solve flow is unavailable" {
		t.Fatalf("error = %v", err)
	}
	if !reflect.DeepEqual(got, cloudflare.Response{}) {
		t.Fatalf("failed Solve returned %+v", got)
	}
}
