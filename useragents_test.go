package evade

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/EvadeNow/evade-sdk/useragent"
)

// listedUserAgents is a Shape server's GET /user-agents list (2026-10-18), in
// its order.
var listedUserAgents = []string{
	windowsChrome151, macChrome155, macSafari, iosSafari18, iosSafari26, iosChrome266, iosChrome2661, iosChrome27, iosSafari27,
}

const (
	windowsChrome151 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	macChrome155     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
	macSafari        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15"
	iosSafari18      = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	iosSafari26      = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1"
	iosChrome266     = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1"
	iosChrome2661    = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1"
	iosChrome27      = "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1"
	iosSafari27      = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1"
)

func userAgentsBody(t *testing.T, agents []string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"success": true, "user_agents": agents})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestUserAgentsFilters(t *testing.T) {
	body := userAgentsBody(t, listedUserAgents)
	for _, test := range []struct {
		filters []UserAgentFilter
		want    []string
	}{
		{nil, listedUserAgents},
		{[]UserAgentFilter{"windows"}, []string{windowsChrome151}},
		{[]UserAgentFilter{"macos"}, []string{macChrome155, macSafari}},
		{[]UserAgentFilter{"ios"}, []string{iosSafari18, iosSafari26, iosChrome266, iosChrome2661, iosChrome27, iosSafari27}},
		{[]UserAgentFilter{"ios_safari"}, []string{iosSafari18, iosSafari26, iosSafari27}},
		{[]UserAgentFilter{"ios_chrome"}, []string{iosChrome266, iosChrome2661, iosChrome27}},
		{[]UserAgentFilter{"macos_safari"}, []string{macSafari}},
		{[]UserAgentFilter{"chrome"}, []string{windowsChrome151, macChrome155, iosChrome266, iosChrome2661, iosChrome27}},
		{[]UserAgentFilter{"safari"}, []string{macSafari, iosSafari18, iosSafari26, iosSafari27}},
		{[]UserAgentFilter{"android"}, []string{}},
		// A union keeps the server's order, and a value two filters match once.
		{[]UserAgentFilter{"ios_chrome", "windows", "chrome"}, []string{windowsChrome151, macChrome155, iosChrome266, iosChrome2661, iosChrome27}},
	} {
		server, seen := testServer(t, http.StatusOK, body, nil)
		client := newTestClient(t, Config{BaseURL: server.URL, APIKey: "sk_test"})
		got, err := client.UserAgents(context.Background(), "shape", test.filters...)
		if err != nil {
			t.Fatalf("%v: %v", test.filters, err)
		}
		if !slices.Equal(got, test.want) {
			t.Errorf("%v: got %q, want %q", test.filters, got, test.want)
		}
		if seen.method != http.MethodGet || seen.path != "/user-agents?task=shape" || seen.authorization != "Bearer sk_test" || seen.body != "" {
			t.Errorf("%v: sent %+v, want GET /user-agents?task=shape with the bearer key and no body", test.filters, *seen)
		}
	}
}

func TestUserAgentsRefusesInvalidFilterBeforeRequest(t *testing.T) {
	for _, filter := range []UserAgentFilter{"", "iphone", "iOS", "safari_ios", "ios_", "_safari", "ios_safari_x", "ios_webkit"} {
		server, seen := testServer(t, http.StatusOK, userAgentsBody(t, listedUserAgents), nil)
		client := newTestClient(t, Config{BaseURL: server.URL})
		if _, err := client.UserAgents(context.Background(), "shape", "ios", filter); err == nil {
			t.Errorf("filter %q: no error", filter)
		}
		if seen.method != "" {
			t.Errorf("filter %q: a request was sent", filter)
		}
	}
}

func TestUserAgentsFailsClosed(t *testing.T) {
	const unplaced = "Mozilla/5.0 (PlayStation; PlayStation 5/2.26) AppleWebKit/605.1.15 (KHTML, like Gecko)"
	server, _ := testServer(t, http.StatusOK, userAgentsBody(t, []string{iosSafari18, unplaced}), nil)
	client := newTestClient(t, Config{BaseURL: server.URL})
	// Unfiltered, the list is the server's: nothing needs placing.
	if got, err := client.UserAgents(context.Background(), "shape"); err != nil || !slices.Equal(got, []string{iosSafari18, unplaced}) {
		t.Fatalf("unfiltered: %q, %v", got, err)
	}
	var unsupported *useragent.UnsupportedError
	if _, err := client.UserAgents(context.Background(), "shape", "ios"); !errors.As(err, &unsupported) || unsupported.UserAgent != unplaced {
		t.Fatalf("filtered with an unplaceable value: %v, want its *useragent.UnsupportedError", err)
	}

	server, _ = testServer(t, http.StatusOK, `{"success":true}`, nil)
	client = newTestClient(t, Config{BaseURL: server.URL})
	if _, err := client.UserAgents(context.Background(), "shape"); err == nil || !strings.Contains(err.Error(), "no user_agents") {
		t.Fatalf("missing list: %v", err)
	}

	server, _ = testServer(t, http.StatusBadRequest, `{"error":"invalid or unsupported task"}`, nil)
	client = newTestClient(t, Config{BaseURL: server.URL})
	var apiErr *APIError
	if _, err := client.UserAgents(context.Background(), "nope"); !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest {
		t.Fatalf("router refusal: %v, want a 400 *APIError", err)
	}
	if _, err := client.UserAgents(context.Background(), ""); err == nil {
		t.Fatal("empty task: no error")
	}
}
