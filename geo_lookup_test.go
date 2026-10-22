package evade

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/EvadeNow/evade-sdk/geo"
)

func TestLookupIP(t *testing.T) {
	server, seen := testServer(t, http.StatusOK,
		`{"ip":"2001:db8::1","country_code":"US","subdivision":"Texas","city":"Dallas","time_zone":"America/Chicago"}`, nil)
	client := newTestClient(t, Config{BaseURL: server.URL, APIKey: "sk_test"})
	got, err := client.LookupIP(context.Background(), netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatal(err)
	}
	want := geo.Location{IP: netip.MustParseAddr("2001:db8::1"), CountryCode: "US", Subdivision: "Texas", City: "Dallas", TimeZone: "America/Chicago"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if seen.method != http.MethodGet || seen.path != "/geo/lookup?ip=2001%3Adb8%3A%3A1" || seen.authorization != "Bearer sk_test" || seen.body != "" {
		t.Errorf("sent %+v, want GET /geo/lookup?ip=<escaped> with the bearer key and no body", *seen)
	}
}

func TestLookupIPFailsClosed(t *testing.T) {
	server, seen := testServer(t, http.StatusOK, `{}`, nil)
	client := newTestClient(t, Config{BaseURL: server.URL})
	if _, err := client.LookupIP(context.Background(), netip.Addr{}); err == nil || seen.method != "" {
		t.Fatalf("invalid address: %v, request sent %v", err, seen.method != "")
	}
	if _, err := client.LookupIP(context.Background(), netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("response without time_zone: no error")
	}

	server, _ = testServer(t, http.StatusUnprocessableEntity,
		`{"success":false,"error":{"code":"ip_not_located","message":"geo: lookup 192.0.2.1: no record"}}`, nil)
	client = newTestClient(t, Config{BaseURL: server.URL})
	var apiErr *APIError
	if _, err := client.LookupIP(context.Background(), netip.MustParseAddr("192.0.2.1")); !errors.As(err, &apiErr) ||
		apiErr.Status != http.StatusUnprocessableEntity || apiErr.Code != CodeIPNotLocated {
		t.Fatalf("unlocated: %v, want a 422 ip_not_located *APIError", err)
	}
}
