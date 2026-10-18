package geo

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"
)

// The GeoLite2 database is licensed and not vendored; runs skip without FINGERPRINT_SDK_GEOIP_DB.
func openTestDB(t *testing.T) *Reader {
	t.Helper()
	path := os.Getenv("FINGERPRINT_SDK_GEOIP_DB")
	if path == "" {
		t.Skip("FINGERPRINT_SDK_GEOIP_DB is not set")
	}
	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return reader
}

func TestLookupPublicResolvers(t *testing.T) {
	reader := openTestDB(t)
	cases := []struct {
		ip      string
		country string
	}{
		{"8.8.8.8", "US"},
		{"::ffff:8.8.8.8", "US"},
		{"2001:4860:4860::8888", "US"},
	}
	for _, tc := range cases {
		location, err := reader.Lookup(netip.MustParseAddr(tc.ip))
		if err != nil {
			t.Errorf("Lookup(%s): %v", tc.ip, err)
			continue
		}
		if location.CountryCode != tc.country {
			t.Errorf("Lookup(%s).CountryCode = %q, want %q", tc.ip, location.CountryCode, tc.country)
		}
		if _, err := time.LoadLocation(location.TimeZone); err != nil || location.TimeZone == "" {
			t.Errorf("Lookup(%s).TimeZone = %q does not load: %v", tc.ip, location.TimeZone, err)
		}
		if location.IP != netip.MustParseAddr(tc.ip).Unmap() {
			t.Errorf("Lookup(%s).IP = %s, want the unmapped address", tc.ip, location.IP)
		}
	}
}

func TestLookupRejectsAddressesWithoutRecord(t *testing.T) {
	reader := openTestDB(t)
	for _, ip := range []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("127.0.0.1"), {}} {
		_, err := reader.Lookup(ip)
		if _, ok := errors.AsType[*LookupError](err); !ok {
			t.Errorf("Lookup(%s): err = %v, want *LookupError", ip, err)
		}
	}
}

func TestLocateLooksUpTheObservedExit(t *testing.T) {
	reader := openTestDB(t)
	location, err := reader.Locate(context.Background(), exitServer(t, http.StatusOK, `{"ip":"8.8.8.8"}`))
	if err != nil {
		t.Fatal(err)
	}
	if location.IP != netip.MustParseAddr("8.8.8.8") || location.CountryCode != "US" || location.TimeZone == "" {
		t.Fatalf("Locate = %+v", location)
	}
}
