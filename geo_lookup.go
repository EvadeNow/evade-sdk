package evade

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/EvadeNow/evade-sdk/geo"
)

// GET /geo/lookup's refusals beside invalid_request (an address that does
// not parse).
const (
	CodeIPNotLocated   Code = "ip_not_located"  // shape: no usable record (geo.LookupError's reason)
	CodeGeoUnavailable Code = "geo_unavailable" // shape: the server's database is not open
)

// LookupIP asks the solver for ip's location (GET /geo/lookup), its time
// zone being what /solve's time_zone takes, so the caller needs no MaxMind
// database. ip is the caller's own observation of its exit, geo.ExitIP
// through the session's proxy. The server applies geo.Reader.Lookup's
// fail-closed rules: a record without a country or a loadable time zone is
// a 422 *APIError with CodeIPNotLocated.
func (c *Client) LookupIP(ctx context.Context, ip netip.Addr) (geo.Location, error) {
	if !ip.IsValid() {
		return geo.Location{}, errors.New("evade: geo lookup: address is invalid")
	}
	var location geo.Location
	if _, err := c.Call(ctx, http.MethodGet, "/geo/lookup?ip="+url.QueryEscape(ip.String()), nil, &location); err != nil {
		return geo.Location{}, err
	}
	// The answer is the server's, so an empty time zone is a contract break,
	// not a location to send /solve.
	if !location.IP.IsValid() || location.CountryCode == "" || location.TimeZone == "" {
		return geo.Location{}, fmt.Errorf("evade: geo lookup %s: response lacks ip, country_code or time_zone", ip)
	}
	return location, nil
}
