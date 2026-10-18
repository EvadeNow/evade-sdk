package geo

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

type Location struct {
	IP          netip.Addr
	CountryCode string // upper-case ISO 3166-1 alpha-2
	Subdivision string // English name of the first subdivision; may be empty
	City        string // English name; may be empty
	TimeZone    string // IANA name, loadable by time.LoadLocation
}

type LookupError struct {
	IP     netip.Addr
	Reason string
	Err    error
}

func (e *LookupError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("geo: lookup %s: %s: %v", e.IP, e.Reason, e.Err)
	}
	return fmt.Sprintf("geo: lookup %s: %s", e.IP, e.Reason)
}

func (e *LookupError) Unwrap() error { return e.Err }

// DefaultDatabase is relative to a sibling module directory; the licensed database is not vendored.
const DefaultDatabase = "../libraries/GeoLite2-City.mmdb"

// Reader is safe for concurrent lookups; the caller closes it.
type Reader struct {
	db *maxminddb.Reader
}

func Open(path string) (*Reader, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("geo: MaxMind database path is empty")
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geo: open MaxMind database: %w", err)
	}
	return &Reader{db: db}, nil
}

func (r *Reader) Close() error {
	return r.db.Close()
}

type cityRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		TimeZone string `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

// Lookup fails closed when the record lacks a two-letter country or a loadable time zone.
func (r *Reader) Lookup(a netip.Addr) (Location, error) {
	if !a.IsValid() {
		return Location{}, &LookupError{IP: a, Reason: "address is invalid"}
	}
	a = a.Unmap()
	result := r.db.Lookup(a)
	if err := result.Err(); err != nil {
		return Location{}, &LookupError{IP: a, Reason: "database lookup failed", Err: err}
	}
	if !result.Found() {
		return Location{}, &LookupError{IP: a, Reason: "no record"}
	}
	var record cityRecord
	if err := result.Decode(&record); err != nil {
		return Location{}, &LookupError{IP: a, Reason: "record does not decode", Err: err}
	}
	country := strings.ToUpper(strings.TrimSpace(record.Country.ISOCode))
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return Location{}, &LookupError{IP: a, Reason: "record has no ISO country code"}
	}
	zone := strings.TrimSpace(record.Location.TimeZone)
	if zone == "" {
		return Location{}, &LookupError{IP: a, Reason: "record has no time zone"}
	}
	if _, err := time.LoadLocation(zone); err != nil {
		return Location{}, &LookupError{IP: a, Reason: fmt.Sprintf("time zone %q does not load", zone), Err: err}
	}
	location := Location{
		IP:          a,
		CountryCode: country,
		City:        strings.TrimSpace(record.City.Names["en"]),
		TimeZone:    zone,
	}
	if len(record.Subdivisions) != 0 {
		location.Subdivision = strings.TrimSpace(record.Subdivisions[0].Names["en"])
	}
	return location, nil
}

// Locate looks up the exit IP c egresses from; pass the session's own client.
func (r *Reader) Locate(ctx context.Context, c Doer) (Location, error) {
	ip, err := ExitIP(ctx, c)
	if err != nil {
		return Location{}, err
	}
	return r.Lookup(ip)
}
