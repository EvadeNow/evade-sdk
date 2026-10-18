package geo

import (
	"fmt"
	"strings"
	"time"
)

// Zone is an IANA zone's clock state at one instant, as browsers expose it.
type Zone struct {
	Name          string
	OffsetMinutes int // JS getTimezoneOffset sign: east of UTC is negative (Asia/Kolkata is -330)
	DST           bool
	Abbreviation  string // "EST", "EDT"; numeric such as "+14" when the zone has none
	UsesDaylight  bool   // January and July offsets differ in the instant's year
}

type ZoneError struct {
	Name   string
	Reason string
	Err    error
}

func (e *ZoneError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("geo: time zone %q: %s: %v", e.Name, e.Reason, e.Err)
	}
	return fmt.Sprintf("geo: time zone %q: %s", e.Name, e.Reason)
}

func (e *ZoneError) Unwrap() error { return e.Err }

// ZoneAt rejects "", "Local" and a zero instant rather than silently using UTC or the host zone.
func ZoneAt(name string, at time.Time) (Zone, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || trimmed == "Local" {
		return Zone{}, &ZoneError{Name: name, Reason: "is not an IANA zone name"}
	}
	if at.IsZero() {
		return Zone{}, &ZoneError{Name: name, Reason: "instant is zero"}
	}
	location, err := time.LoadLocation(trimmed)
	if err != nil {
		return Zone{}, &ZoneError{Name: name, Reason: "does not load", Err: err}
	}
	local := at.In(location)
	_, offsetSeconds := local.Zone()
	year := local.Year()
	_, january := time.Date(year, time.January, 1, 0, 0, 0, 0, location).Zone()
	_, july := time.Date(year, time.July, 1, 0, 0, 0, 0, location).Zone()
	return Zone{
		Name:          trimmed,
		OffsetMinutes: -offsetSeconds / 60,
		DST:           local.IsDST(),
		Abbreviation:  local.Format("MST"),
		UsesDaylight:  january != july,
	}, nil
}
