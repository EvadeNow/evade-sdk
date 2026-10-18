package geo

import (
	"errors"
	"testing"
	"time"
	_ "time/tzdata" // pin zone rules so results do not depend on host tzdata
)

func TestZoneAt(t *testing.T) {
	january := time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC)
	july := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		at   time.Time
		want Zone
	}{
		{"America/New_York", january, Zone{Name: "America/New_York", OffsetMinutes: 300, Abbreviation: "EST", UsesDaylight: true}},
		{"America/New_York", july, Zone{Name: "America/New_York", OffsetMinutes: 240, DST: true, Abbreviation: "EDT", UsesDaylight: true}},
		// US spring-forward 2026-03-08 at 02:00 EST = 07:00 UTC.
		{"America/New_York", time.Date(2026, time.March, 8, 6, 59, 59, 0, time.UTC), Zone{Name: "America/New_York", OffsetMinutes: 300, Abbreviation: "EST", UsesDaylight: true}},
		{"America/New_York", time.Date(2026, time.March, 8, 7, 0, 0, 0, time.UTC), Zone{Name: "America/New_York", OffsetMinutes: 240, DST: true, Abbreviation: "EDT", UsesDaylight: true}},
		{"Australia/Sydney", january, Zone{Name: "Australia/Sydney", OffsetMinutes: -660, DST: true, Abbreviation: "AEDT", UsesDaylight: true}},
		{"Asia/Kolkata", july, Zone{Name: "Asia/Kolkata", OffsetMinutes: -330, Abbreviation: "IST"}},
		{"Pacific/Kiritimati", january, Zone{Name: "Pacific/Kiritimati", OffsetMinutes: -840, Abbreviation: "+14"}},
		{" UTC ", july, Zone{Name: "UTC", Abbreviation: "UTC"}},
	}
	for _, tc := range cases {
		got, err := ZoneAt(tc.name, tc.at)
		if err != nil {
			t.Errorf("ZoneAt(%q, %s): %v", tc.name, tc.at, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ZoneAt(%q, %s) = %+v, want %+v", tc.name, tc.at, got, tc.want)
		}
	}
}

func TestZoneAtRejects(t *testing.T) {
	at := time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		at   time.Time
	}{
		{"Mars/Olympus_Mons", at},
		{"", at},
		{"Local", at},
		{"America/New_York", time.Time{}},
	}
	for _, tc := range cases {
		_, err := ZoneAt(tc.name, tc.at)
		if _, ok := errors.AsType[*ZoneError](err); !ok {
			t.Errorf("ZoneAt(%q, %s): err = %v, want *ZoneError", tc.name, tc.at, err)
		}
	}
}
