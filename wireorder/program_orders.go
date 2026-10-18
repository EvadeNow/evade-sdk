package wireorder

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ProgramOutcome is one distinct tuple of variant wire orders; Wires[v] and Calls[v] are variant v's, Units a unit order reaching it.
type ProgramOutcome struct {
	Units []int
	Calls [][]string
	Wires []Wire
}

const xhrUnitLimit = 24

// XHRProgramOrders returns the distinct wire-order tuples of Chromium XHR variants over every order of units[v][i] (variant v's names for unit i; Calls ignored).
func XHRProgramOrders(variants []Request, units [][][]string) ([]ProgramOutcome, error) {
	if len(variants) == 0 || len(variants) != len(units) {
		return nil, &InputError{Field: "variants", Detail: fmt.Sprintf("%d requests for %d unit lists", len(variants), len(units))}
	}
	n := len(units[0])
	if n > xhrUnitLimit {
		return nil, &InputError{Field: "units", Detail: fmt.Sprintf("%d units exceed %d", n, xhrUnitLimit)}
	}
	lower := make([][][]string, len(units))
	for v, r := range variants {
		if r.Engine.Kind != Chromium || r.Class != ClassXHR {
			return nil, &InputError{Field: "engine", Detail: "program orders are enumerated for Chromium XHR only; fetch header lists are sorted"}
		}
		if len(units[v]) != n {
			return nil, &InputError{Field: fmt.Sprintf("units[%d]", v), Detail: fmt.Sprintf("%d units, variant 0 has %d", len(units[v]), n)}
		}
		lower[v] = make([][]string, n)
		for i, u := range units[v] {
			for _, name := range u {
				lower[v][i] = append(lower[v][i], strings.ToLower(name))
			}
		}
	}
	type state struct {
		done   uint32
		tables []blinkTable
		order  []int
	}
	key := func(done uint32, tables []blinkTable) string {
		var b strings.Builder
		b.WriteString(strconv.FormatUint(uint64(done), 36))
		for _, t := range tables {
			b.WriteByte('\x01')
			b.WriteString(strings.Join(t.slots, "\x00"))
		}
		return b.String()
	}
	states := []state{{tables: make([]blinkTable, len(variants))}}
	for range n {
		seen := map[string]struct{}{}
		var next []state
		for _, s := range states {
			for i := range n {
				bit := uint32(1) << i
				if s.done&bit != 0 {
					continue
				}
				tables := make([]blinkTable, len(variants))
				for v := range variants {
					tables[v] = s.tables[v].clone()
					for _, name := range lower[v][i] {
						tables[v].add(name)
					}
				}
				k := key(s.done|bit, tables)
				if _, dup := seen[k]; dup {
					continue
				}
				seen[k] = struct{}{}
				next = append(next, state{done: s.done | bit, tables: tables, order: append(slices.Clone(s.order), i)})
			}
		}
		states = next
	}
	var out []ProgramOutcome
	seen := map[string]struct{}{}
	for _, s := range states {
		o := ProgramOutcome{Units: s.order}
		var sig strings.Builder
		for v, r := range variants {
			var calls []string
			for _, i := range s.order {
				calls = append(calls, units[v][i]...)
			}
			req := r
			req.Calls = calls
			w, err := law.order(&req)
			if err != nil {
				return nil, err
			}
			o.Calls = append(o.Calls, calls)
			o.Wires = append(o.Wires, w)
			sig.WriteString(strings.Join(w.Header, "\x00"))
			sig.WriteByte('\x01')
		}
		if _, dup := seen[sig.String()]; dup {
			continue
		}
		seen[sig.String()] = struct{}{}
		out = append(out, o)
	}
	return out, nil
}
