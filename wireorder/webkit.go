package wireorder

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// cfSizes and cfCaps mirror CFBasicHash.c __CFBasicHashTableSizes and __CFBasicHashTableCapacities.
func cfSizes() [11]int { return [11]int{0, 3, 7, 13, 23, 41, 71, 127, 191, 251, 383} }

func cfCaps() [11]int { return [11]int{0, 3, 6, 11, 19, 32, 52, 85, 118, 155, 237} }

// cfStrHash mirrors CFString.c __CFStrHashCharacters over 8-bit content.
func cfStrHash(s string) uint64 {
	n := len(s)
	r := uint64(n)
	i := 0
	for end := n &^ 3; i < end; i += 4 {
		r = r*67503105 + (((uint64(s[i])*257+uint64(s[i+1]))*257+uint64(s[i+2]))*257 + uint64(s[i+3]))
	}
	for ; i < n; i++ {
		r = r*257 + uint64(s[i])
	}
	return r + r<<(n&31)
}

// cfAdd mirrors CFBasicHash linear probing; growth re-inserts in old bucket order. Slots hold key index + 1.
func cfAdd(slots []uint8, used, key int, hashes []uint64) ([]uint8, error) {
	sizes, caps := cfSizes(), cfCaps()
	idx := slices.Index(sizes[:], len(slots))
	next := slices.Clone(slots)
	if caps[idx] < used+1 {
		grown := slices.IndexFunc(caps[:], func(c int) bool { return used+1 <= c })
		if grown < 0 {
			return nil, fmt.Errorf("%d keys exceed the modelled CF table sizes", used+1)
		}
		next = make([]uint8, sizes[grown])
		for _, k := range slots {
			if k != 0 {
				cfPlace(next, int(k-1), hashes)
			}
		}
	}
	cfPlace(next, key, hashes)
	return next, nil
}

func cfPlace(t []uint8, key int, hashes []uint64) {
	nb := uint64(len(t))
	i := hashes[key] % nb
	for t[i] != 0 {
		i = (i + 1) % nb
	}
	t[i] = uint8(key + 1)
}

func cfInsert(names []string) ([]string, error) {
	hashes := make([]uint64, len(names))
	for i, name := range names {
		hashes[i] = cfStrHash(name)
	}
	var slots []uint8
	for i := range names {
		var err error
		if slots, err = cfAdd(slots, i, i, hashes); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(names))
	for _, k := range slots {
		if k != 0 {
			out = append(out, names[k-1])
		}
	}
	return out, nil
}

// cfCanonical inserts one deterministic history admitted by pred: whenever
// several names are available, the request's supplied name order wins. It is
// the non-blocking WebKit policy's universal insertion history.
func cfCanonical(names []string, pred []uint64) ([]string, error) {
	if len(names) != len(pred) {
		return nil, fmt.Errorf("%d names have %d predecessor sets", len(names), len(pred))
	}
	if len(names) > 64 {
		return nil, fmt.Errorf("%d names exceed the canonical history width", len(names))
	}
	history := make([]string, 0, len(names))
	var done uint64
	for range names {
		next := -1
		for i := range names {
			bit := uint64(1) << i
			if done&bit == 0 && pred[i]&^done == 0 {
				next = i
				break
			}
		}
		if next < 0 {
			return nil, fmt.Errorf("the precedence constraints admit no insertion history")
		}
		history = append(history, names[next])
		done |= uint64(1) << next
	}
	return cfInsert(history)
}

const webkitStateLimit = 1 << 18

// cfOutcomes returns the distinct CF bucket orders of every insertion history obeying pred (bitset of names preceding name i).
func cfOutcomes(names []string, pred []uint64) ([][]string, error) {
	n := len(names)
	if n > 64 {
		return nil, fmt.Errorf("%d names exceed the enumeration width", n)
	}
	hashes := make([]uint64, n)
	for i, name := range names {
		hashes[i] = cfStrHash(name)
	}
	type state struct {
		done  uint64
		slots []uint8
	}
	states := []state{{}}
	for used := range n {
		seen := make(map[string]struct{}, len(states))
		var next []state
		for _, s := range states {
			for i := range n {
				bit := uint64(1) << i
				if s.done&bit != 0 || pred[i]&^s.done != 0 {
					continue
				}
				slots, err := cfAdd(s.slots, used, i, hashes)
				if err != nil {
					return nil, err
				}
				done := s.done | bit
				key := strconv.FormatUint(done, 36) + ":" + string(slots)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				next = append(next, state{done, slots})
			}
		}
		if len(next) == 0 {
			return nil, fmt.Errorf("the precedence constraints admit no insertion history")
		}
		if len(next) > webkitStateLimit {
			return nil, fmt.Errorf("%d insertion states exceed the enumeration bound %d", len(next), webkitStateLimit)
		}
		states = next
	}
	var out [][]string
	seen := map[string]struct{}{}
	for _, s := range states {
		key := string(s.slots)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		order := make([]string, 0, n)
		for _, k := range s.slots {
			if k != 0 {
				order = append(order, names[k-1])
			}
		}
		out = append(out, order)
	}
	return out, nil
}

// webkitDictionary: HTTPHeaderMap yields commons before uncommons and Content-Length is set last; page uncommons keep program order.
type webkitDictionary struct {
	names []string
	pred  []uint64
}

func (d *webkitDictionary) before(a, b string) {
	i, j := slices.Index(d.names, a), slices.Index(d.names, b)
	if i >= 0 && j >= 0 {
		d.pred[j] |= 1 << i
	}
}

func newWebkitDictionary(law *webkitLaw, r *Request, calls []string, shape map[string]string) *webkitDictionary {
	d := &webkitDictionary{}
	d.names = append(d.names, calls...)
	if !slices.Contains(calls, "accept") {
		d.names = append(d.names, "accept")
	}
	for _, name := range law.LoaderAdded {
		if r.Added.present(name) {
			d.names = append(d.names, name)
		}
	}
	if r.Added.Body {
		d.names = append(d.names, "content-length")
	}
	d.pred = make([]uint64, len(d.names))
	common := func(name string) bool { return slices.Contains(law.CommonHeaders, name) }
	var page []string
	for _, name := range calls {
		if _, isShape := shape[name]; !isShape && !common(name) {
			page = append(page, name)
		}
	}
	for _, c := range d.names {
		if c == "content-length" || !common(c) {
			continue
		}
		for _, u := range d.names {
			if !common(u) {
				d.before(c, u)
			}
		}
	}
	for i := 1; i < len(page); i++ {
		d.before(page[i-1], page[i])
	}
	if r.Added.Body {
		for _, name := range d.names {
			if name != "content-length" {
				d.before(name, "content-length")
			}
		}
	}
	return d
}

func ambiguousNames(outcomes [][]string) []string {
	var names []string
	first := outcomes[0]
	for _, o := range outcomes[1:] {
		for i := range first {
			if first[i] == o[i] {
				continue
			}
			for _, name := range []string{first[i], o[i]} {
				if !slices.Contains(names, name) {
					names = append(names, name)
				}
			}
		}
	}
	slices.SortFunc(names, func(a, b string) int {
		return slices.Index(first, a) - slices.Index(first, b)
	})
	return names
}

func precedes(order []string, a, b string) bool {
	i, j := slices.Index(order, a), slices.Index(order, b)
	return i >= 0 && j >= 0 && i < j
}

// obeys reports whether order puts every wire pair's first name before its second.
func obeys(order []string, wire [][2]string) bool {
	for _, e := range wire {
		if !precedes(order, e[0], e[1]) {
			return false
		}
	}
	return true
}

func shapeRole(name, prefix string) (string, bool) {
	if prefix == "" {
		return "", false
	}
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || rest == "" || !strings.ContainsRune("abcdfz", rune(rest[0])) {
		return "", false
	}
	for _, c := range rest[1:] {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return "shape:" + rest, true
}
