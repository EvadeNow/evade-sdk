package wireorder

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func webkitSplit(w *webkitLaw, names []string) (dict, tail []string) {
	end := len(names)
	for end > 0 && slices.Contains(w.Unresolved, names[end-1]) {
		end--
	}
	ti := len(w.CFNetworkTail)
	for end > 0 {
		j := slices.Index(w.CFNetworkTail[:ti], names[end-1])
		if j < 0 {
			break
		}
		ti = j
		end--
	}
	return names[:end], names[end:]
}

func webkitFramed(w *webkitLaw, c *capture) ([]string, bool) {
	if c.HTTP2 {
		return c.Names, true
	}
	np, ns := len(w.HTTP1Prefix), len(w.HTTP1Suffix)
	if len(c.Names) < np+ns || !slices.Equal(c.Names[:np], w.HTTP1Prefix) || !slices.Equal(c.Names[len(c.Names)-ns:], w.HTTP1Suffix) {
		return nil, false
	}
	return c.Names[np : len(c.Names)-ns], true
}

// Every HTTP/1.1 WebKit request: host first, connection last.
func testWebkitHTTP1(t *testing.T, law *lawFile, all []*capture) {
	w := &law.WebKit
	var framed, sockets, cookies int
	dicts := map[string]bool{}
	for _, c := range all {
		e, ok := engineOf(c.UA)
		if !ok || e.Kind != WebKit || c.HTTP2 {
			continue
		}
		if c.has("upgrade") {
			sockets++
			continue
		}
		if c.has("cookie") {
			cookies++
		}
		names, ok := webkitFramed(w, c)
		if !ok {
			t.Errorf("%s: %v is not framed by %v ... %v", c, c.Names, w.HTTP1Prefix, w.HTTP1Suffix)
			continue
		}
		d, _ := webkitSplit(w, names)
		reach, err := cfReaches(d, insertionModel(w, d, nil), d)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if !reach {
			t.Errorf("%s: the insertion model does not reproduce the dictionary %v", c, d)
		}
		framed++
		dicts[strings.Join(d, ",")] = true
	}
	t.Logf("%d WebKit HTTP/1.1 captures (%d with a cookie) in %d dictionary sequences framed by %v ... %v; %d WebSocket handshakes",
		framed, cookies, len(dicts), w.HTTP1Prefix, w.HTTP1Suffix, sockets)
	if framed != 319 || cookies != 1 || len(dicts) != 14 {
		t.Errorf("want 319 framed captures, 1 with a cookie, in 14 dictionary sequences")
	}
}

// cfReaches reports whether some insertion history obeying pred iterates in want order.
func cfReaches(names []string, pred []uint64, want []string) (bool, error) {
	n := len(names)
	caps := cfCaps()
	final := slices.IndexFunc(caps[:], func(c int) bool { return n <= c })
	if final < 0 {
		return false, fmt.Errorf("%d keys exceed the modelled CF table sizes", n)
	}
	finalSize := cfSizes()[final]
	rank := make([]int, n)
	for i, name := range names {
		rank[i] = slices.Index(want, name)
		if rank[i] < 0 {
			return false, nil
		}
	}
	hashes := make([]uint64, n)
	for i, name := range names {
		hashes[i] = cfStrHash(name)
	}
	type state struct {
		done  uint64
		slots []uint8
	}
	consistent := func(slots []uint8) bool {
		last := -1
		for _, k := range slots {
			if k != 0 {
				if rank[k-1] < last {
					return false
				}
				last = rank[k-1]
			}
		}
		return true
	}
	states := []state{{}}
	for used := range n {
		seen := map[string]struct{}{}
		var next []state
		for _, s := range states {
			for i := range n {
				bit := uint64(1) << i
				if s.done&bit != 0 || pred[i]&^s.done != 0 {
					continue
				}
				slots, err := cfAdd(s.slots, used, i, hashes)
				if err != nil {
					return false, err
				}
				if len(slots) == finalSize && !consistent(slots) {
					continue
				}
				key := fmt.Sprintf("%x:%s", s.done|bit, slots)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				next = append(next, state{s.done | bit, slots})
			}
		}
		if len(next) == 0 {
			return false, nil
		}
		if len(next) > 1<<22 {
			return false, fmt.Errorf("%d states", len(next))
		}
		states = next
	}
	return true, nil
}

// Commons before uncommons, content-length last, plus extra precedences.
func insertionModel(w *webkitLaw, names []string, extra [][2]string) []uint64 {
	d := &webkitDictionary{names: names, pred: make([]uint64, len(names))}
	common := func(n string) bool { return slices.Contains(w.CommonHeaders, n) }
	for _, a := range names {
		for _, b := range names {
			if a != b && ((common(a) && a != "content-length" && !common(b)) || b == "content-length") {
				d.before(a, b)
			}
		}
	}
	for _, e := range extra {
		d.before(e[0], e[1])
	}
	return d.pred
}

type webkitSeq struct {
	dict  []string
	first *capture
	all   []*capture
}

func webkitSequences(t *testing.T, w *webkitLaw, all []*capture) (seqs []*webkitSeq, services int, tails map[string]bool, generations map[string]bool) {
	tails, generations = map[string]bool{}, map[string]bool{}
	for _, c := range all {
		e, ok := engineOf(c.UA)
		if !ok || e.Kind != WebKit || !c.HTTP2 {
			continue
		}
		if !slices.Equal(c.Pseudo, w.Pseudo) {
			services++
			continue
		}
		if g := w.generation(e); g != nil {
			generations[g.Name] = true
		} else {
			generations[e.String()] = true
		}
		d, tail := webkitSplit(w, c.Names)
		for _, n := range tail {
			tails[n] = true
		}
		i := slices.IndexFunc(seqs, func(s *webkitSeq) bool { return slices.Equal(s.dict, d) })
		if i < 0 {
			seqs = append(seqs, &webkitSeq{dict: d, first: c})
			i = len(seqs) - 1
		}
		seqs[i].all = append(seqs[i].all, c)
	}
	return seqs, services, tails, generations
}

func webkitInfeasibleReason(law *lawFile, s *webkitSeq) string {
	switch {
	case s.first.Method == "OPTIONS":
		return "CORS preflight: built on a separate path"
	case slices.Contains(s.dict, "service-worker"):
		return "service-worker script fetch"
	}
	for _, cw := range law.WebKit.Counterwitness {
		if slices.Equal(cw.Dictionary, s.dict) {
			return "counterwitness: " + cw.Reason
		}
	}
	return ""
}

func testWebkitCorpus(t *testing.T, law *lawFile, all []*capture) {
	w := &law.WebKit
	seqs, services, tails, generations := webkitSequences(t, w, all)
	requests := 0
	for _, s := range seqs {
		requests += len(s.all)
	}
	t.Logf("%d WebKit page requests in %d dictionary sequences; %d with another pseudo order (Safari services)", requests, len(seqs), services)
	if len(seqs) != 92 {
		t.Errorf("distinct WebKit dictionary sequences: %d, want 92", len(seqs))
	}
	for _, n := range w.CFNetworkTail {
		if !tails[n] {
			t.Errorf("tail name %s never witnessed after the dictionary", n)
		}
	}
	for _, g := range w.Generations {
		if !generations[g.Name] && webkitWitnessedOutsideCorpus[g.Name] == "" {
			t.Errorf("WebKit generation %s has no capture", g.Name)
		}
	}
	for name := range generations {
		if !slices.ContainsFunc(w.Generations, func(g webkitGeneration) bool { return g.Name == name }) {
			t.Errorf("WebKit build %s is captured but no generation holds it", name)
		}
	}
	for _, cw := range w.Counterwitness {
		i := slices.IndexFunc(all, func(c *capture) bool { return c.HAR == cw.HAR && c.Entry == cw.Entry })
		if i < 0 {
			t.Errorf("counterwitness %s#%d not in the corpus", cw.HAR, cw.Entry)
			continue
		}
		if d, _ := webkitSplit(w, all[i].Names); !slices.Equal(d, cw.Dictionary) {
			t.Errorf("counterwitness %s#%d dictionary %v, law %v", cw.HAR, cw.Entry, d, cw.Dictionary)
		}
	}
	var feasible, shapeSeqs, nonShape int
	for _, s := range seqs {
		model, err := cfReaches(s.dict, insertionModel(w, s.dict, nil), s.dict)
		if err != nil {
			t.Fatalf("%s: %v", s.first, err)
		}
		if !model {
			ok, err := cfReaches(s.dict, make([]uint64, len(s.dict)), s.dict)
			if err != nil {
				t.Fatalf("%s: %v", s.first, err)
			}
			if ok {
				t.Errorf("%s: CF-feasible but the insertion model does not reproduce %v", s.first, s.dict)
				continue
			}
			reason := webkitInfeasibleReason(law, s)
			if reason == "" {
				t.Errorf("%s %s: CF-infeasible and unaccounted for: %v", s.first, s.first.Method, s.dict)
			}
			t.Logf("infeasible %s (%d requests): %s", s.first, len(s.all), reason)
			continue
		}
		feasible++
		if shapePrefix(s.dict) != "" {
			shapeSeqs++
		} else {
			nonShape++
		}
	}
	t.Logf("CF-feasible and reproduced by the insertion model: %d/%d (non-Shape %d, Shape %d with the Shape order free)", feasible, len(seqs), nonShape, shapeSeqs)
	if feasible != 88 || shapeSeqs != 9 || nonShape != 79 {
		t.Errorf("want 88/92 feasible, 79 non-Shape, 9 Shape sequences")
	}
}

// TestWebKitLoaderInsertionOrderCaptures is
// HYPOTHESIS(webkit_loader_insertion_order)'s corpus test (law.go): every
// distinct late/law WebKit fetch/XHR dictionary without a Shape block, sent
// through OrderUniversal with the capture's page calls and added names, is
// counted when it comes out exactly as captured; and with the loader names
// forced into LoaderAdded's order, exactly its two counterwitnesses become
// unreachable.
func TestWebKitLoaderInsertionOrderCaptures(t *testing.T) {
	w := &testLaw(t).WebKit
	all := corpus(t)
	browserNames := append([]string{"accept", "content-length"}, w.LoaderAdded...)
	seen := map[string]bool{}
	var total, exact int
	var contradicted []string
	for _, c := range all {
		e, ok := engineOf(c.UA)
		if !ok || e.Kind != WebKit || c.Dest != "empty" || !c.HTTP2 || c.Method == "OPTIONS" || !slices.Equal(c.Pseudo, w.Pseudo) {
			continue
		}
		if g := w.generation(e); g == nil || !g.InsertionLaw {
			continue
		}
		d, _ := webkitSplit(w, c.Names)
		key := strings.Join(d, ",")
		if seen[key] || shapePrefix(d) != "" {
			continue
		}
		seen[key] = true
		total++
		var calls []string
		for _, n := range d {
			if !slices.Contains(browserNames, n) {
				calls = append(calls, n)
			}
		}
		// Fetch and XHR share the insertion law, so each goes as a fetch.
		r := Request{Engine: e, Class: ClassFetch, Method: c.Method, HTTP2: true, Calls: calls,
			Added: Added{Origin: c.has("origin"), Referer: c.has("referer"), Cookie: c.has("cookie"),
				Body: c.has("content-length"), Priority: c.has("priority")}}
		if got, err := OrderUniversal(r); err == nil {
			if dict, _ := webkitSplit(w, got.Header); slices.Equal(dict, d) {
				exact++
			}
		}
		var present []string
		for _, n := range w.LoaderAdded {
			if slices.Contains(d, n) {
				present = append(present, n)
			}
		}
		var chain [][2]string
		for i := 1; i < len(present); i++ {
			chain = append(chain, [2]string{present[i-1], present[i]})
		}
		free, err := cfReaches(d, insertionModel(w, d, nil), d)
		if err != nil {
			t.Fatal(err)
		}
		chained, err := cfReaches(d, insertionModel(w, d, chain), d)
		if err != nil {
			t.Fatal(err)
		}
		if free && !chained {
			contradicted = append(contradicted, c.String())
		}
	}
	slices.Sort(contradicted)
	t.Logf("%d late/law fetch/XHR dictionaries: %d come out exactly as captured; %v contradict the loader order", total, exact, contradicted)
	want := []string{"bandai-jp_login_iphone-safari18.7_1_1020#340", "vinted_safari_register#247"}
	if total != 58 || exact != 44 || !slices.Equal(contradicted, want) {
		t.Errorf("want 44/58 exact and counterwitnesses %v", want)
	}
}
