package wireorder

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

var corpusData = sync.OnceValues(loadCorpus)

func corpus(t *testing.T) []*capture {
	t.Helper()
	all, err := corpusData()
	if err != nil {
		t.Fatal(err)
	}
	if all == nil {
		t.Skip("capture corpus is not in this checkout")
	}
	return all
}

func testLaw(t *testing.T) *lawFile {
	t.Helper()
	return law
}

var chromiumExcluded = map[string]string{
	"westjet_login_mac-chrome151_1_0908_sanitized":  "powhttp export: sanitized casing, sec-ch-*/accept/sec-fetch-* stripped",
	"bandai-jp_product_windows-chrome151_1_0809":        "a document request carrying edge-proxy headers",
	"bandai-item-domfree":   "a document request carrying edge-proxy headers (#9: akamai-origin-hop, x-envoy-*, x-forwarded-*)",
	"bandai-cart-haronly#8": "a document request carrying edge-proxy headers (the interstitial replay: akamai-origin-hop, x-envoy-*, x-forwarded-*)",
}

func chromiumAdded(c *capture, law *chromiumLaw) Added {
	a := Added{Origin: c.has("origin"), Referer: c.has("referer"), Cookie: c.has("cookie"),
		Body: c.has("content-length"), Priority: c.has("priority"), StorageAccess: c.has("sec-fetch-storage-access")}
	for _, n := range law.BlinkSetOrder {
		if n != "user-agent" && c.has(n) {
			a.ClientHints = append(a.ClientHints, n)
		}
	}
	return a
}

func pageCalls(law *lawFile, c *capture) []string {
	var out []string
	for _, n := range c.Names {
		if law.forbidden(n) || n == "user-agent" || strings.HasPrefix(n, "sec-") ||
			n == "priority" || n == "accept-language" || n == "accept" {
			continue
		}
		out = append(out, n)
	}
	return out
}

func shapeBlock(names []string, prefix string) []string {
	var out []string
	for _, s := range "fbcdza" {
		base := prefix + string(s)
		if slices.Contains(names, base) {
			out = append(out, base)
		}
		for i := 0; ; i++ {
			cont := fmt.Sprintf("%s%d", base, i)
			if !slices.Contains(names, cont) {
				break
			}
			out = append(out, cont)
		}
	}
	return out
}

func permute(xs []string, fn func([]string) bool) bool {
	var rec func(int) bool
	rec = func(k int) bool {
		if k == len(xs) {
			return fn(xs)
		}
		for i := k; i < len(xs); i++ {
			xs[k], xs[i] = xs[i], xs[k]
			if rec(k + 1) {
				xs[k], xs[i] = xs[i], xs[k]
				return true
			}
			xs[k], xs[i] = xs[i], xs[k]
		}
		return false
	}
	return rec(0)
}

// accept and accept-language are tried as page calls and as network defaults.
func chromiumReproduces(t *testing.T, law *lawFile, c *capture, e Engine, prefix string) []string {
	calls := pageCalls(law, c)
	shape := shapeBlock(calls, prefix)
	var page []string
	for _, n := range calls {
		if !slices.Contains(shape, n) {
			page = append(page, n)
		}
	}
	var optional []string
	for _, n := range []string{"accept", "accept-language"} {
		if c.has(n) {
			optional = append(optional, n)
		}
	}
	try := func(class Class, program []string) bool {
		w, err := law.order(&Request{Engine: e, Class: class, Method: c.Method, HTTP2: c.HTTP2,
			Calls: program, ShapePrefix: prefix, Added: chromiumAdded(c, &law.Chromium)})
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		return slices.Equal(w.Header, c.Names)
	}
	var classes []string
	add := func(class string) {
		if !slices.Contains(classes, class) {
			classes = append(classes, class)
		}
	}
	for mask := range 1 << len(optional) {
		pg := slices.Clone(page)
		for i, n := range optional {
			if mask&(1<<i) != 0 {
				pg = append(pg, n)
			}
		}
		if try(ClassFetch, append(slices.Clone(pg), shape...)) {
			add("fetch")
		}
		if !slices.Contains(classes, "xhr") && permute(pg, func(p []string) bool {
			for cut := 0; cut <= len(p); cut++ {
				if try(ClassXHR, slices.Concat(p[:cut], shape, p[cut:])) {
					return true
				}
			}
			return false
		}) {
			add("xhr")
		}
	}
	return classes
}

func TestWireOrderLawCaptures(t *testing.T) {
	law := testLaw(t)
	all := corpus(t)

	t.Run("chromium", func(t *testing.T) {
		var reproduced, total int
		majors := map[int]bool{}
		for _, c := range all {
			e, ok := engineOf(c.UA)
			if !ok || e.Kind != Chromium {
				continue
			}
			prefix := shapePrefix(c.Names)
			if prefix == "" {
				continue
			}
			why, skip := chromiumExcluded[c.HAR]
			if !skip {
				why, skip = chromiumExcluded[c.String()]
			}
			if skip {
				t.Logf("excluded %s: %s", c, why)
				continue
			}
			total++
			majors[e.Major] = true
			if c.HTTP2 && !slices.Equal(c.Pseudo, law.Chromium.Pseudo) {
				t.Errorf("%s: pseudo order %v, law %v", c, c.Pseudo, law.Chromium.Pseudo)
			}
			classes := chromiumReproduces(t, law, c, e, prefix)
			if len(classes) == 0 {
				t.Errorf("%s: no class reproduces %v", c, c.Names)
				continue
			}
			reproduced++
			t.Logf("%s chrome/%d %v", c, e.Major, classes)
		}
		if total != 76 || reproduced != total {
			t.Errorf("Chromium protected captures: %d/%d reproduced, want 76/76", reproduced, total)
		}
		lo, hi := law.Chromium.Witnessed[0], law.Chromium.Witnessed[1]
		if !majors[lo] || !majors[hi] {
			t.Errorf("witnessed majors %d-%d: captures carry %v", lo, hi, majors)
		}
		for m := range majors {
			if m < lo || m > hi {
				t.Errorf("capture major %d outside witnessed %d-%d", m, lo, hi)
			}
		}
	})

	t.Run("webkit", func(t *testing.T) { testWebkitCorpus(t, law, all) })
	t.Run("webkit-http1", func(t *testing.T) { testWebkitHTTP1(t, law, all) })
}
