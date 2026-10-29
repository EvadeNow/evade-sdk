package wireorder

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const testShapePrefix = "x-gyjwza5z-"

func chromeXHR(major int, calls ...string) Request {
	return Request{
		Engine: Engine{Kind: Chromium, Major: major}, Class: ClassXHR, Method: "POST", HTTP2: true,
		Calls: calls, Added: Added{Origin: true, Referer: true, Cookie: true, Body: true, Priority: true,
			ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}},
	}
}

// A captured Safari 18.7 username-validation XHR whose Shape block has no -a0.
func safariShapeXHR(pins ...*Pin) Request {
	calls := []string{"content-type"}
	for _, s := range "fbcdza" {
		calls = append(calls, testShapePrefix+string(s))
	}
	return Request{
		Engine: Engine{Kind: WebKit, Major: 18, Minor: 7}, Class: ClassXHR, Method: "POST", HTTP2: true,
		Calls: calls, ShapePrefix: testShapePrefix, Pins: pins,
		Added: Added{Origin: true, Referer: true, Cookie: true, Body: true, Priority: true},
	}
}

// testInstall is a synthetic Shape install pin, one precedence: the
// generic Pin mechanics need a pin that orders the Shape block, not any
// page's certificate.
var testInstall = &Pin{ID: "test-install", Engine: "webkit", Install: [][2]string{{"shape:a", "shape:b"}}}

func wantErr[E error](t *testing.T, err error) E {
	t.Helper()
	var typed E
	if !errors.As(err, &typed) {
		t.Fatalf("want %T, got %v", typed, err)
	}
	return typed
}

func testLaw(t *testing.T) *lawFile {
	t.Helper()
	return law
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

// dictionaryOf strips r's HTTP/1.1 framing and its generation's tail from
// o, a wire order of r.
func dictionaryOf(t *testing.T, r Request, o []string) []string {
	t.Helper()
	w := &testLaw(t).WebKit
	g := w.generation(r.Engine)
	if g == nil {
		t.Fatalf("%s is in no WebKit generation", r.Engine)
	}
	if !r.HTTP2 {
		o = o[len(w.HTTP1Prefix) : len(o)-len(w.HTTP1Suffix)]
	}
	return slices.Clone(o[:len(o)-len(g.tail(&r, lowerAll(r.Calls)))])
}

// decidingPin is a synthetic law case that leaves only o among r's
// outcomes: o's dictionary with each adjacent pair a precedence, on r's
// generation.
func decidingPin(t *testing.T, r Request, o []string) *Pin {
	t.Helper()
	dict := dictionaryOf(t, r, o)
	var wire [][2]string
	for i := 1; i < len(dict); i++ {
		wire = append(wire, [2]string{dict[i-1], dict[i]})
	}
	return &Pin{ID: "test-decide", Engine: "webkit", Cases: []PinCase{{Dictionary: dict, Wire: wire,
		Generations: []string{testLaw(t).WebKit.generation(r.Engine).Name}, Witnesses: []Witness{{HAR: "test"}}}}}
}

func capturedPin(dict []string, generations ...string) *Pin {
	return &Pin{ID: "test-captured", Engine: "webkit", Cases: []PinCase{{Dictionary: dict, Captured: true,
		Generations: generations, Witnesses: []Witness{{HAR: "test"}}}}}
}

// wantLateOrder: r has an order, the one the same request has on a late build (Safari 18.7).
func wantLateOrder(t *testing.T, name string, r Request) {
	t.Helper()
	late := r
	late.Engine = Engine{Kind: WebKit, Major: 18, Minor: 7}
	want, err := Order(late)
	if err != nil {
		t.Fatalf("%s on late: %v", name, err)
	}
	if got, err := Order(r); err != nil || !slices.Equal(got.Header, want.Header) || !slices.Equal(got.Pseudo, want.Pseudo) {
		t.Errorf("%s: got %v %v (%v), late %v %v", name, got.Header, got.Pseudo, err, want.Header, want.Pseudo)
	}
}

// HYPOTHESIS(webkit_early_falls_back_to_late) and HYPOTHESIS(webkit_macos_is_ios_late): an early build's
// XHR with the browser's priority, under late-scoped pins, and macOS Safari 26.6.2's are ordered as late.
func TestWebKitFallsBackToLate(t *testing.T) {
	r := safariShapeXHR(testInstall)
	outcomes, err := Outcomes(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Pins = append(r.Pins, decidingPin(t, r, outcomes[0]))
	early := r
	early.Engine = Engine{Kind: WebKit, Major: 18}
	wantLateOrder(t, "early priority", early)
	mac := r
	mac.Engine = EngineFromUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15")
	wantLateOrder(t, "macos safari 26.6.2", mac)
}

func TestOrderRefusesClassesOutsideTheCertificate(t *testing.T) {
	for _, class := range []Class{ClassUnknown, ClassNavigation, ClassForm, ClassPreflight, ClassNoCORS} {
		r := chromeXHR(151, "content-type")
		r.Class = class
		_, err := Order(r)
		wantErr[*UnwitnessedError](t, err)
	}
}

func TestOrderRefusesUnwitnessedEngines(t *testing.T) {
	for _, r := range []Request{
		chromeXHR(140, "content-type"),
		chromeXHR(157, "content-type"),
		{Engine: Engine{Kind: EngineUnknown, Major: 148}, Class: ClassFetch, Method: "GET"},
		func() Request { r := safariShapeXHR(testInstall); r.Engine.Major = 17; return r }(),
		func() Request { r := safariShapeXHR(testInstall); r.Engine.Major = 19; return r }(),
		func() Request { r := safariShapeXHR(testInstall); r.Engine.Minor = 1; return r }(),
		func() Request { r := safariShapeXHR(testInstall); r.Engine.Minor, r.Engine.WebView = 2, true; return r }(),
		func() Request {
			r := safariShapeXHR(testInstall)
			r.Engine.Major, r.Engine.Minor = 26, 5
			r.Engine.WebView = true
			return r
		}(),
	} {
		_, err := Order(r)
		wantErr[*UnwitnessedError](t, err)
	}
	for _, major := range []int{141, 156} {
		if _, err := Order(chromeXHR(major, "content-type")); err != nil {
			t.Fatalf("Chrome %d is witnessed: %v", major, err)
		}
	}
}

// TestWebKitHTTP1PinCase: a WebKit XHR GET on HTTP/1.1 is framed by
// host ... connection with no pseudo-headers; unpinned the law leaves it
// open, Outcomes lists exactly the open orders, and a case on its
// dictionary selects each one.
func TestWebKitHTTP1PinCase(t *testing.T) {
	r := Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 7}, Class: ClassXHR, Method: "GET",
		Added: Added{Origin: true, Referer: true, Priority: true}}
	_, err := Order(r)
	amb := wantErr[*AmbiguousError](t, err)
	outcomes, err := Outcomes(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != amb.Outcomes {
		t.Fatalf("Outcomes lists %d orders, Order's ambiguity %d", len(outcomes), amb.Outcomes)
	}
	for _, o := range outcomes {
		if o[0] != "host" || o[len(o)-1] != "connection" {
			t.Errorf("outcome %v is not framed by host ... connection", o)
		}
		pinned := r
		pinned.Pins = []*Pin{decidingPin(t, r, o)}
		got, err := Order(pinned)
		if err != nil || !slices.Equal(got.Header, o) || got.Pseudo != nil {
			t.Errorf("case on %v: got %v %v (%v), want it and no pseudo-headers", o, got.Pseudo, got.Header, err)
		}
	}
}

func TestOrderRefusesWebKitInputsTheLawDoesNotCover(t *testing.T) {
	base := safariShapeXHR(testInstall)
	outcomes, err := Outcomes(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Pins = append(base.Pins, decidingPin(t, base, outcomes[0]))
	if _, err := Order(base); err != nil {
		t.Fatalf("the decided request: %v", err)
	}
	cases := map[string]func(*Request){
		"client hints":   func(r *Request) { r.Added.ClientHints = []string{"sec-ch-ua"} },
		"storage access": func(r *Request) { r.Added.StorageAccess = true },
		"authorization":  func(r *Request) { r.Calls = append(r.Calls, "authorization") },
		"accept-lang":    func(r *Request) { r.Calls = append(r.Calls, "accept-language") },
		"priority":       func(r *Request) { r.Calls = append(r.Calls, "priority") },
		"no install pin": func(r *Request) { r.Pins = nil },
	}
	for name, mutate := range cases {
		r := base
		r.Calls = slices.Clone(base.Calls)
		mutate(&r)
		_, err := Order(r)
		if _, ok := errors.AsType[*UnwitnessedError](err); !ok {
			t.Errorf("%s: want UnwitnessedError, got %v", name, err)
		}
	}
}

func TestOrderRejectsImpossibleInputs(t *testing.T) {
	cases := map[string]Request{
		"empty method":     func() Request { r := chromeXHR(151); r.Method = ""; return r }(),
		"GET with body":    func() Request { r := chromeXHR(151); r.Method = "GET"; return r }(),
		"POST sans origin": func() Request { r := chromeXHR(151); r.Added.Origin = false; return r }(),
		"repeat":           chromeXHR(151, "x-a", "X-A"),
		"forbidden":        chromeXHR(151, "cookie"),
		"origin":           chromeXHR(151, "origin"),
		"sec-":             chromeXHR(151, "sec-fetch-mode"),
		"user-agent":       chromeXHR(151, "user-agent"),
		"proxy-":           chromeXHR(151, "proxy-foo"),
		"space":            chromeXHR(151, "x a"),
		"colon":            chromeXHR(151, ":path"),
		"non-ascii":        chromeXHR(151, "x-é"),
		"prefix unused":    func() Request { r := chromeXHR(151, "x-a"); r.ShapePrefix = testShapePrefix; return r }(),
		"nil pin":          safariShapeXHR(testInstall, nil),
		"webkit pin":       func() Request { r := chromeXHR(151, "x-a"); r.Pins = []*Pin{testInstall}; return r }(),
		"redirected xhr":   func() Request { r := safariShapeXHR(testInstall); r.Redirected = true; return r }(),
	}
	for name, r := range cases {
		_, err := Order(r)
		if _, ok := errors.AsType[*InputError](err); !ok {
			t.Errorf("%s: want InputError, got %v", name, err)
		}
	}
}

func TestOrderDoesNotMutateTheRequest(t *testing.T) {
	r := chromeXHR(151, "Content-Type", "X-Api-Key")
	before := slices.Clone(r.Calls)
	w, err := Order(r)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Calls, before) {
		t.Fatalf("calls mutated: %v", r.Calls)
	}
	w.Pseudo[0], w.Header[0] = "mutated", "mutated"
	again, err := Order(r)
	if err != nil {
		t.Fatal(err)
	}
	if again.Pseudo[0] == "mutated" || again.Header[0] == "mutated" {
		t.Fatal("Order returned law-owned memory")
	}
}

func TestChromiumFetchIgnoresProgramOrder(t *testing.T) {
	a := chromeXHR(151, "x-b", "content-type", "x-a")
	a.Class = ClassFetch
	b := chromeXHR(151, "x-a", "x-b", "content-type")
	b.Class = ClassFetch
	wa, err := Order(a)
	if err != nil {
		t.Fatal(err)
	}
	wb, err := Order(b)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(wa.Header, wb.Header) {
		t.Fatalf("fetch header lists are sorted before Blink sees them: %v vs %v", wa.Header, wb.Header)
	}
}

func TestChromiumFramingByProtocol(t *testing.T) {
	r := chromeXHR(151, "content-type")
	h2, err := Order(r)
	if err != nil {
		t.Fatal(err)
	}
	r.HTTP2 = false
	h1, err := Order(r)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h1.Header[:3], []string{"host", "connection", "content-length"}) || slices.Contains(h1.Header, "priority") {
		t.Fatalf("HTTP/1.1: %v", h1.Header)
	}
	if h2.Header[0] != "content-length" || h2.Header[len(h2.Header)-1] != "priority" || slices.Contains(h2.Header, "host") {
		t.Fatalf("HTTP/2: %v", h2.Header)
	}
	for _, name := range []string{"accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
		"accept-encoding", "accept-language", "cookie", "user-agent", "sec-ch-ua"} {
		if !slices.Contains(h2.Header, name) {
			t.Errorf("HTTP/2 order lacks %s: %v", name, h2.Header)
		}
	}
	if slices.Contains(h2.Header, "sec-fetch-user") || slices.Contains(h2.Header, "sec-ch-ua-model") {
		t.Errorf("order carries headers the request does not: %v", h2.Header)
	}
}

// TestWebKitAmbiguityFailsClosedUntilAPinCaseDecides: a case decides only
// on its own dictionary and generations.
func TestWebKitAmbiguityFailsClosedUntilAPinCaseDecides(t *testing.T) {
	r := safariShapeXHR(testInstall)
	_, err := Order(r)
	amb := wantErr[*AmbiguousError](t, err)
	outcomes, err := Outcomes(r)
	if err != nil {
		t.Fatal(err)
	}
	if amb.Outcomes < 2 || amb.Outcomes != len(outcomes) || len(amb.Names) == 0 {
		t.Fatalf("ambiguity %v; Outcomes lists %d orders", amb, len(outcomes))
	}
	elsewhere := decidingPin(t, r, outcomes[0])
	elsewhere.Cases[0].Dictionary = slices.DeleteFunc(slices.Clone(elsewhere.Cases[0].Dictionary), func(n string) bool { return n == "content-type" })
	otherGeneration := decidingPin(t, r, outcomes[0])
	otherGeneration.Cases[0].Generations = []string{"law"}
	for name, p := range map[string]*Pin{"another dictionary": elsewhere, "another generation": otherGeneration} {
		r.Pins = []*Pin{testInstall, p}
		_, err = Order(r)
		if _, ok := errors.AsType[*AmbiguousError](err); !ok {
			t.Errorf("a case on %s: %v, want ambiguous", name, err)
		}
	}
	pseudo := testLaw(t).WebKit.Pseudo
	for _, o := range [][]string{outcomes[0], outcomes[len(outcomes)-1]} {
		r.Pins = []*Pin{testInstall, decidingPin(t, r, o)}
		w, err := Order(r)
		if err != nil || !slices.Equal(w.Header, o) || !slices.Equal(w.Pseudo, pseudo) {
			t.Errorf("case on %v: got %v %v (%v)", o, w.Pseudo, w.Header, err)
		}
	}
}

func TestOrderUniversalSelectsAnAdmissibleWebKitHistory(t *testing.T) {
	r := safariShapeXHR()
	if _, err := Order(r); !errors.As(err, new(*UnwitnessedError)) {
		t.Fatalf("strict order without an install pin = %v, want unwitnessed", err)
	}
	outcomes, err := Outcomes(r)
	if err != nil {
		t.Fatal(err)
	}
	first, err := OrderUniversal(r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OrderUniversal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(first.Header, second.Header) || !slices.Equal(first.Pseudo, second.Pseudo) {
		t.Fatalf("universal order changed between calls: %v/%v then %v/%v", first.Pseudo, first.Header, second.Pseudo, second.Header)
	}
	if !slices.ContainsFunc(outcomes, func(outcome []string) bool { return slices.Equal(outcome, first.Header) }) {
		t.Fatalf("universal order %v is not one of the engine law's %d admissible outcomes", first.Header, len(outcomes))
	}
}

func TestOrderUniversalKeepsPageSetWebKitTailNamesInTheDictionary(t *testing.T) {
	r := Request{
		Engine: Engine{Kind: WebKit, Major: 26, Minor: 6}, Class: ClassXHR, Method: "POST", HTTP2: true,
		Calls: []string{"accept", "content-type", "x-requested-with", "accept-language", "x-g1-area-code", "x-csrf-token"},
		Added: Added{Origin: true, Referer: true, Body: true, Priority: true},
	}
	if _, err := Order(r); !errors.As(err, new(*UnwitnessedError)) {
		t.Fatalf("strict page-set accept-language order = %v, want unwitnessed", err)
	}
	got, err := OrderUniversal(r)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range got.Header {
		if name == "accept-language" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("accept-language occurs %d times in %v", count, got.Header)
	}
	if tail := got.Header[len(got.Header)-2:]; !slices.Equal(tail, []string{"priority", "accept-encoding"}) {
		t.Fatalf("CFNetwork tail = %v in %v", tail, got.Header)
	}
	if !slices.Equal(got.Pseudo, []string{":method", ":scheme", ":authority", ":path"}) {
		t.Fatalf("pseudo order = %v", got.Pseudo)
	}
	r.Engine.Major = 17
	if _, err := Order(r); !errors.As(err, new(*UnwitnessedError)) {
		t.Fatalf("strict uncovered WebKit build = %v, want unwitnessed", err)
	}
	uncovered, err := OrderUniversal(r)
	if err != nil || !slices.Equal(uncovered.Header, got.Header) || !slices.Equal(uncovered.Pseudo, got.Pseudo) {
		t.Fatalf("uncovered WebKit build = %v (%v), want late's %v (HYPOTHESIS(webkit-uncovered-generation-late))", uncovered, err, got)
	}
	r.Engine.Major = 26
	r.Calls = append(r.Calls, "accept")
	if _, err := OrderUniversal(r); !errors.As(err, new(*InputError)) {
		t.Fatalf("duplicate page call = %v, want input error", err)
	}
}

// safariShapeXHR calls shape:b before shape:a; testInstall's shape:a < shape:b
// outranks that supplied order instead of cycling with it.
func TestOrderUniversalHonorsInstallPins(t *testing.T) {
	r := safariShapeXHR(testInstall)
	_, err := Order(r)
	wantErr[*AmbiguousError](t, err)
	pinned, err := Outcomes(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OrderUniversal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(pinned, func(o []string) bool { return slices.Equal(o, got.Header) }) {
		t.Fatalf("universal order %v is none of the %d outcomes under the install pin", got.Header, len(pinned))
	}
	if !precedes(got.Header, testShapePrefix+"a", testShapePrefix+"b") {
		t.Fatalf("universal order %v breaks the install precedence shape:a < shape:b", got.Header)
	}
	reversed := &Pin{ID: "test-install-reversed", Engine: "webkit", Install: [][2]string{{"shape:b", "shape:a"}}}
	r.Pins = []*Pin{testInstall, reversed}
	_, err = OrderUniversal(r)
	wantErr[*UnwitnessedError](t, err)
}

// A matching case's wire precedences constrain the emitted order, not the
// insertion history; no admitted outcome obeying them fails closed.
func TestOrderUniversalObeysMatchingWireCases(t *testing.T) {
	r := safariShapeXHR(testInstall)
	outcomes, err := Outcomes(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) < 2 {
		t.Fatalf("%d outcomes; the test needs the law to leave a choice", len(outcomes))
	}
	for _, o := range [][]string{outcomes[0], outcomes[len(outcomes)-1]} {
		// Without an install pin strict Order refuses the Shape block before
		// reading cases, so only the universal path applies this one.
		cased := safariShapeXHR(decidingPin(t, r, o))
		if _, err := Order(cased); !errors.As(err, new(*UnwitnessedError)) {
			t.Fatalf("strict order without an install pin = %v, want unwitnessed", err)
		}
		got, err := OrderUniversal(cased)
		if err != nil || !slices.Equal(got.Header, o) {
			t.Errorf("case on %v: got %v (%v)", o, got.Header, err)
		}
	}
	dict := dictionaryOf(t, r, outcomes[0])
	a, b := slices.Index(dict, testShapePrefix+"a"), slices.Index(dict, testShapePrefix+"b")
	dict[a], dict[b] = dict[b], dict[a]
	contrary := &Pin{ID: "test-contrary", Engine: "webkit", Cases: []PinCase{{Dictionary: dict,
		Wire: [][2]string{{testShapePrefix + "b", testShapePrefix + "a"}}, Generations: []string{"late"}, Witnesses: []Witness{{HAR: "test"}}}}}
	r.Pins = []*Pin{testInstall, contrary}
	_, err = OrderUniversal(r)
	wantErr[*UnwitnessedError](t, err)
}

// Strict Order orders an early build as late (HYPOTHESIS(webkit_early_falls_back_to_late));
// OrderUniversal's callers pass generation-correct added headers, so it keeps
// the early generation's facts: accept-language and accept-encoding inside the
// CF dictionary, cookie the whole tail, and no priority header.
func TestOrderUniversalKeepsEarlyGenerationFacts(t *testing.T) {
	r := safariShapeXHR()
	r.Engine.Minor, r.Added.Priority = 0, false
	if _, err := Order(r); !errors.As(err, new(*UnwitnessedError)) {
		t.Fatalf("strict early order without an install pin = %v, want unwitnessed", err)
	}
	got, err := OrderUniversal(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header[len(got.Header)-1] != "cookie" || slices.Contains(got.Header, "priority") {
		t.Fatalf("early tail in %v, want cookie alone and no priority", got.Header)
	}
	for _, name := range []string{"accept-language", "accept-encoding", "cookie"} {
		if n := len(slices.DeleteFunc(slices.Clone(got.Header), func(h string) bool { return h != name })); n != 1 {
			t.Errorf("%s occurs %d times in %v", name, n, got.Header)
		}
	}
	r.Added.Priority = true
	_, err = OrderUniversal(r)
	wantErr[*InputError](t, err)
}

// Strict Order resolves this Safari 18.0 XHR by late's law
// (HYPOTHESIS(webkit_early_falls_back_to_late)): it accepts priority, ends in
// late's tail and takes late's captured cases. None of that is the early
// generation's: OrderUniversal refuses the priority header and keeps early's
// tail although late's law leaves this dictionary unambiguous, exactly as it
// does on a dictionary late's law leaves open, and only early's own captured
// case orders it. No early capture holds these names; the universal order is
// HYPOTHESIS(webkit-universal-order)'s canonical history (late's commons,
// x-a, then early's Inside accept-language and accept-encoding) in the CF
// table, then early's cookie tail.
func TestOrderUniversalIgnoresStrictLateFallback(t *testing.T) {
	r := Request{Engine: Engine{Kind: WebKit, Major: 18}, Class: ClassXHR, Method: "GET", HTTP2: true,
		Calls: []string{"x-a"}, Added: Added{Referer: true, Cookie: true, Priority: true}}
	if strict, err := Order(r); err != nil || !slices.Contains(strict.Header, "priority") {
		t.Fatalf("strict late fallback = %v (%v), want late's priority", strict.Header, err)
	}
	_, err := OrderUniversal(r)
	wantErr[*InputError](t, err)

	r.Added.Priority = false
	strict, err := Order(r)
	if err != nil {
		t.Fatal(err)
	}
	lateTail := []string{"accept-language", "accept-encoding", "cookie"}
	if !slices.Equal(strict.Header[len(strict.Header)-len(lateTail):], lateTail) {
		t.Fatalf("strict late fallback %v does not end in late's tail %v", strict.Header, lateTail)
	}
	got, err := OrderUniversal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"accept", "sec-fetch-site", "accept-encoding", "x-a", "sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "accept-language", "cookie"}
	if !slices.Equal(got.Header, want) {
		t.Fatalf("universal early order %v, want the canonical early order %v", got.Header, want)
	}
	open := safariShapeXHR()
	open.Engine.Minor, open.Added.Priority = 0, false
	if o, err := OrderUniversal(open); err != nil || o.Header[len(o.Header)-1] != "cookie" ||
		o.Header[len(o.Header)-2] == "accept-encoding" && o.Header[len(o.Header)-3] == "accept-language" {
		t.Fatalf("universal early order on an open dictionary = %v (%v), want early's tail", o.Header, err)
	}

	l := testLaw(t)
	calls, shape, err := l.validate(&r)
	if err != nil {
		t.Fatal(err)
	}
	early := l.WebKit.generation(r.Engine)
	names := newWebkitDictionary(&l.WebKit, &r, calls, shape).names
	own := early.dictionary(&r, names)
	slices.Reverse(own)
	r.Pins = []*Pin{capturedPin(own, early.Name)}
	ownWant := slices.Concat(own, early.tail(&r, calls))
	if s, err := Order(r); err != nil || !slices.Equal(s.Header, ownWant) {
		t.Fatalf("strict own captured case = %v (%v), want %v", s.Header, err, ownWant)
	}
	if o, err := OrderUniversal(r); err != nil || !slices.Equal(o.Header, ownWant) {
		t.Errorf("universal own captured case = %v (%v), want %v", o.Header, err, ownWant)
	}
	lateSet := slices.Clone(names) // late's Inside is empty
	slices.Reverse(lateSet)
	r.Pins = []*Pin{capturedPin(lateSet, "late")}
	if s, err := Order(r); err != nil || !slices.Equal(s.Header[:len(lateSet)], lateSet) {
		t.Fatalf("strict late fallback under late's captured case %v = %v (%v)", lateSet, s.Header, err)
	}
	if o, err := OrderUniversal(r); err != nil || !slices.Equal(o.Header, got.Header) {
		t.Errorf("late's captured case ordered the early build: %v (%v), want %v", o.Header, err, got.Header)
	}
}

// Late's counterwitnesses and cases are stated on dictionaries without early's Inside names: an early
// build's request whose own names are probe-safari-16#19's dictionary is refused by it, although early adds
// accept-language and accept-encoding to its CF table.
func TestOrderUniversalEarlyKeepsLateCounterwitnesses(t *testing.T) {
	r := Request{Engine: Engine{Kind: WebKit, Major: 18}, Class: ClassXHR, Method: "GET", HTTP2: true,
		Calls: []string{"x-beta", "x-alpha"}, Added: Added{Referer: true}}
	for name, order := range map[string]func(Request) (Wire, error){"strict": Order, "universal": OrderUniversal} {
		_, err := order(r)
		if u := wantErr[*UnwitnessedError](t, err); !strings.Contains(u.Reason, "probe-safari-16#19") {
			t.Errorf("%s: %v, want the probe-safari-16#19 counterwitness", name, err)
		}
	}
}

// HYPOTHESIS(webkit-uncovered-generation-late): an exact captured case of the
// late generation on the request's dictionary orders an uncovered build ahead
// of the canonical history, as strict Order honours it on a late build; a
// captured case on another generation or dictionary does not.
func TestOrderUniversalHonorsLateCapturedCaseOnUncoveredBuilds(t *testing.T) {
	late := Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 7}, Class: ClassXHR, Method: "GET", HTTP2: true,
		Calls: []string{"x-a"}, Added: Added{Referer: true, Cookie: true, Priority: true}}
	canonical, err := OrderUniversal(late)
	if err != nil {
		t.Fatal(err)
	}
	dict := dictionaryOf(t, late, canonical.Header)
	captured := slices.Clone(dict)
	slices.Reverse(captured)
	want := slices.Concat(captured, canonical.Header[len(dict):])
	late.Pins = []*Pin{capturedPin(captured, "late")}
	if got, err := Order(late); err != nil || !slices.Equal(got.Header, want) {
		t.Fatalf("strict late captured %v: got %v (%v), want %v", captured, got.Header, err, want)
	}
	for _, e := range []Engine{{Kind: WebKit, Major: 18, Minor: 2}, {Kind: WebKit, Major: 26, Minor: 2, WebView: true}} {
		r := late
		r.Engine = e
		_, err := Order(r)
		wantErr[*UnwitnessedError](t, err)
		got, err := OrderUniversal(r)
		if err != nil || !slices.Equal(got.Header, want) || !slices.Equal(got.Pseudo, canonical.Pseudo) {
			t.Errorf("%s: got %v %v (%v), want late's captured %v", e, got.Pseudo, got.Header, err, want)
		}
		for name, pins := range map[string][]*Pin{
			"another generation": {capturedPin(captured, "law")},
			"another dictionary": {capturedPin(append(slices.Clone(captured), "x-b"), "late")},
		} {
			r.Pins = pins
			if got, err := OrderUniversal(r); err != nil || !slices.Equal(got.Header, canonical.Header) {
				t.Errorf("%s, %s: got %v (%v), want the canonical %v", e, name, got.Header, err, canonical.Header)
			}
		}
	}
}

func TestWebKitPinCasesBindThePhysicalNames(t *testing.T) {
	// Another Shape prefix moves every CF home: a case witnessed on
	// testShapePrefix must not decide it.
	r := safariShapeXHR(testInstall)
	outcomes, err := Outcomes(r)
	if err != nil {
		t.Fatal(err)
	}
	decide := decidingPin(t, r, outcomes[0])
	const other = "x-q7m2k9vb-"
	for i, name := range r.Calls {
		r.Calls[i] = strings.Replace(name, testShapePrefix, other, 1)
	}
	r.ShapePrefix = other
	pinned := r
	pinned.Pins = []*Pin{testInstall, decide}
	w1, err1 := Order(pinned)
	w2, err2 := Order(r)
	if (err1 == nil) != (err2 == nil) || !slices.Equal(w1.Header, w2.Header) {
		t.Fatalf("the case applied to another prefix: %v/%v vs %v/%v", w1.Header, err1, w2.Header, err2)
	}
}

// TestWebKitCapturedCaseIsItsOrder: a captured case is the order of
// exactly its dictionary on its generations over HTTP/2, one the insertion
// law does not reach included, followed by the generation's tail; on a
// generation without the insertion law it is the only order there is.
func TestWebKitCapturedCaseIsItsOrder(t *testing.T) {
	late := Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 7}, Class: ClassXHR, Method: "GET", HTTP2: true,
		Calls: []string{"x-a"}, Added: Added{Referer: true, Cookie: true, Priority: true}}
	outcomes, err := Outcomes(late)
	if err != nil {
		t.Fatal(err)
	}
	dict := dictionaryOf(t, late, outcomes[0])
	tail := outcomes[0][len(dict):]
	var unreached []string
	permute(slices.Clone(dict), func(p []string) bool {
		if slices.ContainsFunc(outcomes, func(o []string) bool { return slices.Equal(o[:len(dict)], p) }) {
			return false
		}
		unreached = slices.Clone(p)
		return true
	})
	if unreached == nil {
		t.Fatalf("the law reaches every order of %v", dict)
	}
	want := slices.Concat(unreached, tail)
	pinned := late
	pinned.Pins = []*Pin{capturedPin(unreached, "late")}
	if got, err := Order(pinned); err != nil || !slices.Equal(got.Header, want) {
		t.Errorf("captured %v: got %v (%v), want %v", unreached, got.Header, err, want)
	}
	for name, r := range map[string]Request{
		"another generation": func() Request { r := late; r.Pins = []*Pin{capturedPin(unreached, "law")}; return r }(),
		"HTTP/1.1":           func() Request { r := pinned; r.HTTP2 = false; return r }(),
		"another dictionary": func() Request { r := pinned; r.Calls = []string{"x-b"}; return r }(),
	} {
		if got, err := Order(r); err == nil && slices.Equal(dictionaryOf(t, r, got.Header), unreached) {
			t.Errorf("%s: the captured case applied: %v", name, got.Header)
		}
	}

	// HYPOTHESIS(webkit_early_falls_back_to_late): off its captured case an early build is ordered as late.
	early := late
	early.Engine = Engine{Kind: WebKit, Major: 18}
	early.Added.Priority = false
	wantLateOrder(t, "early off its captured case", early)
	law := testLaw(t)
	g := law.WebKit.generation(early.Engine)
	calls, shape, err := law.validate(&early)
	if err != nil {
		t.Fatal(err)
	}
	set := g.dictionary(&early, newWebkitDictionary(&law.WebKit, &early, calls, shape).names)
	early.Pins = []*Pin{capturedPin(set, g.Name)}
	if got, err := Order(early); err != nil || !slices.Equal(got.Header, slices.Concat(set, g.tail(&early, calls))) {
		t.Errorf("generation %s captured %v: got %v (%v)", g.Name, set, got.Header, err)
	}
}

// TestOutcomesUnderInstallPrecedences: Outcomes honours the pins' install
// precedences, needs no install pin for a Shape block, and refuses what
// the insertion law does not order.
func TestOutcomesUnderInstallPrecedences(t *testing.T) {
	r := safariShapeXHR(testInstall)
	pinned, err := Outcomes(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Pins = nil
	free, err := Outcomes(r)
	if err != nil {
		t.Fatalf("a Shape block without an install pin: %v", err)
	}
	if len(pinned) == 0 || len(pinned) > len(free) {
		t.Fatalf("%d outcomes under the install pin, %d free", len(pinned), len(free))
	}
	for _, o := range pinned {
		if !precedes(o, testShapePrefix+"a", testShapePrefix+"b") {
			t.Errorf("outcome %v breaks the install precedence shape:a < shape:b", o)
		}
		if !slices.ContainsFunc(free, func(f []string) bool { return slices.Equal(f, o) }) {
			t.Errorf("outcome %v under the install pin is no free outcome", o)
		}
	}
	refused := map[string]Request{
		"chromium":   chromeXHR(151, "content-type"),
		"navigation": {Engine: Engine{Kind: WebKit, Major: 18, Minor: 7}, Class: ClassNavigation, Method: "GET", HTTP2: true},
		"safari 17":  func() Request { r := safariShapeXHR(); r.Engine.Major = 17; return r }(),
		"no insertion law": func() Request {
			r := safariShapeXHR()
			r.Engine.Minor, r.Added.Priority = 0, false
			return r
		}(),
		"page-set accept-language": func() Request {
			r := safariShapeXHR()
			r.Calls = append(r.Calls, "accept-language")
			return r
		}(),
	}
	for name, r := range refused {
		if _, err := Outcomes(r); !errors.As(err, new(*UnwitnessedError)) {
			t.Errorf("%s: %v, want unwitnessed", name, err)
		}
	}
	r = safariShapeXHR()
	r.Redirected = true
	_, err = Outcomes(r)
	wantErr[*InputError](t, err)
}

func TestParsePins(t *testing.T) {
	const valid = `[
 {"id": "install", "engine": "webkit", "install": [["shape:a", "shape:b"], ["shape:a0", "shape:z"]],
  "witnesses": [{"har": "h", "entry": 1}]},
 {"id": "page", "engine": "webkit", "cases": [
  {"dictionary": ["x-a", "accept"], "wire": [["x-a", "accept"]], "generations": ["late", "law"], "witnesses": [{"har": "h", "entry": 2}]},
  {"dictionary": ["accept", "x-a"], "captured": true, "generations": ["early"], "witnesses": [{"har": "h", "entry": 3}]}
 ]}
]`
	pins, err := ParsePins([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 || pins[0].ID != "install" || len(pins[0].Install) != 2 || !pins[1].Cases[1].Captured ||
		!slices.Equal(pins[1].Cases[0].Generations, []string{"late", "law"}) || pins[1].Cases[1].Witnesses[0] != (Witness{HAR: "h", Entry: 3}) {
		t.Fatalf("parsed %+v", pins)
	}
	lawCase := func(c string) string { return `[{"id": "p", "engine": "webkit", "cases": [` + c + `]}]` }
	for name, data := range map[string]string{
		"not an array":     `{"id": "p"}`,
		"trailing data":    `[] []`,
		"unknown field":    `[{"id": "p", "engine": "webkit", "majors": [26]}]`,
		"empty id":         `[{"id": "", "engine": "webkit"}]`,
		"repeated id":      `[{"id": "p", "engine": "webkit"}, {"id": "p", "engine": "webkit"}]`,
		"chromium":         `[{"id": "p", "engine": "chromium"}]`,
		"no engine":        `[{"id": "p"}]`,
		"page name":        `[{"id": "p", "engine": "webkit", "install": [["shape:a", "x-a"]]}]`,
		"bad suffix":       `[{"id": "p", "engine": "webkit", "install": [["shape:a", "shape:e"]]}]`,
		"bad continuation": `[{"id": "p", "engine": "webkit", "install": [["shape:a", "shape:bx"]]}]`,
		"self edge":        `[{"id": "p", "engine": "webkit", "install": [["shape:a", "shape:a"]]}]`,
		"no witnesses":     lawCase(`{"dictionary": ["x-a", "accept"], "wire": [["x-a", "accept"]], "generations": ["late"], "witnesses": []}`),
		"no generations":   lawCase(`{"dictionary": ["x-a", "accept"], "wire": [["x-a", "accept"]], "witnesses": [{"har": "h"}]}`),
		"unknown gen":      lawCase(`{"dictionary": ["x-a", "accept"], "wire": [["x-a", "accept"]], "generations": ["latest"], "witnesses": [{"har": "h"}]}`),
		"captured wire":    lawCase(`{"dictionary": ["x-a", "accept"], "wire": [["x-a", "accept"]], "captured": true, "generations": ["late"], "witnesses": [{"har": "h"}]}`),
		"law case no wire": lawCase(`{"dictionary": ["x-a", "accept"], "generations": ["late"], "witnesses": [{"har": "h"}]}`),
		"early law case":   lawCase(`{"dictionary": ["x-a", "accept"], "wire": [["x-a", "accept"]], "generations": ["early"], "witnesses": [{"har": "h"}]}`),
		"outside name":     lawCase(`{"dictionary": ["x-a", "accept"], "wire": [["x-a", "x-b"]], "generations": ["late"], "witnesses": [{"har": "h"}]}`),
		"contradiction":    lawCase(`{"dictionary": ["x-a", "accept"], "wire": [["accept", "x-a"]], "generations": ["late"], "witnesses": [{"har": "h"}]}`),
	} {
		if _, err := ParsePins([]byte(data)); !errors.As(err, new(*InputError)) {
			t.Errorf("%s: %v, want an input error", name, err)
		}
	}
}

func TestWebKitFacts(t *testing.T) {
	law := testLaw(t)
	w := &law.WebKit
	for _, e := range []Engine{{Kind: WebKit, Major: 18, Minor: 7}, {Kind: WebKit, Major: 18}, {Kind: WebKit, Major: 26, Minor: 6, WebView: true}} {
		f, err := WebKitFacts(e)
		if err != nil {
			t.Fatal(err)
		}
		g := w.generation(e)
		if f.Generation.Name != g.Name || !slices.Equal(f.Generation.Inside, g.Inside) || !slices.Equal(f.Generation.Tail, g.Tail) ||
			f.Generation.Priority != g.Priority || f.Generation.InsertionLaw != g.InsertionLaw || f.Generation.ScriptLaw != g.ScriptLaw {
			t.Errorf("%s: generation %+v, law %+v", e, f.Generation, g)
		}
		if !slices.Equal(f.CFNetworkTail, w.CFNetworkTail) || !slices.Equal(f.Unresolved, w.Unresolved) || !slices.Equal(f.Pseudo, w.Pseudo) ||
			!slices.Equal(f.HTTP1Prefix, w.HTTP1Prefix) || !slices.Equal(f.HTTP1Suffix, w.HTTP1Suffix) {
			t.Errorf("%s: facts %+v", e, f)
		}
		f.CFNetworkTail[0], f.Pseudo[0] = "mutated", "mutated"
		if len(f.Generation.Tail) != 0 {
			f.Generation.Tail[0] = "mutated"
		}
		if slices.Contains(w.CFNetworkTail, "mutated") || slices.Contains(w.Pseudo, "mutated") || slices.Contains(g.Tail, "mutated") {
			t.Fatal("WebKitFacts returned law-owned memory")
		}
	}
	for _, e := range []Engine{{Kind: Chromium, Major: 151}, {Kind: WebKit, Major: 17}, {}} {
		_, err := WebKitFacts(e)
		wantErr[*UnwitnessedError](t, err)
	}
}

// WebKitFactsUniversal states a witnessed build's own generation, exactly as
// strict WebKitFacts does (Safari 18.0 keeps early's no-priority facts), and
// an uncovered build's as late under
// HYPOTHESIS(webkit-uncovered-generation-late), which Hypothesis names.
// Strict WebKitFacts still refuses the uncovered builds.
func TestWebKitFactsUniversal(t *testing.T) {
	for _, e := range []Engine{
		{Kind: WebKit, Major: 18}, {Kind: WebKit, Major: 18, Minor: 3}, {Kind: WebKit, Major: 18, Minor: 7},
		{Kind: WebKit, Major: 26}, {Kind: WebKit, Major: 18, Minor: 6, WebView: true}, {Kind: WebKit, Major: 26, Minor: 6, WebView: true},
	} {
		strict, err := WebKitFacts(e)
		if err != nil {
			t.Fatal(err)
		}
		universal, err := WebKitFactsUniversal(e)
		if err != nil {
			t.Fatal(err)
		}
		if universal.Hypothesis != "" || !reflect.DeepEqual(universal, strict) {
			t.Errorf("%s: universal facts %+v, strict %+v", e, universal, strict)
		}
	}
	early, err := WebKitFactsUniversal(Engine{Kind: WebKit, Major: 18})
	if err != nil || early.Generation.Name != "early" || early.Generation.Priority {
		t.Fatalf("Safari 18.0 = %+v (%v), want early without priority", early.Generation, err)
	}
	late, err := WebKitFacts(Engine{Kind: WebKit, Major: 18, Minor: 7})
	if err != nil {
		t.Fatal(err)
	}
	late.Hypothesis = HypothesisUncoveredGenerationLate
	for _, e := range []Engine{
		{Kind: WebKit, Major: 18, Minor: 2}, {Kind: WebKit, Major: 18, Minor: 1}, {Kind: WebKit, Major: 17, Minor: 6},
		{Kind: WebKit, Major: 18, Minor: 7, WebView: true}, {Kind: WebKit, Major: 26, Minor: 2, WebView: true},
	} {
		_, err := WebKitFacts(e)
		wantErr[*UnwitnessedError](t, err)
		got, err := WebKitFactsUniversal(e)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, late) {
			t.Errorf("%s: universal facts %+v, want late's under %s: %+v", e, got, HypothesisUncoveredGenerationLate, late)
		}
	}
	for _, e := range []Engine{{Kind: Chromium, Major: 151}, {}} {
		_, err := WebKitFactsUniversal(e)
		wantErr[*UnwitnessedError](t, err)
	}
}

// An otherwise valid XHR or fetch on an uncovered WebKit build (Safari 18.2,
// Chrome for iOS on iOS 18.7 and 26.2) is refused by strict Order and
// Outcomes and ordered by OrderUniversal exactly as the same request on a
// late build. Input, client-hint and counterwitness refusals still apply.
func TestOrderUniversalOrdersUncoveredBuildsAsLate(t *testing.T) {
	base := Request{Class: ClassXHR, Method: "POST", HTTP2: true,
		Calls: []string{"accept", "content-type", "x-requested-with", "accept-language", "x-csrf-token"},
		Added: Added{Origin: true, Referer: true, Body: true, Priority: true}}
	lateReq := base
	lateReq.Engine = Engine{Kind: WebKit, Major: 18, Minor: 7}
	want, err := OrderUniversal(lateReq)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []Engine{
		{Kind: WebKit, Major: 18, Minor: 2}, {Kind: WebKit, Major: 18, Minor: 7, WebView: true}, {Kind: WebKit, Major: 26, Minor: 2, WebView: true},
	} {
		r := base
		r.Engine = e
		_, err := Order(r)
		wantErr[*UnwitnessedError](t, err)
		_, err = Outcomes(r)
		wantErr[*UnwitnessedError](t, err)
		got, err := OrderUniversal(r)
		if err != nil {
			t.Fatalf("%s: %v", e, err)
		}
		if !slices.Equal(got.Header, want.Header) || !slices.Equal(got.Pseudo, want.Pseudo) {
			t.Errorf("%s: %v, want late's %v", e, got, want)
		}
		hinted := r
		hinted.Added.ClientHints = []string{"sec-ch-ua"}
		_, err = OrderUniversal(hinted)
		wantErr[*UnwitnessedError](t, err)
		bad := r
		bad.Calls = append(slices.Clone(r.Calls), "accept")
		_, err = OrderUniversal(bad)
		wantErr[*InputError](t, err)
	}
	r := Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 2}, Class: ClassFetch, Method: "GET", HTTP2: true,
		Calls: []string{"x-probe"}}
	cw := *law
	cw.WebKit.Counterwitness = []Counterwitness{{HAR: "probe", Entry: 1, Reason: "test",
		Dictionary: []string{"x-probe", "accept", "user-agent", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"}}}
	if _, err := law.universalWebkitOrder(&r); err != nil {
		t.Fatalf("without the counterwitness: %v", err)
	}
	_, err = cw.universalWebkitOrder(&r)
	if u := wantErr[*UnwitnessedError](t, err); !strings.Contains(u.Reason, "probe#1") {
		t.Fatalf("refusal does not name the counterwitness: %v", u)
	}
}

func TestWebKitCounterwitnessRefusesItsDictionary(t *testing.T) {
	r := Request{Engine: Engine{Kind: WebKit, Major: 26}, Class: ClassFetch, Method: "GET", HTTP2: true,
		Calls: []string{"x-probe"}}
	cw := *law
	cw.WebKit.Counterwitness = []Counterwitness{{HAR: "probe", Entry: 1, Reason: "test",
		Dictionary: []string{"x-probe", "accept", "user-agent", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"}}}
	if _, err := law.order(&r); err != nil {
		if _, refused := errors.AsType[*UnwitnessedError](err); refused {
			t.Fatalf("without the counterwitness: %v", err)
		}
	}
	_, err := cw.order(&r)
	if u := wantErr[*UnwitnessedError](t, err); !strings.Contains(u.Reason, "probe#1") {
		t.Fatalf("refusal does not name the counterwitness: %v", u)
	}
}

func TestBlinkMapIteratesEachKeyOnce(t *testing.T) {
	var keys []string
	for i := range 40 {
		keys = append(keys, "x-key-"+strings.Repeat("k", i))
	}
	got := blinkMap(append(slices.Clone(keys), keys[3], keys[17]))
	if len(got) != len(keys) {
		t.Fatalf("%d keys iterated, want %d", len(got), len(keys))
	}
	for _, k := range keys {
		if !slices.Contains(got, k) {
			t.Fatalf("%s lost", k)
		}
	}
}

func TestLawDataIsWellFormed(t *testing.T) {
	for _, n := range law.WebKit.LoaderAdded {
		if !slices.Contains(law.WebKit.CommonHeaders, n) {
			t.Errorf("loader-added %s is not a WebKit common header", n)
		}
	}
	if !sameSet(law.WebKit.FormLoaderAdded, law.WebKit.LoaderAdded) {
		t.Errorf("form loader names %v are not the loader names %v", law.WebKit.FormLoaderAdded, law.WebKit.LoaderAdded)
	}
	tail := law.WebKit.CFNetworkTail
	for _, g := range law.WebKit.Generations {
		var split []string
		for _, n := range tail {
			switch {
			case slices.Contains(g.Inside, n) && slices.Contains(g.Tail, n):
				t.Errorf("generation %s keeps %s both inside and in its tail", g.Name, n)
			case slices.Contains(g.Inside, n), slices.Contains(g.Tail, n):
				split = append(split, n)
			case n != "priority" || g.Priority:
				t.Errorf("generation %s places %s nowhere", g.Name, n)
			}
		}
		if len(split) != len(g.Inside)+len(g.Tail) {
			t.Errorf("generation %s names %v %v outside the CFNetwork tail %v", g.Name, g.Inside, g.Tail, tail)
		}
		var inTail []string
		for _, n := range tail {
			if slices.Contains(g.Tail, n) {
				inTail = append(inTail, n)
			}
		}
		if !slices.Equal(inTail, g.Tail) {
			t.Errorf("generation %s tail %v is not in CFNetwork's order %v", g.Name, g.Tail, tail)
		}
		if g.InsertionLaw && len(g.Inside) != 0 {
			t.Errorf("generation %s: the insertion law places no inside name %v", g.Name, g.Inside)
		}
		if len(g.Builds) == 0 || len(g.Witnesses) == 0 {
			t.Errorf("generation %s states no builds or no witnesses", g.Name)
		}
		for _, b := range g.Builds {
			if !versionBefore(b.From, b.To) {
				t.Errorf("generation %s range %v-%v is empty", g.Name, b.From, b.To)
			}
			for _, o := range law.WebKit.Generations {
				for _, ob := range o.Builds {
					if (o.Name != g.Name || ob != b) && ob.WebView == b.WebView && versionBefore(b.From, ob.To) && versionBefore(ob.From, b.To) {
						t.Errorf("generations %s and %s overlap: %v and %v", g.Name, o.Name, b, ob)
					}
				}
			}
		}
		for _, w := range g.Witnesses {
			if got := law.WebKit.generation(EngineFromUserAgent(w.UserAgent)); got == nil || got.Name != g.Name {
				t.Errorf("generation %s witness %s: %q resolves to %v", g.Name, w.HAR, w.UserAgent, got)
			}
		}
	}
}

// OrderUniversal's mechanism data is consistent: the browser-owned GET insertion is the inserted-script law's
// plus upgrade-insecure-requests, each WebKit generation has exactly one browser-owned GET law, and Chromium's
// form runs cover the witnessed majors in order.
func TestUniversalLawDataIsWellFormed(t *testing.T) {
	w := &law.WebKit
	load := slices.DeleteFunc(slices.Clone(w.BrowserLoad.Insertion), func(n string) bool { return n == "upgrade-insecure-requests" })
	if !slices.Equal(load, w.InsertedScript.Insertion) || len(load) != len(w.BrowserLoad.Insertion)-1 {
		t.Errorf("browser-owned GET insertion %v is not the inserted-script law %v plus upgrade-insecure-requests", w.BrowserLoad.Insertion, w.InsertedScript.Insertion)
	}
	for _, n := range w.BrowserLoad.RedirectCarried {
		if !slices.Contains(w.CFNetworkTail, n) {
			t.Errorf("redirect-carried %s is no CFNetwork tail name", n)
		}
	}
	for _, n := range w.BrowserLoad.Reinserted {
		if !slices.Contains(w.BrowserLoad.Insertion, n) {
			t.Errorf("re-inserted %s is no browser-owned GET name", n)
		}
	}
	for _, n := range w.Preflight.Insertion {
		if !slices.Contains(w.CommonHeaders, n) {
			t.Errorf("preflight name %s is not a WebKit common header", n)
		}
	}
	for _, g := range w.Generations {
		if g.ScriptLaw == (len(g.BrowserGet) != 0) {
			t.Errorf("generation %s: script law %v with captured browser-owned GET %v", g.Name, g.ScriptLaw, g.BrowserGet)
		}
		for _, n := range g.BrowserGet {
			if !slices.Contains(w.BrowserLoad.Insertion, n) && !slices.Contains(g.Inside, n) {
				t.Errorf("generation %s browser-owned GET name %s is neither loader-set nor inside", g.Name, n)
			}
		}
		for _, n := range g.Inside {
			if !g.ScriptLaw && !slices.Contains(g.BrowserGet, n) {
				t.Errorf("generation %s browser-owned GET does not place inside name %s", g.Name, n)
			}
		}
	}
	c := &law.Chromium
	runs := c.Form.Majors
	if len(runs) == 0 || runs[0].From != c.Witnessed[0] || runs[len(runs)-1].To > c.Witnessed[1] {
		t.Fatalf("form runs %v fall outside the witnessed Chromium majors %v", runs, c.Witnessed)
	}
	for i, m := range runs {
		if m.From > m.To || i > 0 && m.From <= runs[i-1].To || len(m.Witnesses) == 0 || !slices.Contains(m.BrowserSet, "origin") {
			t.Errorf("form run %d %+v is empty, unordered, unwitnessed or without origin", i, m)
		}
	}
}

// Strict Order is unchanged beside OrderUniversal: it refuses every class without a strict law on both engines,
// keeps its WebKit fetch/XHR refusals, and ignores the universal-only inputs.
func TestStrictOrderKeepsItsRefusals(t *testing.T) {
	for _, e := range []Engine{{Kind: Chromium, Major: 151}, {Kind: WebKit, Major: 18, Minor: 7}} {
		for _, class := range []Class{ClassForm, ClassPreflight, ClassNoCORS} {
			_, err := Order(Request{Engine: e, Class: class, Method: "POST", HTTP2: true, Added: Added{Origin: true, Body: true}})
			wantErr[*UnwitnessedError](t, err)
		}
	}
	for _, class := range []Class{ClassNavigation, ClassScript} {
		_, err := Order(Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 7}, Class: class, Method: "GET", HTTP2: true,
			Added: Added{Referer: true, Priority: true, UpgradeInsecureRequests: class == ClassNavigation}})
		wantErr[*UnwitnessedError](t, err)
	}
	_, err := Order(safariShapeXHR())
	wantErr[*UnwitnessedError](t, err)
	_, err = Order(safariShapeXHR(testInstall))
	wantErr[*AmbiguousError](t, err)
	nav := Request{Engine: Engine{Kind: Chromium, Major: 154}, Class: ClassNavigation, Method: "GET", HTTP2: true,
		Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}, FetchUser: true, Priority: true}}
	for _, r := range []Request{chromeXHR(151, "content-type"), nav} {
		want, err := Order(r)
		if err != nil {
			t.Fatal(err)
		}
		r.Added.UpgradeInsecureRequests, r.Added.RequestHeaders = true, true
		if got, err := Order(r); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s %s with universal-only inputs: %v (%v), want %v", r.Engine, r.Class, got, err, want)
		}
	}
}

func TestXHRProgramOrdersMatchesBruteForce(t *testing.T) {
	page := []string{"content-type", "x-api-key", "accept", "x-application-name", "x-requested-with"}
	shapes := [][]string{
		{testShapePrefix + "f", testShapePrefix + "b", testShapePrefix + "c", testShapePrefix + "d", testShapePrefix + "z", testShapePrefix + "a"},
		{testShapePrefix + "f", testShapePrefix + "b", testShapePrefix + "c", testShapePrefix + "d", testShapePrefix + "z", testShapePrefix + "a", testShapePrefix + "a0"},
	}
	var variants []Request
	var units [][][]string
	for _, shape := range shapes {
		r := chromeXHR(151)
		r.ShapePrefix = testShapePrefix
		variants = append(variants, r)
		var u [][]string
		for _, p := range page {
			u = append(u, []string{p})
		}
		units = append(units, append(u, shape))
	}
	got, err := XHRProgramOrders(variants, units)
	if err != nil {
		t.Fatal(err)
	}
	sig := func(ws []Wire) string {
		var parts []string
		for _, w := range ws {
			parts = append(parts, strings.Join(w.Header, ","))
		}
		return strings.Join(parts, "|")
	}
	want := map[string]bool{}
	idx := []int{0, 1, 2, 3, 4, 5}
	var perm func(int)
	perm = func(k int) {
		if k == len(idx) {
			var ws []Wire
			for v, r := range variants {
				var calls []string
				for _, i := range idx {
					calls = append(calls, units[v][i]...)
				}
				r.Calls = calls
				w, err := Order(r)
				if err != nil {
					t.Fatal(err)
				}
				ws = append(ws, w)
			}
			want[sig(ws)] = true
			return
		}
		for i := k; i < len(idx); i++ {
			idx[k], idx[i] = idx[i], idx[k]
			perm(k + 1)
			idx[k], idx[i] = idx[i], idx[k]
		}
	}
	perm(0)
	if len(got) != len(want) {
		t.Fatalf("%d outcomes, brute force %d", len(got), len(want))
	}
	for _, o := range got {
		if !want[sig(o.Wires)] {
			t.Fatalf("outcome %v not reachable by brute force", o.Units)
		}
		for v, r := range variants {
			r.Calls = o.Calls[v]
			w, err := Order(r)
			if err != nil || !slices.Equal(w.Header, o.Wires[v].Header) {
				t.Fatalf("witness calls %v do not reach their wire: %v", o.Calls[v], err)
			}
		}
	}
	t.Logf("%d distinct outcome tuples", len(got))
}

func TestEngineFromUserAgent(t *testing.T) {
	for ua, want := range map[string]Engine{
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36":                            {Kind: Chromium, Major: 151},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1":  {Kind: WebKit, Major: 18, Minor: 7},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26 Mobile/15E148 Safari/604.1":      {Kind: WebKit, Major: 26},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0":              {},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/151.0 Mobile/15E148 Safari/604.1":     {Kind: WebKit, Major: 18, Minor: 7, WebView: true},
		"Mozilla/5.0 (iPad; CPU OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1":     {Kind: WebKit, Major: 18, Minor: 4, WebView: true},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15":  {},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/140.0 Mobile/15E148 Safari/605.1.15": {},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0":                                                           {},
		"curl/8.0": {},
		// HYPOTHESIS(webkit_macos_is_ios_late): macOS Safari, and an iPadOS
		// browser in desktop mode (the same User-Agent), read as iOS Safari.
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15":        {Kind: WebKit, Major: 26, Minor: 6},
		"Mozilla/5.0 (iPad; CPU OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1": {Kind: WebKit, Major: 18, Minor: 6},
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Safari/604.1":     {},
	} {
		if got := EngineFromUserAgent(ua); got != want {
			t.Errorf("%s: %v, want %v", ua, got, want)
		}
	}
	for e, want := range map[Engine]string{
		{Kind: Chromium, Major: 151}:                       "chromium/151",
		{Kind: WebKit, Major: 18, Minor: 3}:                "webkit/18.3",
		{Kind: WebKit, Major: 26, Minor: 6, WebView: true}: "webkit-webview/26.6",
	} {
		if got := e.String(); got != want {
			t.Errorf("%#v: %s, want %s", e, got, want)
		}
	}
}

func TestOrderUniversalFollowsTheLoaderInsertionOrder(t *testing.T) {
	for name, c := range map[string]struct {
		r    Request
		want []string
	}{
		"sign-in POST": {Request{Class: ClassFetch, Method: "POST", HTTP2: true, Calls: []string{"content-type"},
			Added: Added{Origin: true, Referer: true, Body: true}},
			strings.Fields("accept content-type sec-fetch-site origin sec-fetch-mode user-agent referer sec-fetch-dest content-length")},
		"account-message GET": {Request{Class: ClassFetch, Method: "GET", HTTP2: true, Added: Added{Origin: true}},
			strings.Fields("sec-fetch-dest user-agent accept sec-fetch-site origin sec-fetch-mode")},
	} {
		for _, e := range []Engine{safari187, {Kind: WebKit, Major: 26, Minor: 6}} {
			c.r.Engine = e
			got, err := OrderUniversal(c.r)
			if err != nil || len(got.Header) < len(c.want) || !slices.Equal(got.Header[:len(c.want)], c.want) {
				t.Errorf("%s on %s = %v (%v), want the dictionary %v", name, e, got.Header, err, c.want)
			}
		}
	}
}
