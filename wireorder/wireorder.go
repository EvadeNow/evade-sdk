// Package wireorder derives a browser engine's request-header wire order
// from the engine's own law (Blink's HTTPHeaderMap, CFNetwork's CF hash
// table), never from samples. An unwitnessed engine, class or version is an
// UnwitnessedError; a WebKit request whose insertion histories reach more
// than one order is an AmbiguousError unless a caller-supplied pin decides it.
package wireorder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

type EngineKind uint8

const (
	EngineUnknown EngineKind = iota
	// Chromium: Major is Chrome's major.
	Chromium
	// WebKit: Major.Minor is Safari's Version/, or the iOS version for a WebView.
	WebKit
)

func (k EngineKind) String() string {
	switch k {
	case Chromium:
		return "chromium"
	case WebKit:
		return "webkit"
	}
	return fmt.Sprintf("engine(%d)", uint8(k))
}

type Engine struct {
	Kind  EngineKind
	Major int
	Minor int
	// WebView is a third-party iOS browser on WKWebView; it orders headers unlike Safari of the same release.
	WebView bool
}

func (e Engine) String() string {
	switch {
	case e.Kind == WebKit && e.WebView:
		return fmt.Sprintf("%s-webview/%d.%d", e.Kind, e.Major, e.Minor)
	case e.Kind == WebKit:
		return fmt.Sprintf("%s/%d.%d", e.Kind, e.Major, e.Minor)
	}
	return fmt.Sprintf("%s/%d", e.Kind, e.Major)
}

type Class uint8

const (
	ClassUnknown Class = iota
	ClassXHR
	ClassFetch
	// ClassNavigation is one top-level document GET hop (see Request.Redirected).
	ClassNavigation
	// Order refuses ClassForm, ClassPreflight and ClassNoCORS: no witnessed law.
	ClassForm
	ClassPreflight
	ClassNoCORS
	// ClassScript is a classic <script src> GET; the browser sets every header.
	ClassScript
)

func (c Class) String() string {
	switch c {
	case ClassXHR:
		return "xhr"
	case ClassFetch:
		return "fetch"
	case ClassNavigation:
		return "navigation"
	case ClassForm:
		return "form"
	case ClassPreflight:
		return "preflight"
	case ClassNoCORS:
		return "no-cors"
	case ClassScript:
		return "script"
	}
	return fmt.Sprintf("class(%d)", uint8(c))
}

type Request struct {
	Engine Engine
	Class  Class
	// Method: GET and HEAD carry no body; any other method carries Origin.
	Method string
	HTTP2  bool
	// Calls are the page's header-set calls in program order, Shape headers at their install point; never browser-owned headers.
	Calls []string
	// ShapePrefix is the protected-header prefix including its trailing '-'; empty when there is no Shape block.
	ShapePrefix string
	Added       Added
	// Pins (from ParsePins) decide what the engine law leaves open; Order only reads them.
	Pins       []*Pin
	Redirected bool
	// Inserted marks a script element page JavaScript inserted, not one the HTML parser requested.
	Inserted bool
}

// Added are the browser's conditional headers; user-agent, sec-fetch-*, accept-encoding and accept-language are always added.
type Added struct {
	// ClientHints are the sec-ch-ua* names Blink attaches with a value; must be empty for WebKit.
	ClientHints []string
	Origin      bool
	Referer     bool
	Cookie      bool
	// Body adds content-length.
	Body          bool
	Priority      bool
	StorageAccess bool
	FetchUser     bool
}

func (a *Added) present(name string) bool {
	switch name {
	case "origin":
		return a.Origin
	case "referer":
		return a.Referer
	case "cookie":
		return a.Cookie
	case "content-length":
		return a.Body
	case "priority":
		return a.Priority
	case "sec-fetch-storage-access":
		return a.StorageAccess
	case "sec-fetch-user":
		return a.FetchUser
	case "user-agent", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
		"accept-encoding", "accept-language":
		return true
	}
	return false
}

// Wire is fhttp's HeaderOrderKey (Header) and PHeaderOrderKey (Pseudo); names are lower-case.
type Wire struct {
	Header []string
	Pseudo []string
}

type UnwitnessedError struct {
	Engine Engine
	Class  Class
	Reason string
}

func (e *UnwitnessedError) Error() string {
	return fmt.Sprintf("wireorder: %s %s unwitnessed: %s", e.Engine, e.Class, e.Reason)
}

// AmbiguousError: the law admits Outcomes orders; Names are the headers whose position differs.
type AmbiguousError struct {
	Engine   Engine
	Class    Class
	Names    []string
	Outcomes int
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("wireorder: %s %s ambiguous: %d orders differ on %s",
		e.Engine, e.Class, e.Outcomes, strings.Join(e.Names, ","))
}

// InputError is a request no browser could issue as described.
type InputError struct {
	Field  string
	Detail string
}

func (e *InputError) Error() string {
	return "wireorder: input " + e.Field + ": " + e.Detail
}

type lawFile struct {
	Forbidden []string
	Chromium  chromiumLaw
	WebKit    webkitLaw
}

type chromiumLaw struct {
	Witnessed            [2]int
	BlinkSetOrder        []string
	HTTP1Prefix          []string
	NetworkAfter         []string
	NetworkTail          []string
	Pseudo               []string
	HintCounterwitnesses []HintCounterwitness
	Navigation           chromiumNavigation
}

// HintCounterwitness is a capture whose Blink map the set order does not reproduce, blamed on hint Name.
type HintCounterwitness struct {
	Name   string `json:"name"`
	HAR    string `json:"har"`
	Entry  int    `json:"entry"`
	Reason string `json:"reason"`
}

type chromiumNavigation struct {
	ClientHints []string
	BrowserSet  []string
}

type webkitLaw struct {
	CommonHeaders      []string
	LoaderAdded        []string
	CFNetworkTail      []string
	Unresolved         []string
	Pseudo             []string
	HTTP1Prefix        []string
	HTTP1Suffix        []string
	Counterwitness     []Counterwitness
	UnwitnessedClasses map[string]string
	InsertedScript     webkitInsertedScript
	Generations        []webkitGeneration
}

// webkitGeneration: Inside are CFNetwork-tail names kept in the dictionary on these builds; Tail the rest, in wire order.
type webkitGeneration struct {
	Name           string
	Builds         []webkitBuilds
	Witnesses      []GenerationWitness
	Inside         []string
	Tail           []string
	Priority       bool
	InsertionLaw   bool
	ScriptLaw      bool
	PageSetTail    bool
	Counterwitness []Counterwitness
}

type webkitBuilds struct {
	WebView bool
	From    [2]int
	To      [2]int
}

type GenerationWitness struct {
	HAR       string `json:"har"`
	UserAgent string `json:"user_agent"`
}

// HYPOTHESIS(webkit_generation_contiguous): unwitnessed builds inside a generation's range behave like its witnessed ones.
func (w *webkitLaw) generation(e Engine) *webkitGeneration {
	v := [2]int{e.Major, e.Minor}
	for i := range w.Generations {
		for _, b := range w.Generations[i].Builds {
			if b.WebView == e.WebView && !versionBefore(v, b.From) && versionBefore(v, b.To) {
				return &w.Generations[i]
			}
		}
	}
	return nil
}

func (w *webkitLaw) uncovered() string {
	var parts []string
	for _, g := range w.Generations {
		var ranges []string
		for _, b := range g.Builds {
			kind := "safari"
			if b.WebView {
				kind = "webview"
			}
			ranges = append(ranges, fmt.Sprintf("%s [%d.%d, %d.%d)", kind, b.From[0], b.From[1], b.To[0], b.To[1]))
		}
		parts = append(parts, g.Name+" "+strings.Join(ranges, ", "))
	}
	return "no witnessed WebKit generation holds this build; witnessed: " + strings.Join(parts, "; ")
}

func versionBefore(a, b [2]int) bool { return a[0] < b[0] || a[0] == b[0] && a[1] < b[1] }

func (g *webkitGeneration) dictionary(r *Request, names []string) []string {
	out := slices.Clone(names)
	for _, name := range g.Inside {
		if r.Added.present(name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// webkitInsertedScript.Insertion reproduces every witness but is not WebKit's source order: the CF table decides only collisions.
type webkitInsertedScript struct {
	Insertion      []string
	Counterwitness []Counterwitness
}

// Counterwitness is a capture the law does not reproduce; a request with the same dictionary is refused.
type Counterwitness struct {
	HAR        string   `json:"har"`
	Entry      int      `json:"entry"`
	Dictionary []string `json:"dictionary"`
	Reason     string   `json:"reason"`
}

// Pin is a capture certificate: Install orders the Shape block ("shape:<suffix>" tokens), Cases select among the law's outcomes.
type Pin struct {
	ID        string      `json:"id"`
	Engine    string      `json:"engine"`
	Install   [][2]string `json:"install,omitempty"`
	Witnesses []Witness   `json:"witnesses,omitempty"`
	Cases     []PinCase   `json:"cases,omitempty"`
}

// PinCase applies only on exactly Dictionary's set and Generations; Wire's precedences select one outcome, or Captured makes Dictionary the order.
type PinCase struct {
	Dictionary  []string    `json:"dictionary"`
	Wire        [][2]string `json:"wire,omitempty"`
	Captured    bool        `json:"captured,omitempty"`
	Generations []string    `json:"generations"`
	Witnesses   []Witness   `json:"witnesses"`
}

type Witness struct {
	HAR   string `json:"har"`
	Entry int    `json:"entry"`
}

func (p *Pin) matchCase(g *webkitGeneration, names []string) *PinCase {
	for i := range p.Cases {
		c := &p.Cases[i]
		if !c.Captured && slices.Contains(c.Generations, g.Name) && sameSet(c.Dictionary, names) {
			return c
		}
	}
	return nil
}

func capturedOrder(g *webkitGeneration, w *webkitLaw, r *Request, calls, names []string, pins []*Pin) (Wire, bool) {
	if !r.HTTP2 {
		return Wire{}, false
	}
	for _, p := range pins {
		for i := range p.Cases {
			c := &p.Cases[i]
			if !c.Captured || !slices.Contains(c.Generations, g.Name) || !sameSet(c.Dictionary, names) {
				continue
			}
			return Wire{Header: append(slices.Clone(c.Dictionary), g.tail(r, calls)...), Pseudo: slices.Clone(w.Pseudo)}, true
		}
	}
	return Wire{}, false
}

// ParsePins strictly decodes a JSON pin array and checks each pin against the law; every error is an *InputError naming the field.
func ParsePins(data []byte) ([]Pin, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var pins []Pin
	if err := dec.Decode(&pins); err != nil {
		return nil, &InputError{Field: "pins", Detail: err.Error()}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, &InputError{Field: "pins", Detail: "data after the pin array"}
	}
	ids := map[string]bool{}
	for i := range pins {
		p := &pins[i]
		if err := law.WebKit.checkPin(p, fmt.Sprintf("pins[%d]", i)); err != nil {
			return nil, err
		}
		if ids[p.ID] {
			return nil, &InputError{Field: fmt.Sprintf("pins[%d].id", i), Detail: fmt.Sprintf("%q repeats an earlier pin's id", p.ID)}
		}
		ids[p.ID] = true
	}
	return pins, nil
}

func (w *webkitLaw) checkPin(p *Pin, field string) error {
	bad := func(sub, format string, args ...any) error {
		return &InputError{Field: field + sub, Detail: fmt.Sprintf(format, args...)}
	}
	if p.ID == "" {
		return bad(".id", "empty")
	}
	if p.Engine != WebKit.String() {
		return bad(".engine", "%q: only the %s law leaves orders open for a pin to decide", p.Engine, WebKit)
	}
	for i, e := range p.Install {
		for _, token := range e {
			if _, ok := shapeRole(token, "shape:"); !ok {
				return bad(fmt.Sprintf(".install[%d]", i), "%q is not a Shape token shape:<a|b|c|d|f|z><digits>", token)
			}
		}
		if e[0] == e[1] {
			return bad(fmt.Sprintf(".install[%d]", i), "%s precedes itself", e[0])
		}
	}
	for i := range p.Cases {
		c := &p.Cases[i]
		sub := fmt.Sprintf(".cases[%d]", i)
		if len(c.Witnesses) == 0 {
			return bad(sub+".witnesses", "a case states the captures it is derived from")
		}
		if len(c.Generations) == 0 {
			return bad(sub+".generations", "a case states the WebKit generations whose builds captured it")
		}
		for _, name := range c.Generations {
			j := slices.IndexFunc(w.Generations, func(g webkitGeneration) bool { return g.Name == name })
			if j < 0 {
				return bad(sub+".generations", "the law declares no WebKit generation %q", name)
			}
			if !c.Captured && !w.Generations[j].InsertionLaw {
				return bad(sub+".generations", "generation %s has no insertion law to select among; a case on it is captured", name)
			}
		}
		switch {
		case c.Captured && len(c.Wire) != 0:
			return bad(sub+".wire", "a captured case is its own order; it states no precedences")
		case !c.Captured && len(c.Wire) == 0:
			return bad(sub+".wire", "a law case states the precedences that select its order")
		}
		for j, e := range c.Wire {
			if !precedes(c.Dictionary, e[0], e[1]) {
				return bad(fmt.Sprintf("%s.wire[%d]", sub, j), "%v names a header outside the dictionary or contradicts its order", e)
			}
		}
	}
	return nil
}

func Order(r Request) (Wire, error) {
	return law.order(&r)
}

// Outcomes lists the header orders the WebKit insertion law admits for r before pin cases select (no install pin required), for deriving pins.
func Outcomes(r Request) ([][]string, error) {
	return law.outcomes(&r)
}

// WebKitLaw is the WebKit law's facts for one build, for splitting captures into dictionary and tail; slices are copies.
type WebKitLaw struct {
	Generation WebKitGeneration
	// CFNetworkTail is every name CFNetwork may append, in tail order; Generation splits it into Inside and Tail.
	CFNetworkTail []string
	// Unresolved names have no stated placement: CFNetwork-added ones land after the tail, page-set ones are refused.
	Unresolved               []string
	HTTP1Prefix, HTTP1Suffix []string
	Pseudo                   []string
}

// WebKitGeneration is a run of WebKit builds sharing one header-list behaviour; Name is what PinCase.Generations states.
type WebKitGeneration struct {
	Name string
	// Inside are CFNetwork-tail names kept in the dictionary on these builds; Tail the rest, in wire order.
	Inside, Tail []string
	// Priority: the builds add an HTTP/2 priority header at all.
	Priority bool
	// InsertionLaw: the CF insertion law orders fetch/XHR; otherwise a captured pin case does, else Order uses the
	// late generation's (HYPOTHESIS(webkit_early_falls_back_to_late)).
	InsertionLaw bool
	// ScriptLaw: the inserted-script law orders JS-inserted script GETs; otherwise Order uses the late generation's.
	ScriptLaw bool
}

func WebKitFacts(e Engine) (WebKitLaw, error) {
	w := &law.WebKit
	if e.Kind != WebKit {
		return WebKitLaw{}, &UnwitnessedError{Engine: e, Reason: "not a WebKit build"}
	}
	g := w.generation(e)
	if g == nil {
		return WebKitLaw{}, &UnwitnessedError{Engine: e, Reason: w.uncovered()}
	}
	return WebKitLaw{
		Generation: WebKitGeneration{Name: g.Name, Inside: slices.Clone(g.Inside), Tail: slices.Clone(g.Tail),
			Priority: g.Priority, InsertionLaw: g.InsertionLaw, ScriptLaw: g.ScriptLaw},
		CFNetworkTail: slices.Clone(w.CFNetworkTail),
		Unresolved:    slices.Clone(w.Unresolved),
		HTTP1Prefix:   slices.Clone(w.HTTP1Prefix),
		HTTP1Suffix:   slices.Clone(w.HTTP1Suffix),
		Pseudo:        slices.Clone(w.Pseudo),
	}, nil
}

func (law *lawFile) order(r *Request) (Wire, error) {
	unwitnessed := func(format string, args ...any) error {
		return &UnwitnessedError{Engine: r.Engine, Class: r.Class, Reason: fmt.Sprintf(format, args...)}
	}
	switch r.Class {
	case ClassXHR, ClassFetch:
	case ClassNavigation, ClassScript:
		return law.browserOrder(r, unwitnessed)
	default:
		return Wire{}, unwitnessed("only navigation, script, fetch and XHR have a witnessed law")
	}
	calls, shape, err := law.pageRequest(r)
	if err != nil {
		return Wire{}, err
	}
	switch r.Engine.Kind {
	case Chromium:
		if len(r.Pins) != 0 {
			return Wire{}, &InputError{Field: "pins", Detail: "the Chromium law is deterministic; it takes no pins"}
		}
		if err := law.chromiumWitnessed(r, unwitnessed); err != nil {
			return Wire{}, err
		}
		return Wire{Header: chromiumOrder(&law.Chromium, r, calls), Pseudo: slices.Clone(law.Chromium.Pseudo)}, nil
	case WebKit:
		return law.webkitOrder(r, calls, shape)
	}
	return Wire{}, unwitnessed("no law for this engine")
}

func (law *lawFile) outcomes(r *Request) ([][]string, error) {
	unwitnessed := func(format string, args ...any) error {
		return &UnwitnessedError{Engine: r.Engine, Class: r.Class, Reason: fmt.Sprintf(format, args...)}
	}
	if r.Engine.Kind != WebKit || r.Class != ClassXHR && r.Class != ClassFetch {
		return nil, unwitnessed("only WebKit fetch and XHR are ordered by insertion history")
	}
	calls, shape, err := law.pageRequest(r)
	if err != nil {
		return nil, err
	}
	w := &law.WebKit
	g, err := w.build(r, unwitnessed)
	if err != nil {
		return nil, err
	}
	if err := g.priority(r); err != nil {
		return nil, err
	}
	if err := w.insertion(g, calls, unwitnessed); err != nil {
		return nil, err
	}
	outcomes, err := w.histories(g, newWebkitDictionary(w, r, calls, shape), shape, r.Pins, unwitnessed)
	if err != nil {
		return nil, err
	}
	tail := g.tail(r, calls)
	for i, o := range outcomes {
		outcomes[i] = w.frame(r, append(o, tail...))
	}
	return outcomes, nil
}

func (law *lawFile) pageRequest(r *Request) ([]string, map[string]string, error) {
	if r.Redirected || r.Added.FetchUser {
		return nil, nil, &InputError{Field: "redirected", Detail: "only a navigation hop follows a redirect or carries sec-fetch-user"}
	}
	calls, shape, err := law.validate(r)
	if err != nil {
		return nil, nil, err
	}
	for i, p := range r.Pins {
		field := fmt.Sprintf("pins[%d]", i)
		if p == nil {
			return nil, nil, &InputError{Field: field, Detail: "nil pin"}
		}
		if p.Engine != r.Engine.Kind.String() {
			return nil, nil, &InputError{Field: field, Detail: fmt.Sprintf("pin %q is a %s certificate", p.ID, p.Engine)}
		}
	}
	return calls, shape, nil
}

func (law *lawFile) chromiumWitnessed(r *Request, unwitnessed func(string, ...any) error) error {
	c := &law.Chromium
	if r.Engine.Major < c.Witnessed[0] || r.Engine.Major > c.Witnessed[1] {
		return unwitnessed("Chromium majors %d-%d are witnessed", c.Witnessed[0], c.Witnessed[1])
	}
	for _, hint := range r.Added.ClientHints {
		if !slices.Contains(c.BlinkSetOrder, hint) || hint == "user-agent" {
			return unwitnessed("client hint %q is outside the witnessed Blink set order", hint)
		}
		for _, w := range c.HintCounterwitnesses {
			if w.Name == hint {
				return unwitnessed("client hint %q: counterwitness %s#%d: %s", hint, w.HAR, w.Entry, w.Reason)
			}
		}
	}
	if len(c.Pseudo) == 0 {
		return unwitnessed("no witnessed HTTP/2 pseudo-header order")
	}
	return nil
}

// validate returns the lower-cased calls and a map of Shape block names to their pin tokens.
func (law *lawFile) validate(r *Request) ([]string, map[string]string, error) {
	method := strings.ToUpper(r.Method)
	if method == "" {
		return nil, nil, &InputError{Field: "method", Detail: "empty"}
	}
	bodyless := method == "GET" || method == "HEAD"
	if bodyless && r.Added.Body {
		return nil, nil, &InputError{Field: "added.body", Detail: method + " carries no body in fetch or XHR"}
	}
	if !bodyless && !r.Added.Origin {
		return nil, nil, &InputError{Field: "added.origin", Detail: method + " fetch/XHR always carries Origin"}
	}
	prefix := strings.ToLower(r.ShapePrefix)
	calls := make([]string, 0, len(r.Calls))
	shape := map[string]string{}
	for i, raw := range r.Calls {
		name := strings.ToLower(raw)
		if name == "" || strings.ContainsFunc(name, func(c rune) bool { return c <= ' ' || c > '~' || c == ':' }) {
			return nil, nil, &InputError{Field: fmt.Sprintf("calls[%d]", i), Detail: fmt.Sprintf("%q is not a header name", raw)}
		}
		if slices.Contains(calls, name) {
			return nil, nil, &InputError{Field: fmt.Sprintf("calls[%d]", i), Detail: name + " set twice"}
		}
		if law.forbidden(name) || name == "user-agent" || strings.HasPrefix(name, "sec-") {
			return nil, nil, &InputError{Field: fmt.Sprintf("calls[%d]", i), Detail: name + " is browser-owned; the page cannot set it"}
		}
		if role, ok := shapeRole(name, prefix); ok {
			shape[name] = role
		}
		calls = append(calls, name)
	}
	if prefix != "" && len(shape) == 0 {
		return nil, nil, &InputError{Field: "shape_prefix", Detail: "no call carries the prefix " + prefix}
	}
	return calls, shape, nil
}

// PageSettable reports whether a page's header-set call on name reaches the wire: not Fetch-forbidden, proxy-, sec- or user-agent.
func PageSettable(name string) (bool, error) {
	name = strings.ToLower(name)
	return !law.forbidden(name) && name != "user-agent" && !strings.HasPrefix(name, "sec-"), nil
}

func (law *lawFile) forbidden(name string) bool {
	if strings.HasPrefix(name, "proxy-") {
		return true
	}
	return slices.Contains(law.Forbidden, name)
}

func (law *lawFile) webkitOrder(r *Request, calls []string, shape map[string]string) (Wire, error) {
	w := &law.WebKit
	unwitnessed := func(format string, args ...any) error {
		return &UnwitnessedError{Engine: r.Engine, Class: r.Class, Reason: fmt.Sprintf(format, args...)}
	}
	g, err := w.build(r, unwitnessed)
	if err != nil {
		return Wire{}, err
	}
	d := newWebkitDictionary(w, r, calls, shape)
	// A build without priority sends none, so a priority request is no capture of its generation.
	if !r.Added.Priority || g.Priority {
		if wire, ok := capturedOrder(g, w, r, calls, g.dictionary(r, d.names), r.Pins); ok {
			return wire, nil
		}
	}
	if !g.InsertionLaw {
		g = w.late()
		if wire, ok := capturedOrder(g, w, r, calls, g.dictionary(r, d.names), r.Pins); ok {
			return wire, nil
		}
	}
	if err := g.priority(r); err != nil {
		return Wire{}, err
	}
	if err := w.insertion(g, calls, unwitnessed); err != nil {
		return Wire{}, err
	}
	if len(shape) != 0 && !slices.ContainsFunc(r.Pins, pinOrdersShape) {
		return Wire{}, unwitnessed("the Shape install order on WebKit is witnessed only through a page pin; this request names none")
	}
	outcomes, err := w.histories(g, d, shape, r.Pins, unwitnessed)
	if err != nil {
		return Wire{}, err
	}
	var wire [][2]string
	for _, p := range r.Pins {
		if c := p.matchCase(g, d.names); c != nil {
			wire = append(wire, c.Wire...)
		}
	}
	var kept [][]string
	for _, o := range outcomes {
		if !slices.ContainsFunc(wire, func(e [2]string) bool { return !precedes(o, e[0], e[1]) }) {
			kept = append(kept, o)
		}
	}
	switch len(kept) {
	case 0:
		return Wire{}, unwitnessed("the pins exclude every order the law admits")
	case 1:
	default:
		return Wire{}, &AmbiguousError{Engine: r.Engine, Class: r.Class, Names: ambiguousNames(kept), Outcomes: len(kept)}
	}
	header := w.frame(r, append(kept[0], g.tail(r, calls)...))
	if !r.HTTP2 {
		return Wire{Header: header}, nil
	}
	return Wire{Header: header, Pseudo: slices.Clone(w.Pseudo)}, nil
}

func (w *webkitLaw) build(r *Request, unwitnessed func(string, ...any) error) (*webkitGeneration, error) {
	g := w.generation(r.Engine)
	if g == nil {
		return nil, unwitnessed("%s", w.uncovered())
	}
	switch {
	case !r.HTTP2 && len(w.HTTP1Prefix) == 0:
		return nil, unwitnessed("no witnessed HTTP/1.1 framing")
	case r.HTTP2 && len(w.Pseudo) == 0:
		return nil, unwitnessed("no witnessed HTTP/2 pseudo-header order")
	}
	if len(r.Added.ClientHints) != 0 {
		return nil, unwitnessed("WebKit sends no client hints; an empty sec-ch-ua* is absent, not ordered")
	}
	if r.Added.StorageAccess {
		return nil, unwitnessed("sec-fetch-storage-access is a Chromium header")
	}
	return g, nil
}

func (g *webkitGeneration) priority(r *Request) error {
	if r.Added.Priority && !g.Priority {
		return &InputError{Field: "added.priority", Detail: fmt.Sprintf("WebKit generation %s adds no priority header", g.Name)}
	}
	return nil
}

// late orders the fetch, XHR and inserted script of a generation without an insertion or script law
// (early, early-webview) that no captured pin case of its own generation holds, pins scoped to late applying.
// HYPOTHESIS(webkit_early_falls_back_to_late): those builds' captures (ios18-safari-14#27, ios18-crios-16#21,
// probe-crios-13#25, probe-crios-14#18) are not this order; a user decision lets live Target results judge it.
// Falsified by a live BLOCK/refusal on an iOS 18.0-18.1 Safari or iOS 18.0-18.1/18.4-18.7 Chrome for iOS device.
func (w *webkitLaw) late() *webkitGeneration {
	return &w.Generations[slices.IndexFunc(w.Generations, func(g webkitGeneration) bool { return g.Name == "late" })]
}

func (w *webkitLaw) insertion(g *webkitGeneration, calls []string, unwitnessed func(string, ...any) error) error {
	if !g.InsertionLaw {
		return unwitnessed("WebKit generation %s: the CF insertion law reproduces none of its fetch/XHR captures; only a pin's captured case orders one, and none is witnessed on this dictionary", g.Name)
	}
	for _, name := range calls {
		if slices.Contains(w.Unresolved, name) || slices.Contains(w.CFNetworkTail, name) && !g.PageSetTail {
			return unwitnessed("whether CFNetwork keeps a page-set %s in its dictionary or its tail is not witnessed on WebKit generation %s", name, g.Name)
		}
	}
	return nil
}

// histories mutates d: it adds the pins' install precedences before enumerating.
func (w *webkitLaw) histories(g *webkitGeneration, d *webkitDictionary, shape map[string]string, pins []*Pin, unwitnessed func(string, ...any) error) ([][]string, error) {
	for _, cw := range slices.Concat(w.Counterwitness, g.Counterwitness) {
		if sameSet(cw.Dictionary, d.names) {
			return nil, unwitnessed("the law does not reproduce %s#%d with this dictionary: %s", cw.HAR, cw.Entry, cw.Reason)
		}
	}
	resolve := func(token string) string {
		if !strings.HasPrefix(token, "shape:") {
			return token
		}
		for name, role := range shape {
			if role == token {
				return name
			}
		}
		return ""
	}
	for _, p := range pins {
		for _, e := range p.Install {
			d.before(resolve(e[0]), resolve(e[1]))
		}
	}
	outcomes, err := cfOutcomes(d.names, d.pred)
	if err != nil {
		return nil, unwitnessed("%v", err)
	}
	return outcomes, nil
}

// tail skips page-set names: those sit in the dictionary where the capture has them.
func (g *webkitGeneration) tail(r *Request, calls []string) []string {
	var out []string
	for _, name := range g.Tail {
		if r.Added.present(name) && !slices.Contains(calls, name) {
			out = append(out, name)
		}
	}
	return out
}

func (w *webkitLaw) frame(r *Request, header []string) []string {
	if r.HTTP2 {
		return header
	}
	return slices.Concat(w.HTTP1Prefix, header, w.HTTP1Suffix)
}

func pinOrdersShape(p *Pin) bool {
	for _, e := range p.Install {
		if strings.HasPrefix(e[0], "shape:") || strings.HasPrefix(e[1], "shape:") {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}
