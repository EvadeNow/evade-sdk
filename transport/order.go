package transport

import (
	"fmt"
	"strings"

	"github.com/EvadeNow/evade-sdk/useragent"
	"github.com/EvadeNow/evade-sdk/wireorder"
)

type RequestClass string

const (
	ClassNavigation RequestClass = "navigation"
	ClassReload     RequestClass = "reload" // same-origin document reload carrying cookies; only captured rows order it
	ClassXHR        RequestClass = "xhr"
	ClassFetch      RequestClass = "fetch"
	ClassScript     RequestClass = "script"    // classic <script src> subresource
	ClassImage      RequestClass = "image"     // an <img> load: OrderUniversal frames it as a no-cors element load
	ClassForm       RequestClass = "form"      // form POST submission: Order fails (no captured row), OrderUniversal frames it
	ClassPreflight  RequestClass = "preflight" // the browser's CORS OPTIONS preflight
	ClassNoCORS     RequestClass = "no-cors"   // element subresource GET (image, stylesheet, media); a page's no-cors fetch is ClassFetch
)

// lawClass maps c to its wire-order law class; a reload and an unknown class have none.
func (c RequestClass) lawClass() (wireorder.Class, bool) {
	switch c {
	case ClassNavigation:
		return wireorder.ClassNavigation, true
	case ClassScript:
		return wireorder.ClassScript, true
	case ClassXHR:
		return wireorder.ClassXHR, true
	case ClassFetch:
		return wireorder.ClassFetch, true
	case ClassForm:
		return wireorder.ClassForm, true
	case ClassPreflight:
		return wireorder.ClassPreflight, true
	case ClassNoCORS, ClassImage:
		return wireorder.ClassNoCORS, true
	}
	return wireorder.ClassUnknown, false
}

// strictLaw reports whether strict wireorder.Order certifies c; it refuses form, preflight and no-cors, so Order
// keeps serving those from captured rows or failing.
func strictLaw(c wireorder.Class) bool {
	switch c {
	case wireorder.ClassNavigation, wireorder.ClassScript, wireorder.ClassXHR, wireorder.ClassFetch:
		return true
	}
	return false
}

type OrderRequest struct {
	UserAgent string
	Class     RequestClass
	Method    string
	HTTP2     bool
	// Page header-set calls in program order (setRequestHeader or fetch init); browser-owned names are refused.
	Calls []string
	// ShapePrefix is the protected-header prefix including its trailing '-', classifying Calls' Shape headers;
	// empty without a Shape block.
	ShapePrefix string
	// Pins are capture certificates (wireorder.ParsePins). Order passes them as given; OrderUniversal takes a
	// mixed-engine candidate set and passes only the resolved engine's.
	Pins       []*wireorder.Pin
	Added      wireorder.Added // conditional headers the browser adds
	Redirected bool            // navigation hop following a server redirect
	Inserted   bool            // script element created by page JS, not the HTML parser
}

func (r *OrderRequest) law(engine wireorder.Engine, class wireorder.Class, pins []*wireorder.Pin) wireorder.Request {
	return wireorder.Request{
		Engine: engine, Class: class, Method: r.Method, HTTP2: r.HTTP2,
		Calls: r.Calls, ShapePrefix: r.ShapePrefix, Pins: pins,
		Added: r.Added, Redirected: r.Redirected, Inserted: r.Inserted,
	}
}

// enginePins selects the candidates certifying engine's kind: a pin whose Engine is engine.Kind's label is kept, one
// labelled with another engine kind is dropped, and a nil pin or an empty or unknown label is an InputError.
func enginePins(engine wireorder.Engine, candidates []*wireorder.Pin) ([]*wireorder.Pin, error) {
	want := engine.Kind.String()
	var pins []*wireorder.Pin
	for i, p := range candidates {
		field := fmt.Sprintf("pins[%d]", i)
		switch {
		case p == nil:
			return nil, &wireorder.InputError{Field: field, Detail: "nil pin"}
		case p.Engine == want:
			pins = append(pins, p)
		case p.Engine != wireorder.Chromium.String() && p.Engine != wireorder.WebKit.String():
			return nil, &wireorder.InputError{Field: field + ".engine", Detail: fmt.Sprintf("pin %q names no engine kind: %q", p.ID, p.Engine)}
		}
	}
	return pins, nil
}

// NoOrderError reports that neither the wire-order law nor a captured row orders Family, or Class of it when set.
type NoOrderError struct {
	Family useragent.Family
	Class  RequestClass
}

func (e *NoOrderError) Error() string {
	if e.Class == "" {
		return fmt.Sprintf("transport: no wire-order law or captured header order for %s", e.Family)
	}
	return fmt.Sprintf("transport: no wire-order law or captured header order for %s %s requests", e.Family, e.Class)
}

// NoLawError reports a request OrderUniversal refuses because at most a captured row orders it (a reload, any
// Android WebView request): a row is no law and states no pseudo-header order. Family is empty for a UA
// useragent.Parse refuses (Chrome for iOS).
type NoLawError struct {
	Family useragent.Family
	Class  RequestClass
}

func (e *NoLawError) Error() string {
	if e.Family == "" {
		return fmt.Sprintf("transport: no wire-order law for %s requests", e.Class)
	}
	return fmt.Sprintf("transport: no wire-order law for %s %s requests", e.Family, e.Class)
}

// Order returns r's lowercase header wire order: the wire-order law where it certifies engine and class (its refusals final), else a captured row; Edge and Opera always fail.
func Order(r OrderRequest) ([]string, error) {
	agent, parseErr := useragent.Parse(r.UserAgent)
	if parseErr == nil && agent.Family == useragent.FamilyAndroidWebView {
		// Its Chrome/ token reads as Chromium, but WebView adds x-requested-with; only captured rows order it.
		return captured(agent.Family, r.Class, androidWebViewOrder(r.Class))
	}
	engine := wireorder.EngineFromUserAgent(r.UserAgent)
	if class, ok := r.Class.lawClass(); ok && strictLaw(class) && engine.Kind != wireorder.EngineUnknown && (parseErr == nil || engine.WebView) {
		wire, err := wireorder.Order(r.law(engine, class, r.Pins))
		if err != nil {
			return nil, err
		}
		return wire.Header, nil
	}
	if parseErr != nil {
		return nil, parseErr
	}
	switch agent.Family {
	case useragent.FamilyChrome:
		return captured(agent.Family, r.Class, chromeOrder(r.Class))
	case useragent.FamilySafariIOS:
		return captured(agent.Family, r.Class, safariIOSOrder(r.Class))
	}
	return nil, &NoOrderError{Family: agent.Family}
}

// OrderUniversal returns r's wire order from wireorder.OrderUniversal, header and pseudo-header order from one
// law result. It serves no captured row: a reload or any Android WebView request is a NoLawError, a family
// without a law (Edge, Opera, Firefox) a NoOrderError, and the law's refusals, an unknown class's included, are final.
func OrderUniversal(r OrderRequest) (wireorder.Wire, error) {
	agent, err := useragent.Parse(r.UserAgent)
	var engine wireorder.Engine
	switch {
	case err != nil:
		// Chrome for iOS, a WKWebView, is the one UA useragent.Parse refuses that the law orders; only the
		// raw-UA engine reader places it.
		if engine = wireorder.EngineFromUserAgent(r.UserAgent); !engine.WebView {
			return wireorder.Wire{}, err
		}
	case agent.Family == useragent.FamilyAndroidWebView:
		// Its Chrome/ token reads as Chromium, but WebView adds x-requested-with, which no law places.
		return wireorder.Wire{}, &NoLawError{Family: agent.Family, Class: r.Class}
	default:
		if engine, err = lawEngine(agent); err != nil {
			return wireorder.Wire{}, err
		}
	}
	if r.Class == ClassReload {
		return wireorder.Wire{}, &NoLawError{Family: agent.Family, Class: r.Class}
	}
	// An unknown class reaches the law as ClassUnknown, which refuses it.
	class, _ := r.Class.lawClass()
	pins, err := enginePins(engine, r.Pins)
	if err != nil {
		return wireorder.Wire{}, err
	}
	return wireorder.OrderUniversal(r.law(engine, class, pins))
}

// lawEngine is the engine the wire-order law orders a parsed agent's requests as: Chrome's Chromium major, Safari's
// (iOS or macOS) WebKit Version/ release. Every other family is a NoOrderError.
func lawEngine(a useragent.Agent) (wireorder.Engine, error) {
	switch a.Family {
	case useragent.FamilyChrome:
		if strings.Contains(a.Raw, "SamsungBrowser/") {
			// useragent.Parse folds Samsung Internet into Chrome; the law has no witness of it.
			return wireorder.Engine{}, &useragent.UnsupportedError{UserAgent: a.Raw, Reason: "Samsung Internet (SamsungBrowser/) has no wire-order law"}
		}
		return wireorder.Engine{Kind: wireorder.Chromium, Major: a.ChromiumMajor}, nil
	case useragent.FamilySafariIOS, useragent.FamilySafariMacOS:
		if !strings.Contains(a.Raw, "Version/") {
			// useragent.Parse stands the iOS version in for a missing Version/; the law reads only Safari's release.
			return wireorder.Engine{}, &NoOrderError{Family: a.Family}
		}
		return wireorder.Engine{Kind: wireorder.WebKit, Major: a.Major, Minor: a.Minor}, nil
	}
	return wireorder.Engine{}, &NoOrderError{Family: a.Family}
}

func captured(f useragent.Family, c RequestClass, row []string) ([]string, error) {
	if row == nil {
		return nil, &NoOrderError{Family: f, Class: c}
	}
	return row, nil
}

type ArrangeError struct {
	Extra, Missing []string
}

func (e *ArrangeError) Error() string {
	return fmt.Sprintf("transport: headers do not match the wire order: extra %q, missing %q", e.Extra, e.Missing)
}

// Arrange returns a copy of h in order, failing unless h names exactly its headers (stack-written ones as empty-valued entries).
func (h Headers) Arrange(order []string) (Headers, error) {
	at := make(map[string]int, len(order))
	for i, name := range order {
		at[name] = i
	}
	pos := make([]int, len(h))
	placed := make([]bool, len(order))
	var extra []string
	for i, header := range h {
		p, ok := at[strings.ToLower(header.Name)]
		if !ok {
			extra = append(extra, header.Name)
			continue
		}
		pos[i] = p
		placed[p] = true
	}
	var missing []string
	for i, name := range order {
		if !placed[i] {
			missing = append(missing, name)
		}
	}
	if extra != nil || missing != nil {
		return nil, &ArrangeError{Extra: extra, Missing: missing}
	}
	result := make(Headers, 0, len(h))
	for p := range order {
		for i, header := range h {
			if pos[i] == p {
				result = append(result, header)
			}
		}
	}
	return result, nil
}

// chromeOrder holds captured Chrome 152 Windows rows; each call returns a fresh slice callers may edit.
func chromeOrder(c RequestClass) []string {
	switch c {
	case ClassReload:
		// Post-challenge reload after Accept-CH, hence high-entropy hints inside the sec-ch-ua group.
		return []string{
			"cache-control", "sec-ch-device-memory", "sec-ch-ua", "sec-ch-ua-mobile",
			"sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-ua-model", "sec-ch-ua-full-version-list",
			"upgrade-insecure-requests", "user-agent", "accept",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "cookie", "priority",
		}
	case ClassImage:
		// The captures also end with priority; omitted pending a parity check.
		return []string{
			"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
			"referer", "accept-encoding", "accept-language", "cookie",
		}
	}
	return nil
}

// androidWebViewOrder is from a HAR, so its order is unverified against a wire-preserving capture.
func androidWebViewOrder(c RequestClass) []string {
	switch c {
	case ClassNavigation:
		return []string{
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent", "accept", "x-requested-with",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"accept-encoding", "accept-language", "cookie",
		}
	case ClassReload:
		// Uncaptured: the navigation row minus sec-fetch-user, plus referer where Chrome's reload has it.
		return []string{
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent", "accept", "x-requested-with",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "cookie",
		}
	case ClassXHR:
		return []string{
			"content-length", "sec-ch-ua-platform", "user-agent", "sec-ch-ua",
			"content-type", "sec-ch-ua-mobile", "accept", "origin", "x-requested-with",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "cookie",
		}
	case ClassScript:
		// No script load captured; the page's stylesheet and image share this order.
		return []string{
			"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"accept", "x-requested-with", "sec-fetch-site", "sec-fetch-mode",
			"sec-fetch-dest", "referer", "accept-encoding", "accept-language", "priority",
		}
	}
	return nil
}

func safariIOSOrder(c RequestClass) []string {
	if c == ClassReload {
		return []string{
			"accept", "sec-fetch-site", "sec-fetch-mode", "user-agent", "referer",
			"sec-fetch-dest", "cache-control", "accept-language", "priority",
			"accept-encoding", "cookie",
		}
	}
	return nil
}
