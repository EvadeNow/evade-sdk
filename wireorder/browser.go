package wireorder

import (
	"fmt"
	"slices"
	"strings"
)

// browserOrder: a Chromium script is a Blink subresource ordered like a call-less fetch; a navigation is the browser process's list.
func (law *lawFile) browserOrder(r *Request, unwitnessed func(string, ...any) error) (Wire, error) {
	switch {
	case r.Engine.Kind == WebKit && r.Class == ClassScript && r.Inserted:
		return law.webkitInsertedScriptOrder(r, unwitnessed)
	case r.Engine.Kind == WebKit:
		reason, ok := law.WebKit.UnwitnessedClasses[r.Class.String()]
		if !ok {
			reason = "no witnessed law"
		}
		return Wire{}, unwitnessed("%s", reason)
	case r.Engine.Kind != Chromium:
		return Wire{}, unwitnessed("no law for this engine")
	case strings.ToUpper(r.Method) != "GET":
		return Wire{}, unwitnessed("only GET is witnessed (a POST navigation is a form)")
	case len(r.Calls) != 0 || r.ShapePrefix != "" || len(r.Pins) != 0:
		return Wire{}, &InputError{Field: "calls", Detail: "the browser sets every header of a " + r.Class.String() + "; the page sets none"}
	case r.Added.Body || r.Added.Origin:
		return Wire{}, &InputError{Field: "added", Detail: "a GET " + r.Class.String() + " carries no body and no Origin"}
	case r.Class == ClassScript && (r.Redirected || r.Added.FetchUser):
		return Wire{}, &InputError{Field: "redirected", Detail: "only a navigation hop follows a redirect or carries sec-fetch-user"}
	}
	if err := law.chromiumWitnessed(r, unwitnessed); err != nil {
		return Wire{}, err
	}
	c := &law.Chromium
	if r.Class == ClassScript {
		return Wire{Header: chromiumOrder(c, r, nil), Pseudo: slices.Clone(c.Pseudo)}, nil
	}
	if r.Added.StorageAccess {
		return Wire{}, unwitnessed("no witnessed top-level navigation carries sec-fetch-storage-access")
	}
	hints, err := c.navigationHints(r, unwitnessed)
	if err != nil {
		return Wire{}, err
	}
	out := make([]string, 0, 20)
	if !r.HTTP2 {
		out = append(out, c.HTTP1Prefix...)
	}
	if !r.Redirected {
		out = append(out, hints...)
	}
	out = append(out, c.Navigation.BrowserSet...)
	for _, name := range c.NetworkAfter {
		if name == "referer" && r.Redirected {
			out = append(out, hints...)
		}
		if r.Added.present(name) {
			out = append(out, name)
		}
	}
	for _, name := range c.NetworkTail {
		if r.Added.present(name) {
			out = append(out, name)
		}
	}
	if r.HTTP2 && r.Added.Priority {
		out = append(out, "priority")
	}
	return Wire{Header: out, Pseudo: slices.Clone(c.Pseudo)}, nil
}

func (law *lawFile) webkitInsertedScriptOrder(r *Request, unwitnessed func(string, ...any) error) (Wire, error) {
	w := &law.WebKit
	g := w.generation(r.Engine)
	if g != nil && !g.ScriptLaw {
		g = w.late() // HYPOTHESIS(webkit_early_falls_back_to_late), at webkitLaw.late
	}
	switch {
	case g == nil:
		return Wire{}, unwitnessed("%s", w.uncovered())
	case strings.ToUpper(r.Method) != "GET":
		return Wire{}, &InputError{Field: "method", Detail: "a script element GETs its src"}
	case !r.HTTP2:
		return Wire{}, unwitnessed("only HTTP/2 is witnessed")
	case len(r.Calls) != 0 || r.ShapePrefix != "" || len(r.Pins) != 0:
		return Wire{}, &InputError{Field: "calls", Detail: "the browser sets every header of a script GET; the page sets none"}
	case r.Added.Body || r.Added.Origin || r.Added.FetchUser || r.Redirected:
		return Wire{}, &InputError{Field: "added", Detail: "a no-cors script GET carries no body, Origin or sec-fetch-user and follows no navigation redirect"}
	case len(r.Added.ClientHints) != 0 || r.Added.StorageAccess:
		return Wire{}, &InputError{Field: "added", Detail: "WebKit sends no client hints and no sec-fetch-storage-access"}
	}
	order := make([]string, 0, len(w.InsertedScript.Insertion))
	for _, name := range w.InsertedScript.Insertion {
		if name == "accept" || r.Added.present(name) {
			order = append(order, name)
		}
	}
	header, err := cfInsert(order)
	if err != nil {
		return Wire{}, err
	}
	for _, name := range g.Tail {
		if r.Added.present(name) {
			header = append(header, name)
		}
	}
	return Wire{Header: header, Pseudo: slices.Clone(w.Pseudo)}, nil
}

// navigationHints is r's client hints in the browser process's order; an origin's Accept-CH hints are unwitnessed.
func (c *chromiumLaw) navigationHints(r *Request, unwitnessed func(string, ...any) error) ([]string, error) {
	var hints []string
	for _, name := range c.Navigation.ClientHints {
		if slices.Contains(r.Added.ClientHints, name) {
			hints = append(hints, name)
		}
	}
	if len(hints) != len(r.Added.ClientHints) {
		return nil, unwitnessed("navigation client hints %v: only %v are witnessed (an origin's Accept-CH hints are not)", r.Added.ClientHints, c.Navigation.ClientHints)
	}
	return hints, nil
}

// universalInputs refuses OrderUniversal's own inputs on a class that never carries them.
func universalInputs(r *Request) error {
	switch {
	case r.Added.UpgradeInsecureRequests && r.Class != ClassNavigation && r.Class != ClassForm:
		return &InputError{Field: "added.upgrade_insecure_requests", Detail: "only a navigation or form carries upgrade-insecure-requests"}
	case r.Added.RequestHeaders && r.Class != ClassPreflight:
		return &InputError{Field: "added.request_headers", Detail: "only a preflight carries access-control-request-headers"}
	}
	return nil
}

// universalBrowserOrder frames OrderUniversal's browser-owned requests: Chromium form, preflight and no-cors
// element loads; WebKit form, preflight, navigation, script and no-cors element loads.
func (law *lawFile) universalBrowserOrder(r *Request) (Wire, error) {
	unwitnessed := func(format string, args ...any) error {
		return &UnwitnessedError{Engine: r.Engine, Class: r.Class, Reason: fmt.Sprintf(format, args...)}
	}
	if err := browserRequest(r); err != nil {
		return Wire{}, err
	}
	switch r.Engine.Kind {
	case Chromium:
		return law.universalChromiumOrder(r, unwitnessed)
	case WebKit:
		return law.universalWebkitBrowserOrder(r, unwitnessed)
	}
	return Wire{}, unwitnessed("no law for this engine")
}

// browserRequest refuses a browser-owned request no browser issues as described.
func browserRequest(r *Request) error {
	bad := func(field, format string, args ...any) error {
		return &InputError{Field: field, Detail: fmt.Sprintf(format, args...)}
	}
	method := strings.ToUpper(r.Method)
	if len(r.Calls) != 0 || r.ShapePrefix != "" || len(r.Pins) != 0 {
		return bad("calls", "the browser sets every header of a %s; the page sets none", r.Class)
	}
	switch r.Class {
	case ClassForm:
		switch {
		case method != "POST":
			return bad("method", "%q: a form submission POSTs (a GET form submission is a navigation)", r.Method)
		case !r.Added.Origin || !r.Added.Body:
			return bad("added", "a form POST carries Origin and a body")
		}
	case ClassPreflight:
		switch {
		case method != "OPTIONS":
			return bad("method", "%q: a preflight is OPTIONS", r.Method)
		case !r.Added.Origin:
			return bad("added.origin", "a preflight always carries Origin")
		case r.Added.Body || r.Added.Cookie || len(r.Added.ClientHints) != 0:
			return bad("added", "a preflight carries no body, cookie or client hints")
		}
	default:
		switch {
		case method != "GET":
			return bad("method", "%q: a %s GETs (a POST navigation is a form; a page's no-cors fetch is ClassFetch)", r.Method, r.Class)
		case r.Added.Body || r.Added.Origin:
			return bad("added", "a GET %s carries no body and no Origin", r.Class)
		}
	}
	switch {
	case r.Redirected && r.Class != ClassNavigation:
		return bad("redirected", "only a navigation hop follows a redirect")
	case r.Added.FetchUser && r.Class != ClassNavigation && r.Class != ClassForm:
		return bad("added.fetch_user", "only a navigation or form carries sec-fetch-user")
	}
	return nil
}

// universalChromiumOrder: a no-cors element load is a Blink subresource like a script; a preflight is the network
// service's fixed sequence, without cookie, body or client hints; a form is the browser process's navigation list
// with its body, cache-control, content-type and Origin.
func (law *lawFile) universalChromiumOrder(r *Request, unwitnessed func(string, ...any) error) (Wire, error) {
	if err := law.chromiumWitnessed(r, unwitnessed); err != nil {
		return Wire{}, err
	}
	c := &law.Chromium
	var out []string
	if !r.HTTP2 && r.Class != ClassNoCORS {
		out = append(out, c.HTTP1Prefix...)
	}
	switch r.Class {
	case ClassNoCORS:
		out = chromiumOrder(c, r, nil)
	case ClassPreflight:
		if r.Added.StorageAccess {
			return Wire{}, unwitnessed("no witnessed preflight carries sec-fetch-storage-access")
		}
		for _, name := range c.Preflight {
			if preflightSends(&r.Added, name) {
				out = append(out, name)
			}
		}
		if r.HTTP2 && r.Added.Priority {
			out = append(out, "priority")
		}
	case ClassForm:
		hints, err := c.navigationHints(r, unwitnessed)
		if err != nil {
			return Wire{}, err
		}
		set := c.Form.browserSet(r.Engine.Major)
		out = slices.Concat(out, c.Form.Prefix, hints, set)
		for _, name := range c.NetworkAfter {
			if !slices.Contains(set, name) && r.Added.present(name) {
				out = append(out, name)
			}
		}
		for _, name := range c.NetworkTail {
			if r.Added.present(name) {
				out = append(out, name)
			}
		}
		if r.HTTP2 && r.Added.Priority {
			out = append(out, "priority")
		}
	default:
		return Wire{}, unwitnessed("no browser-owned law for this class")
	}
	return Wire{Header: out, Pseudo: slices.Clone(c.Pseudo)}, nil
}

// browserSet is major's form BrowserSet. HYPOTHESIS(chromium-form-next-run): a major between two witnessed runs
// (Chrome 142-149) sends the next later run's set, Chrome 150-155's origin after user-agent. Falsified by a
// Chrome 142-149 form POST with origin before content-type, as Chrome 141's (xfinity_login_android-chrome141_1_0907#372).
func (f *chromiumForm) browserSet(major int) []string {
	var next *chromiumFormMajors
	for i := range f.Majors {
		m := &f.Majors[i]
		if major >= m.From && major <= m.To {
			return m.BrowserSet
		}
		if m.From > major && (next == nil || m.From < next.From) {
			next = m
		}
	}
	return next.BrowserSet
}

// preflightSends: a preflight carries access-control-request-headers only for a request with a header that is
// not CORS-safelisted and referer only with a referrer; every other name of a preflight sequence always.
func preflightSends(a *Added, name string) bool {
	switch name {
	case "access-control-request-headers":
		return a.RequestHeaders
	case "referer":
		return a.Referer
	}
	return true
}

// universalWebkitBrowserOrder frames a WebKit form as the fetch/XHR dictionary of its content-type (the
// form's enctype) and the loader's names; a preflight and a browser-owned GET by their own sequences.
func (law *lawFile) universalWebkitBrowserOrder(r *Request, unwitnessed func(string, ...any) error) (Wire, error) {
	w := &law.WebKit
	if r.Added.FetchUser {
		return Wire{}, &InputError{Field: "added.fetch_user", Detail: "WebKit sends no sec-fetch-user"}
	}
	if err := w.framed(r, unwitnessed); err != nil {
		return Wire{}, err
	}
	switch r.Class {
	case ClassForm:
		if r.Added.UpgradeInsecureRequests {
			return Wire{}, unwitnessed("no witnessed WebKit form POST carries upgrade-insecure-requests")
		}
		form := *r
		form.Calls = []string{"content-type"}
		return law.universalWebkitOrder(&form)
	case ClassPreflight:
		return w.preflightOrder(r, unwitnessed)
	}
	return w.browserGetOrder(r, unwitnessed)
}

// preflightOrder inserts the preflight's names into the CF dictionary in Preflight.Insertion's order (every
// captured late Safari preflight). HYPOTHESIS(webkit-early-preflight): an early or early-webview build inserts
// its Inside names after them and sends its own tail, as its fetch and XHR keep them; falsified by an early
// preflight capture in another order.
func (w *webkitLaw) preflightOrder(r *Request, unwitnessed func(string, ...any) error) (Wire, error) {
	g, _ := w.universalGeneration(r.Engine)
	if err := g.priority(r); err != nil {
		return Wire{}, err
	}
	var names []string
	for _, name := range w.Preflight.Insertion {
		if preflightSends(&r.Added, name) {
			names = append(names, name)
		}
	}
	for _, name := range g.Inside {
		if r.Added.present(name) {
			names = append(names, name)
		}
	}
	header, err := cfInsert(names)
	if err != nil {
		return Wire{}, unwitnessed("%v", err)
	}
	return w.wire(r, slices.Concat(header, w.Preflight.Tail, g.tail(r, nil))), nil
}

// browserGetOrder frames a navigation, script or no-cors element load. A generation with the script law
// inserts the browser-owned names in BrowserLoad.Insertion's order and appends its tail; a redirect hop
// re-inserts the hop before it with BrowserLoad's carried and re-set names, as every captured law and late
// redirect hop does. A generation without it keeps its captured BrowserGet order.
// HYPOTHESIS(webkit-early-browser-get): that order also holds an early redirect hop and no-cors element load,
// and an early-webview cookie sits last; falsified by an early capture of either in another order.
func (w *webkitLaw) browserGetOrder(r *Request, unwitnessed func(string, ...any) error) (Wire, error) {
	g, _ := w.universalGeneration(r.Engine)
	if err := g.priority(r); err != nil {
		return Wire{}, err
	}
	sends := func(name string) bool { return name == "accept" || r.Added.present(name) }
	if !g.ScriptLaw {
		var header []string
		for _, name := range g.BrowserGet {
			if sends(name) {
				header = append(header, name)
			}
		}
		for _, name := range w.BrowserLoad.Insertion {
			if sends(name) && !slices.Contains(header, name) {
				return Wire{}, unwitnessed("WebKit generation %s: no captured browser-owned GET carries %s", g.Name, name)
			}
		}
		for _, name := range g.Inside {
			if sends(name) && !slices.Contains(header, name) {
				return Wire{}, unwitnessed("WebKit generation %s: no captured browser-owned GET carries %s", g.Name, name)
			}
		}
		return w.wire(r, append(header, g.tail(r, nil)...)), nil
	}
	var names []string
	for _, name := range w.BrowserLoad.Insertion {
		if sends(name) {
			names = append(names, name)
		}
	}
	dict, err := cfInsert(names)
	if err != nil {
		return Wire{}, unwitnessed("%v", err)
	}
	tail := g.tail(r, nil)
	if r.Redirected {
		carried := slices.DeleteFunc(slices.Clone(w.BrowserLoad.RedirectCarried), func(n string) bool { return !slices.Contains(tail, n) })
		history := slices.DeleteFunc(dict, func(n string) bool { return slices.Contains(w.BrowserLoad.Reinserted, n) })
		history = append(history, carried...)
		for _, name := range w.BrowserLoad.Reinserted {
			if sends(name) {
				history = append(history, name)
			}
		}
		if dict, err = cfInsert(history); err != nil {
			return Wire{}, unwitnessed("%v", err)
		}
		tail = slices.DeleteFunc(tail, func(n string) bool { return slices.Contains(carried, n) })
	}
	return w.wire(r, append(dict, tail...)), nil
}

// wire frames header for r's protocol; HTTP/1.1 carries no pseudo-headers.
func (w *webkitLaw) wire(r *Request, header []string) Wire {
	header = w.frame(r, header)
	if !r.HTTP2 {
		return Wire{Header: header}
	}
	return Wire{Header: header, Pseudo: slices.Clone(w.Pseudo)}
}
