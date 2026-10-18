package wireorder

import (
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
	var hints []string
	for _, name := range c.Navigation.ClientHints {
		if slices.Contains(r.Added.ClientHints, name) {
			hints = append(hints, name)
		}
	}
	if len(hints) != len(r.Added.ClientHints) {
		return Wire{}, unwitnessed("navigation client hints %v: only %v are witnessed (an origin's Accept-CH hints are not)", r.Added.ClientHints, c.Navigation.ClientHints)
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
