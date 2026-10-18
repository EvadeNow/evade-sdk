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
	ClassReload     RequestClass = "reload" // same-origin document reload carrying cookies
	ClassXHR        RequestClass = "xhr"
	ClassFetch      RequestClass = "fetch"
	ClassScript     RequestClass = "script" // classic <script src> subresource
	ClassImage      RequestClass = "image"
	ClassForm       RequestClass = "form" // no captured order: Order fails
)

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
	}
	return wireorder.ClassUnknown, false
}

type OrderRequest struct {
	UserAgent string
	Class     RequestClass
	Method    string
	HTTP2     bool
	// Page header-set calls in program order (setRequestHeader or fetch init); browser-owned names are refused.
	Calls      []string
	Added      wireorder.Added // conditional headers the browser adds
	Redirected bool            // navigation hop following a server redirect
	Inserted   bool            // script element created by page JS, not the HTML parser
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

// Order returns r's lowercase header wire order: the wire-order law where it certifies engine and class (its refusals final), else a captured row; Edge and Opera always fail.
func Order(r OrderRequest) ([]string, error) {
	agent, parseErr := useragent.Parse(r.UserAgent)
	if parseErr == nil && agent.Family == useragent.FamilyAndroidWebView {
		// Its Chrome/ token reads as Chromium, but WebView adds x-requested-with; only captured rows order it.
		return captured(agent.Family, r.Class, androidWebViewOrder(r.Class))
	}
	engine := wireorder.EngineFromUserAgent(r.UserAgent)
	if class, ok := r.Class.lawClass(); ok && engine.Kind != wireorder.EngineUnknown && (parseErr == nil || engine.WebView) {
		wire, err := wireorder.Order(wireorder.Request{
			Engine: engine, Class: class, Method: r.Method, HTTP2: r.HTTP2,
			Calls: r.Calls, Added: r.Added, Redirected: r.Redirected, Inserted: r.Inserted,
		})
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
