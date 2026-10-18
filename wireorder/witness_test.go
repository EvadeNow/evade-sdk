package wireorder

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

type witnessVerdict uint8

const (
	verdictOrder witnessVerdict = iota
	verdictUnwitnessed
	verdictAmbiguous // the law leaves the order open and its outcomes hold the capture
	// verdictLate: the law orders it as the late generation, not as captured: HYPOTHESIS(webkit_early_falls_back_to_late).
	verdictLate
)

// Generations witnessed only by the iOS probe sessions in witnesses, not by the HAR corpus.
var webkitWitnessedOutsideCorpus = map[string]string{
	"early":         "witness_test.go",
	"early-webview": "witness_test.go",
	"law":           "witness_test.go",
}

// witness is a real browser request, header names in received order; id is capture#entry.
type witness struct {
	id      string
	verdict witnessVerdict
	ua      string
	r       Request
	want    []string
	pseudo  []string
}

var witnesses = []witness{
	// Chrome 154/155 on macOS (powhttp).
	{
		id: "chrome155-1#18", verdict: verdictOrder,
		ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
		r:      Request{Engine: Engine{Kind: Chromium, Major: 155}, Class: ClassNavigation, Method: "GET", HTTP2: true, Redirected: true, Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}, Priority: true, FetchUser: true}},
		want:   []string{"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "accept-encoding", "accept-language", "priority"},
		pseudo: []string{":method", ":authority", ":scheme", ":path"},
	},
	{
		id: "chrome155-1#50", verdict: verdictOrder,
		ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
		r:      Request{Engine: Engine{Kind: Chromium, Major: 155}, Class: ClassScript, Method: "GET", HTTP2: true, Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}, Referer: true, Priority: true, StorageAccess: true}},
		want:   []string{"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-storage-access", "referer", "accept-encoding", "accept-language", "priority"},
		pseudo: []string{":method", ":authority", ":scheme", ":path"},
	},
	{
		id: "chrome155-1#198", verdict: verdictOrder,
		ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
		r:      Request{Engine: Engine{Kind: Chromium, Major: 155}, Class: ClassNavigation, Method: "GET", HTTP2: true, Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}, Referer: true, Cookie: true, Priority: true, FetchUser: true}},
		want:   []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"},
		pseudo: []string{":method", ":authority", ":scheme", ":path"},
	},
	{
		id: "chrome155-1#697", verdict: verdictOrder,
		ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
		r:      Request{Engine: Engine{Kind: Chromium, Major: 155}, Class: ClassFetch, Method: "POST", HTTP2: true, Calls: []string{"x-api-key", "content-type", "accept", "x-gyjwza5z-f", "x-gyjwza5z-b", "x-gyjwza5z-c", "x-gyjwza5z-d", "x-gyjwza5z-z", "x-gyjwza5z-a"}, ShapePrefix: "x-gyjwza5z-", Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}, Origin: true, Referer: true, Cookie: true, Body: true, Priority: true}},
		want:   []string{"content-length", "sec-ch-ua-platform", "x-gyjwza5z-z", "sec-ch-ua", "x-gyjwza5z-f", "x-api-key", "sec-ch-ua-mobile", "x-gyjwza5z-b", "x-gyjwza5z-a", "user-agent", "accept", "x-gyjwza5z-c", "content-type", "x-gyjwza5z-d", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"},
		pseudo: []string{":method", ":authority", ":scheme", ":path"},
	},
	{
		id: "control-chrome154-1#27", verdict: verdictOrder,
		ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
		r:      Request{Engine: Engine{Kind: Chromium, Major: 154}, Class: ClassNavigation, Method: "GET", HTTP2: true, Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}, Priority: true, FetchUser: true}},
		want:   []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "priority"},
		pseudo: []string{":method", ":authority", ":scheme", ":path"},
	},
	{
		id: "control-chrome154-1#45", verdict: verdictOrder,
		ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
		r:      Request{Engine: Engine{Kind: Chromium, Major: 154}, Class: ClassScript, Method: "GET", HTTP2: true, Added: Added{ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}, Referer: true, Priority: true, StorageAccess: true}},
		want:   []string{"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-storage-access", "referer", "accept-encoding", "accept-language", "priority"},
		pseudo: []string{":method", ":authority", ":scheme", ":path"},
	},
	// Safari 26/27 on real devices (BrowserStack).
	{
		id: "control-ios26#31", verdict: verdictOrder,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 26, Minor: 6}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true, Added: Added{Referer: true, Priority: true}},
		want: []string{"sec-fetch-dest", "user-agent", "accept", "referer", "sec-fetch-site", "sec-fetch-mode", "accept-language", "priority", "accept-encoding"},
	},
	{
		id: "target-ios27#30", verdict: verdictOrder,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 27}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true, Added: Added{Referer: true, Priority: true}},
		want: []string{"sec-fetch-dest", "user-agent", "accept", "referer", "sec-fetch-site", "sec-fetch-mode", "accept-language", "priority", "accept-encoding"},
	},
	{
		id: "control-ios26-b#33", verdict: verdictOrder,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 26}, Class: ClassFetch, Method: "POST", HTTP2: true, Calls: []string{"content-type", "accept", "x-requested-with", "x-probe-a", "x-probe-b", "accept-api-version"}, Added: Added{Origin: true, Referer: true, Body: true, Priority: true}},
		want: []string{"content-type", "accept", "x-requested-with", "sec-fetch-site", "x-probe-a", "sec-fetch-mode", "origin", "x-probe-b", "user-agent", "referer", "content-length", "sec-fetch-dest", "accept-api-version", "accept-language", "priority", "accept-encoding"},
	},
	{
		id: "control-ios26-b#35", verdict: verdictAmbiguous,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 26}, Class: ClassXHR, Method: "POST", HTTP2: true, Calls: []string{"content-type", "x-probe-a", "x-probe-b"}, Added: Added{Origin: true, Referer: true, Body: true, Priority: true}},
		want: []string{"accept", "content-type", "sec-fetch-site", "origin", "x-probe-b", "sec-fetch-mode", "x-probe-a", "user-agent", "referer", "sec-fetch-dest", "content-length", "accept-language", "priority", "accept-encoding"},
	},
	{
		id: "target-ios27-b#35", verdict: verdictOrder,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 27}, Class: ClassFetch, Method: "POST", HTTP2: true, Calls: []string{"content-type", "accept", "x-requested-with", "x-probe-a", "x-probe-b", "accept-api-version"}, Added: Added{Origin: true, Referer: true, Body: true, Priority: true}},
		want: []string{"content-type", "accept", "x-requested-with", "sec-fetch-site", "x-probe-a", "sec-fetch-mode", "origin", "x-probe-b", "user-agent", "referer", "content-length", "sec-fetch-dest", "accept-api-version", "accept-language", "priority", "accept-encoding"},
	},
	// iOS Safari and Chrome for iOS probe sessions (BrowserStack), by WebKit generation.
	{
		id: "ios18-crios-16#21", verdict: verdictLate,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 6, WebView: true}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true, Added: Added{Referer: true}},
		want: []string{"accept", "sec-fetch-site", "sec-fetch-dest", "accept-language", "sec-fetch-mode", "user-agent", "referer", "accept-encoding"},
	},
	{
		id: "ios18-safari-14#27", verdict: verdictLate,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 18}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true, Added: Added{Referer: true}},
		want: []string{"accept", "sec-fetch-site", "sec-fetch-dest", "accept-language", "sec-fetch-mode", "user-agent", "referer", "accept-encoding"},
	},
	{
		id: "ios18-safari-16#30", verdict: verdictOrder,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 5}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true, Added: Added{Referer: true, Priority: true}},
		want: []string{"sec-fetch-dest", "user-agent", "accept", "referer", "sec-fetch-site", "sec-fetch-mode", "accept-language", "priority", "accept-encoding"},
	},
	{
		id: "probe-crios-13#25", verdict: verdictUnwitnessed,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 4, WebView: true}, Class: ClassFetch, Method: "GET", HTTP2: true, Calls: []string{"X-Alpha", "X-Beta"}, Added: Added{Referer: true, Cookie: true}},
		want: []string{"x-alpha", "x-beta", "accept", "sec-fetch-site", "accept-encoding", "accept-language", "sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "cookie"},
	},
	{
		id: "probe-crios-14#18", verdict: verdictUnwitnessed,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 18, WebView: true}, Class: ClassXHR, Method: "GET", HTTP2: true, Calls: []string{"X-Alpha", "X-Beta"}, Added: Added{Referer: true, Cookie: true}},
		want: []string{"x-alpha", "x-beta", "accept", "sec-fetch-site", "accept-encoding", "accept-language", "sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "cookie"},
	},
	{
		id: "probe-crios26-15#24", verdict: verdictOrder,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 26, Minor: 6, WebView: true}, Class: ClassXHR, Method: "GET", HTTP2: true, Calls: []string{"X-Alpha", "X-Beta"}, Added: Added{Referer: true, Cookie: true, Priority: true}},
		want: []string{"accept", "sec-fetch-site", "x-beta", "sec-fetch-mode", "x-alpha", "user-agent", "referer", "sec-fetch-dest", "accept-language", "priority", "accept-encoding", "cookie"},
	},
	{
		id: "probe-crios26-15#25", verdict: verdictAmbiguous,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 26, Minor: 6, WebView: true}, Class: ClassXHR, Method: "GET", HTTP2: true, Calls: []string{"X-Alpha", "Accept-Language"}, Added: Added{Referer: true, Cookie: true, Priority: true}},
		want: []string{"accept", "sec-fetch-site", "sec-fetch-mode", "x-alpha", "accept-language", "referer", "sec-fetch-dest", "user-agent", "priority", "accept-encoding", "cookie"},
	},
	{
		id: "probe-crios26-15#26", verdict: verdictOrder,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 26, Minor: 6, WebView: true}, Class: ClassFetch, Method: "GET", HTTP2: true, Calls: []string{"X-Alpha", "X-Beta"}, Added: Added{Referer: true, Cookie: true, Priority: true}},
		want: []string{"accept", "sec-fetch-site", "x-beta", "sec-fetch-mode", "x-alpha", "user-agent", "referer", "sec-fetch-dest", "accept-language", "priority", "accept-encoding", "cookie"},
	},
	{
		id: "probe-crios26-15#28", verdict: verdictOrder,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 26, Minor: 6, WebView: true}, Class: ClassScript, Method: "GET", HTTP2: true, Inserted: true, Added: Added{Referer: true, Cookie: true, Priority: true}},
		want: []string{"sec-fetch-dest", "user-agent", "accept", "referer", "sec-fetch-site", "sec-fetch-mode", "accept-language", "priority", "accept-encoding", "cookie"},
	},
	{
		id: "probe-safari-16#19", verdict: verdictUnwitnessed,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 6}, Class: ClassXHR, Method: "GET", HTTP2: true, Calls: []string{"X-Alpha", "X-Beta"}, Added: Added{Referer: true, Cookie: true, Priority: true}},
		want: []string{"accept", "x-beta", "sec-fetch-site", "sec-fetch-mode", "x-alpha", "user-agent", "referer", "sec-fetch-dest", "accept-language", "priority", "accept-encoding", "cookie"},
	},
	{
		id: "probe-safari-16#22", verdict: verdictAmbiguous,
		ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
		r:    Request{Engine: Engine{Kind: WebKit, Major: 18, Minor: 6}, Class: ClassXHR, Method: "POST", HTTP2: true, Calls: []string{"X-Alpha", "Content-Type"}, Added: Added{Origin: true, Referer: true, Cookie: true, Body: true, Priority: true}},
		want: []string{"accept", "content-type", "origin", "sec-fetch-site", "sec-fetch-mode", "x-alpha", "user-agent", "referer", "sec-fetch-dest", "content-length", "accept-language", "priority", "accept-encoding", "cookie"},
	},
}

func TestWitnesses(t *testing.T) {
	law := testLaw(t)
	for _, w := range witnesses {
		t.Run(w.id, func(t *testing.T) {
			if e := EngineFromUserAgent(w.ua); e != w.r.Engine {
				t.Fatalf("%q parses as %s, case says %s", w.ua, e, w.r.Engine)
			}
			got, err := Order(w.r)
			switch w.verdict {
			case verdictOrder:
				if err != nil || !slices.Equal(got.Header, w.want) {
					t.Fatalf("law %v (%v)\ncapture %v", got.Header, err, w.want)
				}
				if w.pseudo != nil && !slices.Equal(got.Pseudo, w.pseudo) {
					t.Fatalf("pseudo %v, capture %v", got.Pseudo, w.pseudo)
				}
			case verdictUnwitnessed:
				wantErr[*UnwitnessedError](t, err)
			case verdictAmbiguous:
				wantErr[*AmbiguousError](t, err)
				if outcomes, err := Outcomes(w.r); err != nil || !containsOrder(outcomes, w.want) {
					t.Fatalf("outcomes %v (%v) omit the capture %v", outcomes, err, w.want)
				}
			case verdictLate:
				wantLateOrder(t, w.id, w.r)
			}
		})
	}
	if law.Chromium.Witnessed[1] < 155 {
		t.Errorf("Chrome 155 witnesses reproduce but the law's majors %v stop before 155", law.Chromium.Witnessed)
	}
}

func TestWebKitCounterwitnesses(t *testing.T) {
	w := &testLaw(t).WebKit
	for _, g := range w.Generations {
		for _, cw := range g.Counterwitness {
			id := fmt.Sprintf("%s#%d", cw.HAR, cw.Entry)
			i := slices.IndexFunc(witnesses, func(x witness) bool { return x.id == id })
			if i < 0 {
				t.Errorf("generation %s counterwitness %s is not in witnesses", g.Name, id)
				continue
			}
			if got := w.generation(witnesses[i].r.Engine); got == nil || got.Name != g.Name {
				t.Errorf("generation %s counterwitness %s is a build of %v", g.Name, id, got)
			}
			d, _ := webkitSplit(w, witnesses[i].want)
			if !slices.Equal(d, cw.Dictionary) {
				t.Errorf("generation %s counterwitness %s dictionary %v, law %v", g.Name, id, d, cw.Dictionary)
				continue
			}
			if reach, err := cfReaches(d, insertionModel(w, d, nil), d); err != nil || reach {
				t.Errorf("generation %s counterwitness %s: the insertion model reaches %v (%v)", g.Name, id, d, err)
			}
		}
	}
}

func containsOrder(outcomes [][]string, o []string) bool {
	return slices.ContainsFunc(outcomes, func(x []string) bool { return slices.Equal(x, o) })
}

func lowerAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.ToLower(n)
	}
	return out
}

// The law generation keeps a page-set Accept-Language as one dictionary entry; the late generation refuses it, and so
// an early one, ordered as late (HYPOTHESIS(webkit_early_falls_back_to_late)).
func TestWebKitPageSetAcceptLanguageByGeneration(t *testing.T) {
	lawBuild := Engine{Kind: WebKit, Major: 18, Minor: 3}
	lateBuild := Engine{Kind: WebKit, Major: 18, Minor: 6}
	xhr := Request{Engine: lawBuild, Class: ClassXHR, Method: "GET", HTTP2: true, Calls: []string{"X-Alpha", "Accept-Language"},
		Added: Added{Referer: true, Cookie: true, Priority: true}}
	_, err := Order(xhr)
	wantErr[*AmbiguousError](t, err)
	outcomes, err := Outcomes(xhr)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range outcomes {
		for _, name := range []string{"accept-language", "priority", "accept-encoding", "cookie"} {
			if n := len(slices.DeleteFunc(slices.Clone(o), func(h string) bool { return h != name })); n != 1 {
				t.Errorf("law generation outcome %v carries %s %d times", o, name, n)
			}
		}
		if !slices.Contains(dictionaryOf(t, xhr, o), "accept-language") {
			t.Errorf("law generation outcome %v: page-set accept-language is not a dictionary entry", o)
		}
	}
	xhr.Engine = lateBuild
	_, err = Order(xhr)
	wantErr[*UnwitnessedError](t, err)
	early := xhr
	early.Engine = Engine{Kind: WebKit, Major: 18}
	_, err = Order(early)
	wantErr[*UnwitnessedError](t, err)
}
