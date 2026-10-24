package wireorder

import (
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

func browserModeled(law *chromiumLaw, c *capture) bool {
	for _, n := range c.Names {
		if !slices.Contains(law.BlinkSetOrder, n) && !slices.Contains(law.NetworkAfter, n) &&
			!slices.Contains(law.NetworkTail, n) && !slices.Contains(law.HTTP1Prefix, n) &&
			!slices.Contains(law.Navigation.BrowserSet, n) && n != "priority" {
			return false
		}
	}
	return true
}

var browserExcluded = map[string]string{
	"vint_web#3":              "evade solver traffic (the HAR's next entry is POST api.evade.now/solve), not a browser",
	"prizepicks#42":           "user-agent after the client hints: a Blink map filled in another order; initiator not recorded",
	"bandai-us_login_android-chrome150_1_0828#24": "typed in the Android omnibox (preceded by complete/search)",
	"bandai-jp_product_windows-chrome151_1_0809#0":        "bare host p-bandai.jp/ typed as the HAR's first request",
	"chase_login_windows-chrome151_1_0830#81":             "typed bare host chase.com (preceded by complete/search)",
	"sky_login_android-chrome151_1_0901#0":             "bare host sky.com typed as the HAR's first request",
	"uhc_login_android-chrome151_1_0901#12":            "typed bare host uhc.com (preceded by complete/search)",
	"westjet_login_android-chrome151_1_0901#27":        "typed bare host westjet.com (preceded by complete/search)",
	"hermes-email#16":         "typed bare host hermes.com",
	"target_login_mac-chrome155_1_1013#16":        "typed bare host target.com (preceded by complete/search)",
	"target_login_mac-chrome155_1_1013#249":       "typed bare host target.com (preceded by complete/search)",
	"bandai-item-domfree#3":   "automation Accept-Language override (en-US after user-agent)",
	"bandai-item-domfree#10":  "automation Accept-Language override (en-US after sec-ch-ua)",
	"bandai-item-domfree#18":  "automation Accept-Language override (en-US after sec-ch-ua)",
	"bandai-cart-haronly":     "automation Accept-Language override (en-US after user-agent or sec-ch-ua)",
	"vint_web#2":              "evade solver session (vint_web#3), hop after an unrecorded redirect",
	"axs-3#3":                 "the hop after http://shop.axs.com/'s cross-scheme redirect",
}

func TestBrowserClassCaptures(t *testing.T) {
	law := testLaw(t)
	c := &law.Chromium
	type tally struct{ reproduced, excluded, refused, total int }
	counts := map[Class]*tally{ClassScript: {}, ClassNavigation: {}}
	seen, loaded := map[string]bool{}, map[string]bool{}
	for _, capture := range corpus(t) {
		loaded[capture.HAR] = true
		e, ok := engineOf(capture.UA)
		if !ok || e.Kind != Chromium || e.Major < c.Witnessed[0] || e.Major > c.Witnessed[1] || capture.Method != "GET" {
			continue
		}
		var class Class
		switch {
		case capture.Mode == "no-cors" && capture.Dest == "script":
			class = ClassScript
		case capture.Mode == "navigate" && capture.Dest == "document":
			class = ClassNavigation
		default:
			continue
		}
		if !browserModeled(c, capture) {
			continue
		}
		n := counts[class]
		n.total++
		added := chromiumAdded(capture, c)
		added.FetchUser = capture.has("sec-fetch-user")
		w, err := law.order(&Request{Engine: e, Class: class, Method: capture.Method, HTTP2: capture.HTTP2,
			Redirected: class == ClassNavigation && capture.Redirected, Added: added})
		key := capture.String()
		why, excluded := browserExcluded[key]
		if !excluded {
			key = capture.HAR
			why, excluded = browserExcluded[key]
		}
		seen[key] = seen[key] || excluded
		switch {
		case errors.As(err, new(*UnwitnessedError)):
			n.refused++
			t.Logf("refused %s: %v", capture, err)
		case err != nil:
			t.Errorf("%s: %v", capture, err)
		case slices.Equal(w.Header, capture.Names) && (!capture.HTTP2 || slices.Equal(w.Pseudo, capture.Pseudo)):
			n.reproduced++
			if excluded {
				t.Errorf("%s is excluded (%s) but reproduces", capture, why)
			}
		case excluded:
			n.excluded++
			t.Logf("excluded %s: %s", capture, why)
		default:
			t.Errorf("%s %s redirected=%v: law %v\ncapture %v", capture, class, capture.Redirected, w.Header, capture.Names)
		}
	}
	for class, want := range map[Class]tally{
		ClassScript:     {reproduced: 1050, excluded: 2, refused: 5, total: 1057},
		ClassNavigation: {reproduced: 61, excluded: 13, refused: 7, total: 81},
	} {
		if got := *counts[class]; got != want {
			t.Errorf("%s: %+v, want %+v", class, got, want)
		}
	}
	// An exclusion of a HAR this checkout lacks is unverifiable, not stale.
	for name := range browserExcluded {
		if har, _, _ := strings.Cut(name, "#"); loaded[har] && !seen[name] {
			t.Errorf("exclusion %s matches no modeled capture", name)
		}
	}
}

var safariVersionRE = regexp.MustCompile(`Version/([\d.]+) `)

// Each refused Safari class has a dictionary captured in two wire orders.
func TestWebKitBrowserClassesAreUnresolved(t *testing.T) {
	law := testLaw(t)
	type key struct{ class, dictionary string }
	orders := map[key]map[string][]string{}
	for _, c := range corpus(t) {
		e, ok := engineOf(c.UA)
		if !ok || e.Kind != WebKit || !c.HTTP2 || c.Method != "GET" {
			continue
		}
		class := map[[2]string]string{{"navigate", "document"}: "navigation", {"no-cors", "script"}: "script"}[[2]string{c.Mode, c.Dest}]
		if class == "" {
			continue
		}
		dictionary := slices.Clone(c.Names)
		sort.Strings(dictionary)
		k := key{class, strings.Join(dictionary, ",")}
		if orders[k] == nil {
			orders[k] = map[string][]string{}
		}
		order := strings.Join(c.Names, ",")
		if m := safariVersionRE.FindStringSubmatch(c.UA); m != nil && !slices.Contains(orders[k][order], m[1]) {
			orders[k][order] = append(orders[k][order], m[1])
		}
	}
	split := map[string]bool{}
	for k, byOrder := range orders {
		if len(byOrder) < 2 {
			continue
		}
		split[k.class] = true
		for order, versions := range byOrder {
			t.Logf("%s {%s}: %s on Safari %v", k.class, k.dictionary, order, versions)
		}
	}
	for class := range law.WebKit.UnwitnessedClasses {
		if !split[class] {
			t.Errorf("webkit %s is refused but no dictionary of it is captured in two orders", class)
		}
	}
	for _, class := range []Class{ClassNavigation, ClassScript} {
		_, err := Order(Request{Engine: Engine{Kind: WebKit, Major: 18}, Class: class, Method: "GET", HTTP2: true})
		wantErr[*UnwitnessedError](t, err)
	}
}

var shapeSeededVM = regexp.MustCompile(`[?&]seed=`)

func TestWebKitInsertedScriptCaptures(t *testing.T) {
	law := testLaw(t)
	w := &law.WebKit
	reproduced := map[string]int{}
	var counter []string
	for _, c := range corpus(t) {
		e, ok := engineOf(c.UA)
		if !ok || e.Kind != WebKit || !c.HTTP2 || !slices.Equal(c.Pseudo, w.Pseudo) ||
			c.Dest != "script" || c.Mode != "no-cors" || !shapeSeededVM.MatchString(c.URL) {
			continue
		}
		got, err := Order(Request{Engine: e, Class: ClassScript, Method: c.Method, HTTP2: true, Inserted: true,
			Added: Added{Referer: c.has("referer"), Cookie: c.has("cookie"), Priority: c.has("priority")}})
		if err != nil {
			t.Errorf("%s: %v", c, err)
			continue
		}
		listed := slices.ContainsFunc(w.InsertedScript.Counterwitness, func(cw Counterwitness) bool { return cw.HAR == c.HAR && cw.Entry == c.Entry })
		switch match := slices.Equal(got.Header, c.Names); {
		case match && listed:
			t.Errorf("%s is a listed counterwitness but reproduces %v", c, c.Names)
		case match:
			reproduced[w.generation(e).Name]++
		case listed:
			counter = append(counter, c.String())
		default:
			t.Errorf("%s (%s): law %v\ncapture %v", c, e, got.Header, c.Names)
		}
	}
	t.Logf("reproduced by WebKit generation %v; counterwitnesses %v", reproduced, counter)
	for _, g := range w.Generations {
		if g.ScriptLaw && reproduced[g.Name] == 0 && webkitWitnessedOutsideCorpus[g.Name] == "" {
			t.Errorf("WebKit generation %s: no loader-inserted VM capture reproduced", g.Name)
		}
	}
	if len(counter) != len(w.InsertedScript.Counterwitness) {
		t.Errorf("counterwitnesses seen %v, law lists %d", counter, len(w.InsertedScript.Counterwitness))
	}
}
