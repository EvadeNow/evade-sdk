// Package useragent classifies User-Agent strings into the browser families whose TLS and HTTP behavior the SDK models.
package useragent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Family string

const (
	FamilyChrome         Family = "chrome" // Google Chrome on desktop and Android
	FamilyEdge           Family = "edge"
	FamilyOpera          Family = "opera"
	FamilyAndroidWebView Family = "android-webview"
	FamilySafariIOS      Family = "safari-ios" // Safari on iPhone and iPad
	FamilySafariMacOS    Family = "safari-macos"
	FamilyFirefox        Family = "firefox" // Firefox on desktop and Android
)

// Blink reports whether f runs on Chromium's network stack.
func (f Family) Blink() bool {
	switch f {
	case FamilyChrome, FamilyEdge, FamilyOpera, FamilyAndroidWebView:
		return true
	}
	return false
}

type OS string

const (
	OSWindows  OS = "windows"
	OSMacOS    OS = "macos"
	OSLinux    OS = "linux"
	OSChromeOS OS = "chromeos"
	OSAndroid  OS = "android"
	OSIOS      OS = "ios"
)

type Agent struct {
	Raw           string
	Family        Family
	OS            OS
	Major, Minor  int // of the browser's own token: Edg/, OPR/, Version/ (Safari), Chrome/, Firefox/
	ChromiumMajor int // Chrome/ major for Blink families, else 0; Blink TLS follows it
	Mobile        bool
}

type UnsupportedError struct {
	UserAgent string
	Reason    string
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("useragent: unsupported User-Agent %q: %s", e.UserAgent, e.Reason)
}

var (
	// Whole-word names: "HeadlessChrome/120" is HeadlessChrome, never Chrome.
	productTokenRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]*)/([^\s;()]+)`)
	versionRe      = regexp.MustCompile(`^(\d+)\.(\d+)`)
	iosVersionRe   = regexp.MustCompile(`\bOS (\d+)_(\d+)`)
	// Case-sensitive: a lowercase "cros" test would match "Microsoft".
	crosRe = regexp.MustCompile(`\bCrOS\b`)
	// Excludes the iOS "Mobile/15E148" build token: iPads carry it too.
	mobileRe = regexp.MustCompile(`\bMobile(?:[\s;)]|$)`)
)

// Third-party iOS browsers carry Safari's tokens but send their own headers.
var thirdPartyIOS = [...]struct {
	token, name string
	browser     Browser
}{
	{"CriOS", "Chrome for iOS", BrowserChrome},
	{"FxiOS", "Firefox for iOS", BrowserFirefox},
	{"EdgiOS", "Edge for iOS", BrowserEdge},
}

// Parse never defaults a field: anything it cannot classify fails with *UnsupportedError naming the reason.
func Parse(ua string) (Agent, error) {
	unsupported := func(reason string) (Agent, error) {
		return Agent{}, &UnsupportedError{UserAgent: ua, Reason: reason}
	}
	if strings.TrimSpace(ua) == "" {
		return unsupported("empty User-Agent")
	}
	tokens := productTokens(ua)
	for _, b := range thirdPartyIOS {
		if has(tokens, b.token) {
			return unsupported(fmt.Sprintf("%s (%s/) is not a supported browser", b.name, b.token))
		}
	}

	os, osKnown := declaredOS(ua)
	webView := strings.Contains(ua, "; wv)")
	a := Agent{
		Raw: ua,
		OS:  os,
		// iPhone/iPod are phones even without the Mobile word; iPads stay non-mobile.
		Mobile: mobileRe.MatchString(ua) || strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPod"),
	}

	var product string
	switch {
	case has(tokens, "Firefox"):
		a.Family, product = FamilyFirefox, "Firefox"
	case has(tokens, "Chrome"):
		chromiumMajor, _, err := tokenVersion(ua, tokens, "Chrome")
		if err != nil {
			return Agent{}, err
		}
		a.ChromiumMajor = chromiumMajor
		switch {
		case has(tokens, "Edg"):
			a.Family, product = FamilyEdge, "Edg"
		case has(tokens, "EdgA"):
			a.Family, product = FamilyEdge, "EdgA"
		case has(tokens, "OPR"):
			a.Family, product = FamilyOpera, "OPR"
		case os == OSAndroid && webView:
			// Every real WebView UA keeps the frozen Version/4.0 next to "; wv)".
			if tokens["Version"] != "4.0" {
				return unsupported("Android \"; wv)\" marker without the WebView Version/4.0 token")
			}
			a.Family, product = FamilyAndroidWebView, "Chrome"
		default:
			a.Family, product = FamilyChrome, "Chrome"
		}
	case has(tokens, "Safari"):
		switch {
		case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") || strings.Contains(ua, "iPod"):
			a.Family = FamilySafariIOS
			if !has(tokens, "Version") {
				// iOS Safari ships with the OS, so the platform version stands in for a missing Version/.
				m := iosVersionRe.FindStringSubmatch(ua)
				if m == nil {
					return unsupported("Safari on iOS without a Version/ token or an \"OS n_n\" platform version")
				}
				major, minor, err := atoiPair(ua, "iOS platform", m[1], m[2])
				if err != nil {
					return Agent{}, err
				}
				a.Major, a.Minor = major, minor
			} else {
				product = "Version"
			}
		case strings.Contains(ua, "Macintosh"):
			a.Family, product = FamilySafariMacOS, "Version"
		default:
			return unsupported("Safari/ token without an Apple device (Macintosh, iPhone, iPad, iPod)")
		}
	default:
		return unsupported("no supported browser token (Firefox/, Chrome/, Safari/)")
	}

	if product != "" {
		if !has(tokens, product) {
			return unsupported(fmt.Sprintf("%s User-Agent without a %s/ version token", a.Family, product))
		}
		major, minor, err := tokenVersion(ua, tokens, product)
		if err != nil {
			return Agent{}, err
		}
		a.Major, a.Minor = major, minor
	}
	if !osKnown {
		return unsupported(fmt.Sprintf("%s User-Agent declares no recognized operating system", a.Family))
	}
	return a, nil
}

// Browser is the browser product a User-Agent names, whatever engine runs
// it: Chrome for iOS is BrowserChrome on OSIOS.
type Browser string

const (
	BrowserChrome  Browser = "chrome"
	BrowserEdge    Browser = "edge"
	BrowserOpera   Browser = "opera"
	BrowserWebView Browser = "webview" // Android System WebView
	BrowserSafari  Browser = "safari"
	BrowserFirefox Browser = "firefox"
)

// Classify names ua's operating system and browser product. It places
// everything Parse accepts plus the third-party iOS browsers Parse refuses
// (CriOS/, FxiOS/, EdgiOS/); anything else fails with *UnsupportedError.
func Classify(ua string) (OS, Browser, error) {
	tokens := productTokens(ua)
	for _, b := range thirdPartyIOS {
		if !has(tokens, b.token) {
			continue
		}
		if os, ok := declaredOS(ua); !ok || os != OSIOS {
			return "", "", &UnsupportedError{UserAgent: ua, Reason: fmt.Sprintf("%s/ token without an iOS device", b.token)}
		}
		return OSIOS, b.browser, nil
	}
	a, err := Parse(ua)
	if err != nil {
		return "", "", err
	}
	switch a.Family {
	case FamilyChrome:
		return a.OS, BrowserChrome, nil
	case FamilyEdge:
		return a.OS, BrowserEdge, nil
	case FamilyOpera:
		return a.OS, BrowserOpera, nil
	case FamilyAndroidWebView:
		return a.OS, BrowserWebView, nil
	case FamilySafariIOS, FamilySafariMacOS:
		return a.OS, BrowserSafari, nil
	case FamilyFirefox:
		return a.OS, BrowserFirefox, nil
	}
	return "", "", &UnsupportedError{UserAgent: ua, Reason: fmt.Sprintf("family %s names no browser", a.Family)}
}

// First value wins so a later repeat cannot override a token.
func productTokens(ua string) map[string]string {
	matches := productTokenRe.FindAllStringSubmatch(ua, -1)
	tokens := make(map[string]string, len(matches))
	for _, m := range matches {
		if _, seen := tokens[m[1]]; !seen {
			tokens[m[1]] = m[2]
		}
	}
	return tokens
}

func has(tokens map[string]string, name string) bool {
	_, ok := tokens[name]
	return ok
}

func tokenVersion(ua string, tokens map[string]string, name string) (major, minor int, err error) {
	value := tokens[name]
	m := versionRe.FindStringSubmatch(value)
	if m == nil {
		return 0, 0, &UnsupportedError{UserAgent: ua, Reason: fmt.Sprintf("%s/%s is not a major.minor version", name, value)}
	}
	return atoiPair(ua, name+"/", m[1], m[2])
}

func atoiPair(ua, what, majorDigits, minorDigits string) (major, minor int, err error) {
	major, err = strconv.Atoi(majorDigits)
	if err != nil {
		return 0, 0, &UnsupportedError{UserAgent: ua, Reason: fmt.Sprintf("%s major %q: %v", what, majorDigits, err)}
	}
	minor, err = strconv.Atoi(minorDigits)
	if err != nil {
		return 0, 0, &UnsupportedError{UserAgent: ua, Reason: fmt.Sprintf("%s minor %q: %v", what, minorDigits, err)}
	}
	return major, minor, nil
}

// Order matters: iOS UAs also say "like Mac OS X", ChromeOS UAs also say X11.
func declaredOS(ua string) (OS, bool) {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad") ||
		strings.Contains(lower, "ipod") || strings.Contains(lower, "cpu os"):
		return OSIOS, true
	case strings.Contains(lower, "android"):
		return OSAndroid, true
	case crosRe.MatchString(ua):
		return OSChromeOS, true
	case strings.Contains(lower, "windows"):
		return OSWindows, true
	case strings.Contains(lower, "macintosh") || strings.Contains(lower, "mac os x"):
		return OSMacOS, true
	case strings.Contains(lower, "linux") || strings.Contains(lower, "x11"):
		return OSLinux, true
	}
	return "", false
}
