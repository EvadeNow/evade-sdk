package wireorder

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	chromeMajorPattern   = regexp.MustCompile(`Chrome/([0-9]+)\.`)
	safariVersionPattern = regexp.MustCompile(`Version/([0-9]+)(?:\.([0-9]+))?(?:\.[0-9]+)* (?:Mobile/[A-Za-z0-9]+ )?Safari/`)
	iosVersionPattern    = regexp.MustCompile(`(?:iPhone|CPU) OS ([0-9]+)_([0-9]+)`)
	iosDevicePattern     = regexp.MustCompile(`\((?:iPhone|iPad|iPod)\b`)
)

// EngineFromUserAgent reads a UA's engine; WebKit is witnessed on iOS (iPhone/iPad/iPod token, CriOS as a WebView),
// macOS Safari reads as iOS Safari of its Version/ release, anything else lawless is EngineUnknown.
func EngineFromUserAgent(ua string) Engine {
	for _, brand := range []string{"Edg/", "OPR/", "SamsungBrowser/", "FxiOS/", "EdgiOS/", "Firefox/"} {
		if strings.Contains(ua, brand) {
			return Engine{}
		}
	}
	if strings.Contains(ua, "CriOS/") {
		match := iosVersionPattern.FindStringSubmatch(ua)
		if match == nil || !iosDevicePattern.MatchString(ua) {
			return Engine{}
		}
		return engineVersion(WebKit, match[1], match[2], true)
	}
	if match := chromeMajorPattern.FindStringSubmatch(ua); match != nil {
		return engineVersion(Chromium, match[1], "", false)
	}
	// HYPOTHESIS(webkit_macos_is_ios_late): macOS Safari orders its requests as iOS Safari of the same Version/
	// release (26.6.2 -> late); no macOS wire capture exists. Falsified by a live BLOCK/refusal on a macOS Safari device.
	if match := safariVersionPattern.FindStringSubmatch(ua); match != nil && (iosDevicePattern.MatchString(ua) || strings.Contains(ua, "(Macintosh;")) {
		return engineVersion(WebKit, match[1], match[2], false)
	}
	return Engine{}
}

func engineVersion(kind EngineKind, major, minor string, webView bool) Engine {
	m, err := strconv.Atoi(major)
	if err != nil {
		return Engine{}
	}
	n := 0
	if minor != "" {
		if n, err = strconv.Atoi(minor); err != nil {
			return Engine{}
		}
	}
	return Engine{Kind: kind, Major: m, Minor: n, WebView: webView}
}
