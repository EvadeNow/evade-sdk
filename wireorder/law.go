package wireorder

// law is shared by every caller; nothing may mutate it.
var law = &lawFile{
	Forbidden: []string{"accept-charset", "accept-encoding", "access-control-request-headers", "access-control-request-method", "connection", "content-length", "cookie", "cookie2", "date", "dnt", "expect", "host", "keep-alive", "origin", "referer", "set-cookie", "te", "trailer", "transfer-encoding", "upgrade", "via"},
	Chromium: chromiumLaw{
		Witnessed:     [2]int{141, 155},
		BlinkSetOrder: []string{"user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-form-factors"},
		HTTP1Prefix:   []string{"host", "connection"},
		NetworkAfter:  []string{"origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "sec-fetch-storage-access", "referer"},
		NetworkTail:   []string{"accept-encoding", "accept-language", "cookie"},
		Pseudo:        []string{":method", ":authority", ":scheme", ":path"},
		HintCounterwitnesses: []HintCounterwitness{
			{
				Name:   "sec-ch-ua-full-version",
				HAR:    "axs-2",
				Entry:  14,
				Reason: "Accept-CH-requested classic script whose Blink map has sec-ch-ua-full-version before user-agent (also axs-3#5, axs-latest#11); every other hint set reproduces",
			},
		},
		Navigation: chromiumNavigation{
			ClientHints: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"},
			BrowserSet:  []string{"upgrade-insecure-requests", "user-agent", "accept"},
		},
		Form: chromiumForm{
			Prefix: []string{"content-length", "cache-control"},
			Majors: []chromiumFormMajors{
				{From: 141, To: 141, BrowserSet: []string{"origin", "content-type", "upgrade-insecure-requests", "user-agent", "accept"},
					Witnesses: []string{"xfinity_login_android-chrome141_1_0907#372"}},
				// Chrome 155 forms are witnessed only with an automation Accept-Language override (bandai-jp-login-evidence-20261020c#275), whose accept-language precedes accept.
				{From: 150, To: 155, BrowserSet: []string{"upgrade-insecure-requests", "content-type", "user-agent", "origin", "accept"},
					Witnesses: []string{"bandai-us_login_android-chrome150_1_0828#217", "bandai-jp_product_windows-chrome151_1_0809#54", "bandai-login13#182", "vint#188", "chess-login#174", "prizepicks#186"}},
			},
		},
		// Every captured Chrome 141-155 preflight (348: target_register_android-chrome151_1_0831#265, sky_login_android-chrome151_1_0901#60 on HTTP/1.1, bandai-login12#8 without referer).
		Preflight: []string{"accept", "access-control-request-method", "access-control-request-headers", "origin", "user-agent", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "referer", "accept-encoding", "accept-language"},
	},
	WebKit: webkitLaw{
		CommonHeaders: []string{"accept", "accept-charset", "accept-language", "accept-encoding", "accept-ranges", "access-control-allow-credentials", "access-control-allow-headers", "access-control-allow-methods", "access-control-allow-origin", "access-control-expose-headers", "access-control-max-age", "access-control-request-headers", "access-control-request-method", "age", "authorization", "cache-control", "clear-site-data", "connection", "content-disposition", "content-encoding", "content-language", "content-length", "content-location", "content-security-policy", "content-security-policy-report-only", "content-type", "content-range", "cookie", "cookie2", "cross-origin-embedder-policy", "cross-origin-embedder-policy-report-only", "cross-origin-opener-policy", "cross-origin-opener-policy-report-only", "cross-origin-resource-policy", "date", "dnt", "default-style", "document-isolation-policy", "etag", "expect", "expires", "host", "if-match", "if-modified-since", "if-none-match", "if-range", "if-unmodified-since", "integrity-policy", "integrity-policy-report-only", "keep-alive", "last-event-id", "last-modified", "link", "location", "origin", "origin-agent-cluster", "ping-from", "ping-to", "pragma", "proxy-authorization", "range", "referer", "referrer-policy", "refresh", "report-to", "reporting-endpoints", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-gpc", "sec-purpose", "sec-speculation-tags", "speculation-rules", "sec-websocket-accept", "sec-websocket-extensions", "sec-websocket-key", "sec-websocket-protocol", "sec-websocket-version", "server-timing", "service-worker", "service-worker-allowed", "service-worker-navigation-preload", "set-cookie", "set-cookie2", "sourcemap", "te", "timing-allow-origin", "trailer", "transfer-encoding", "upgrade", "upgrade-insecure-requests", "use-as-dictionary", "user-agent", "vary", "via", "x-content-type-options", "x-frame-options", "x-sourcemap", "x-xss-protection", "x-temp-tablet", "icy-metaint", "icy-metadata"},
		LoaderAdded:   []string{"origin", "user-agent", "referer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"},
		CFNetworkTail: []string{"accept-language", "priority", "accept-encoding", "cookie"},
		Unresolved:    []string{"authorization"},
		Pseudo:        []string{":method", ":scheme", ":authority", ":path"},
		HTTP1Prefix:   []string{"host"},
		HTTP1Suffix:   []string{"connection"},
		Counterwitness: []Counterwitness{
			{
				HAR:        "target_login_iphone12-safari18.7_1_0910",
				Entry:      404,
				Dictionary: []string{"accept", "sec-fetch-site", "sec-fetch-mode", "user-agent", "accept-language", "sec-fetch-dest"},
				Reason:     "no CF insertion history reproduces this top-level navigation's dictionary",
			},
		},
		UnwitnessedClasses: map[string]string{
			"navigation": "Safari orders one top-level navigation dictionary more than one way within one version (18.7.5, 26.2, 26.5 captures: sec-fetch-dest,user-agent,... and accept,sec-fetch-site,... on the same names); no capture decides which",
			"script":     "a parser-requested classic script (HTML parser or preload scanner) is ordered sec-fetch-dest,user-agent on 18.7.5/26.2/26.5 and user-agent,sec-fetch-dest during the early page load on 26.6.1 (target_cart_iphone17-safari26.6_1_1006/3); only the JS-inserted script law (inserted_script) is certified",
		},
		InsertedScript: webkitInsertedScript{
			Insertion: []string{"accept", "referer", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "user-agent"},
			Counterwitness: []Counterwitness{
				{
					HAR:        "target_cart_iphone17-safari26.6_1_1006",
					Entry:      130,
					Dictionary: []string{"user-agent", "sec-fetch-dest", "accept", "referer", "sec-fetch-site", "sec-fetch-mode"},
					Reason:     "Safari 26.6.1 Shape VM fetched 63 ms after the document, inside the early-load burst whose every request puts user-agent before sec-fetch-dest; the session's later VM fetch (entry 192) and target_cart_iphone17-safari26.6_2_1006#184 reproduce the law",
				},
			},
		},
		// Reproduces all 157 captured late navigations of these names, 31 of them redirect hops (target_login_iphone12-safari18.7_1_0910#39, #320,
		// #404), and 1946 of 2052 parser scripts and no-cors element loads; the rest are 62 redirected loads, which
		// OrderUniversal does not frame, and the 26.6.1 early-load burst's 44 (InsertedScript.Counterwitness's
		// user-agent first, target_cart_iphone17-safari26.6_1_1006#7).
		BrowserLoad: webkitBrowserLoad{
			Insertion:       []string{"accept", "upgrade-insecure-requests", "referer", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "user-agent"},
			RedirectCarried: []string{"accept-language", "priority"},
			Reinserted:      []string{"sec-fetch-mode"},
		},
		// Reproduces all 413 captured late Safari preflights (target_login_iphone15-safari26.5_1_0909#394, morerewards_login_iphone-safari18.7_2_1020#127).
		Preflight: webkitPreflight{
			Insertion: []string{"access-control-request-method", "access-control-request-headers", "origin", "user-agent", "referer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "content-length"},
			Tail:      []string{"accept"},
		},
		Generations: []webkitGeneration{
			{
				Name: "early",
				Builds: []webkitBuilds{
					{
						From: [2]int{18, 0},
						To:   [2]int{18, 1},
					},
					{
						WebView: true,
						From:    [2]int{18, 0},
						To:      [2]int{18, 1},
					},
				},
				Witnesses: []GenerationWitness{
					{
						HAR:       "ios18-safari-14",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-crios-14",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-13",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-13pm",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Mobile/15E148 Safari/604.1",
					},
				},
				Inside: []string{"accept-language", "accept-encoding"},
				Tail:   []string{"cookie"},
				// Every navigation and script of the early sessions (s-live testdata/webkit_generation_witness.json).
				BrowserGet: []string{"accept", "sec-fetch-site", "sec-fetch-dest", "accept-language", "sec-fetch-mode", "user-agent", "referer", "accept-encoding"},
			},
			{
				Name: "early-webview",
				Builds: []webkitBuilds{
					{
						WebView: true,
						From:    [2]int{18, 4},
						To:      [2]int{18, 7},
					},
				},
				Witnesses: []GenerationWitness{
					{
						HAR:       "ios18-crios-16",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-crios-13",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-crios-16",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
					},
				},
				Inside: []string{"accept-language", "accept-encoding", "cookie"},
				Tail:   []string{},
				// ios18-crios-16#21; cookie, inside on these builds, last: HYPOTHESIS(webkit-early-browser-get).
				BrowserGet: []string{"accept", "sec-fetch-site", "sec-fetch-dest", "accept-language", "sec-fetch-mode", "user-agent", "referer", "accept-encoding", "cookie"},
			},
			{
				Name: "law",
				Builds: []webkitBuilds{
					{
						From: [2]int{18, 3},
						To:   [2]int{18, 4},
					},
					{
						WebView: true,
						From:    [2]int{26, 6},
						To:      [2]int{28, 0},
					},
				},
				Witnesses: []GenerationWitness{
					{
						HAR:       "ios26-crios-15",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-crios26-15",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-crios27-15",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.137 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-14",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-14b",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-16e",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
					},
				},
				Inside:       []string{},
				Tail:         []string{"accept-language", "priority", "accept-encoding", "cookie"},
				Priority:     true,
				InsertionLaw: true,
				ScriptLaw:    true,
				PageSetTail:  true,
			},
			{
				Name: "late",
				Builds: []webkitBuilds{
					{
						From: [2]int{18, 4},
						To:   [2]int{19, 0},
					},
					{
						From: [2]int{26, 0},
						To:   [2]int{28, 0},
					},
				},
				Witnesses: []GenerationWitness{
					{
						HAR:       "target_cart_iphone12-safari18.7_1_1006",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "target_login_iphone13-safari26.2_1_0912",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "target_login_iphone15-safari26.5_1_0909",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "target_cart_iphone17-safari26.6_1_1006",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.1 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "ios26-https-2",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "control-ios26-b",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "target-ios27",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "ios18-safari-16",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "ios26-safari-15",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-16",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-16plus",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-16pm",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari-16pro",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari26-15",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1",
					},
					{
						HAR:       "probe-safari27-15",
						UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1",
					},
				},
				Inside:       []string{},
				Tail:         []string{"accept-language", "priority", "accept-encoding", "cookie"},
				Priority:     true,
				InsertionLaw: true,
				ScriptLaw:    true,
				Counterwitness: []Counterwitness{
					{
						HAR:        "probe-safari-16",
						Entry:      19,
						Dictionary: []string{"accept", "x-beta", "sec-fetch-site", "sec-fetch-mode", "x-alpha", "user-agent", "referer", "sec-fetch-dest"},
						Reason:     "Safari 18.4-27.0 place this XHR's and fetch's page uncommons between their commons (every late iOS probe session, xhr-bare and fetch-bare); no history with WebKit's commons before its uncommons reaches it, and the law's one outcome is the law generation's order",
					},
				},
			},
		},
	},
}
