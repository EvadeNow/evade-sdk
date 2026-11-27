# evade-sdk

Go client for the Evade solve API.

```bash
go get github.com/EvadeNow/evade-sdk
```

```go
client, err := evade.NewClient(evade.Config{
	BaseURL: "https://api.evade.now",
	APIKey:  os.Getenv("EVADE_API_KEY"),
})
```

One client serves every solver and is safe for concurrent use.

Low-level browser HTTP clients use `transport.New`. Its optional
`Config.CheckRedirect` callback observes a redirect request before transport
acquisition and controls whether it is followed. A nil callback preserves
tls-client's default redirect policy; a custom callback must enforce its own
redirect limit.

`transport.NewBrowser` binds no Accept-Language (2026-11-18; it used to
start every browser on a literal `en-US,en;q=0.9`): the caller sets
`Browser.AcceptLanguage` from its session (the located exit's locale in the
device's engine, or a stated header), and `Complete` refuses the browser
until it does.

`wireorder` orders Chromium majors past the last witnessed one (157) as 157
under HYPOTHESIS(chromium_wire_order_beyond_witnessed), falsified by a
Chrome 158+ HAR whose navigation, form or subresource order differs from
157's (2026-11-18). `wireorder.ChromiumBeyondWitnessed` names such an
engine; callers surface it as a warning. akamai, datadome and gman callers
of `wireorder` now present Chrome 158+ under this hypothesis instead of
refusing it.

Safari 26 transport follows fresh native Safari/iOS 26.6 evidence: its
ClientHello omits `session_ticket`, and HTTP/2 HEADERS omit priority. Exact
Safari 26.6.1 ClientHello and HTTP/2 behavior remain unconfirmed.

## Shape

```go
res, err := shape.Solve(ctx, client, shape.Request{
	Proxy:           "http://user:pass@1.2.3.4:8080",
	TargetURL:       "https://www.example.com/login",
	ShapeJSURL:      "https://www.example.com/assets/shape.js",
	TargetAPI:       "https://www.example.com/api/login",
	TargetAPIMethod: "POST",
})
// Send your request to TargetAPI with res.Headers added: the generated headers,
// then the device's Accept-Language, User-Agent, Accept-Encoding and UA-CH headers.
```

Afterwards, tell the API whether the target accepted it:

```go
_, err = shape.ReportOutcome(ctx, client, shape.OutcomeReport{
	SolveID: res.SolveID,
	Outcome: shape.OutcomeSuccess, // or shape.OutcomeBlocked
})
```

## DataDome

```go
tags, err := datadome.SolveTags(ctx, client, datadome.TagsRequest{
	Session: datadome.Session{
		UserAgent:      ua,
		AcceptLanguage: "en-US,en;q=0.9",
		IP:             egressIP, // the IP the target sees
	},
	CID: cid, DDK: ddk, Referer: pageURL,
	TagsType: "ch", Script: tagsJS,
})
// POST tags.Payload as the form body to DataDome's /js/ endpoint.
```

The first call opens a session. Later calls (`SolveTags`, `SolveInterstitial`,
`SolveCaptcha`) pass only `datadome.Session{SessionID: tags.SessionID}`:

```go
inter, err := datadome.SolveInterstitial(ctx, client, datadome.InterstitialRequest{
	Session:    datadome.Session{SessionID: tags.SessionID},
	DeviceLink: deviceLink,
	HTML:       interstitialHTML,
})
// POST inter.Payload to the device-check endpoint with inter.Headers added.

captcha, err := datadome.SolveCaptcha(ctx, client, datadome.CaptchaRequest{
	Session:     datadome.Session{SessionID: tags.SessionID},
	Page:        captchaHTML,
	DocumentURL: captchaURL,
	ParentURL:   pageURL,
})
// GET captcha.Payload with captcha.Headers added.
```

A tags call may state the page's counters the server otherwise defaults:
`DataDomeCookieCount` (datadome cookies the browser holds, `nddc`),
`NavigationTiming` (the page's `nt_*` members; an `le` call reuses its page's
first ones) and `BeaconPayloadCount` (an `le` beacon's `bpc`).

## Cloudflare

Challenge page (`Just a moment...`):

```go
res, err := cloudflare.Solve(ctx, client, cloudflare.Request{
	WebsiteURL: "https://www.example.com/",
	HTML:       challengeHTML,
	UserAgent:  ua,
	Proxy:      "1.2.3.4:8080:user:pass", // ip:port:user:pass
})
// Send res.Cookies on later requests, with res.UserAgent and the same proxy.
```

Turnstile:

```go
res, err := cloudflare.Solve(ctx, client, cloudflare.Request{
	WebsiteURL: "https://www.example.com/login",
	WebsiteKey: "0x4AAAAAAA...",
	UserAgent:  ua,
	Proxy:      "1.2.3.4:8080:user:pass",
})
// res.Token is the Turnstile response token.
```

## Akamai

`akamai.Session` drives one page's posts in the order the page sends them and
keeps what every call must repeat: the session token, the page URL and
User-Agent, the staged scripts (resent when the server's cache lost them), and
the device's header values. `ua` must be the User-Agent
`client.UserAgents(ctx, akamai.Task)` lists. Opening needs the proxy exit's
country and IANA zone (`geo.Reader.Locate` through the proxy gives both), or
it is refused `exit_region_missing`. `cookie` below reads your client's jar.

```go
s, err := akamai.Open(ctx, client, akamai.OpenRequest{
	URL: pageURL, UA: ua, ExitCountry: exit.CountryCode, Timezone: exit.TimeZone,
})
err = s.UploadSensorScript(ctx, sensorURL, sensorJS) // as the page fetched it
sensor, err := s.Sensor(ctx, cookie("_abck"), cookie("bm_sz"))
post, err := s.SensorPost(sensor.SensorData) // send it

err = s.UploadSBSDScript(ctx, sbsdURL, sbsdJS) // sbsdLoaded: when the page finished loading it
fp, err := s.SBSDFingerprint(ctx, cookie("bm_so"))
err = akamai.WaitForFingerprint(ctx, sbsdLoaded, fp)
post, err = s.SBSDPost(fp.Body) // send it

for {
	more, err := s.NeedsSensor(cookie("_abck")) // the _abck post-count field, at most three posts
	if err != nil || !more {
		break
	}
	sensor, err = s.Sensor(ctx, cookie("_abck"), cookie("bm_sz"))
	post, err = s.SensorPost(sensor.SensorData) // send it
}
for {
	telemetry, err := s.SBSDTelemetry(ctx, cookie("bm_so"))
	var done *akamai.Done
	if errors.As(err, &done) { // 409 complete or not due: the page sends no more
		break
	}
	post, err = s.SBSDPost(telemetry.Body) // send it
}
```

`SensorPost` and `SBSDPost` build the target requests: the sensor POST to the
sensor script URL (`{"sensor_data":…}`, `text/plain;charset=UTF-8`), the SBSD
POST to the SBSD script URL without its query (`{"body":…}`,
`application/json`), bodies escaped as the page's `JSON.stringify` escapes,
each with the device's `user-agent`, `accept-language`, `accept-encoding` and
low-entropy `sec-ch-ua`, `sec-ch-ua-mobile` and `sec-ch-ua-platform`. Add what
the page's XHR sends besides (`origin`, `referer`, `sec-fetch-*`, `priority`,
cookies), order the headers with `transport.OrderUniversal` (`ClassXHR`,
`Calls: []string{"content-type"}`) and `transport.ApplyWireOrder`, and send
through the page's own client (same proxy; `DisableCompression`, since
`accept-encoding` is set). The server holds each answer until the post's send
instant (`PacedMS` reports the hold): send at once. `WaitUntil` paces a post
sent with `Pace: false` yourself.

Every refusal is an `*akamai.Error` (unwrapping to the `*evade.APIError`):
`Code` is `/solve`'s `error_code` (the `akamai.Code*` constants) or the shared
code of an auth or quota refusal, `Stage` the server stage that refused,
`Reason` set by the 409 telemetry answers, and `Retryable` true when the same
call may succeed later. `invalid_session` and `send_instant_passed` end the
session: open a new one. `RecordID` (on `OpenRequest` and the raw requests)
names the admitted device Record a fresh session runs as; empty is the one
whose User-Agent `/user-agents` lists.

`SolveSensor`, `SolveSBSD` and `SolveOpen` are the raw calls under `Session`,
with the request and response structs as the server reads and writes them.

## reCAPTCHA (task `recaptcha`)

The configured production origin for this solver is
`https://gman.evade.now`; configure a client for that origin rather than
assuming another solver's API origin routes reCAPTCHA:

```go
rcClient, err := evade.NewClient(evade.Config{
	BaseURL: "https://gman.evade.now", APIKey: os.Getenv("EVADE_API_KEY"),
	Timeout: 120 * time.Second, MaxRetries: new(0),
})
if err != nil {
	return err
}
uas, err := rcClient.UserAgents(ctx, recaptcha.Task)
if err != nil {
	return err
}
if len(uas) == 0 {
	return fmt.Errorf("no supported reCAPTCHA User-Agents")
}
// Use this complete HTTP UA string, not a version number or device label.
ua := uas[0]
res, err := recaptcha.Solve(ctx, rcClient, recaptcha.Request{
	URL: "https://www.example.com/login", SiteKey: "REPLACE_WITH_PAGE_SITEKEY",
	Action: "login", UserAgent: ua, Proxy: os.Getenv("EVADE_PROXY"),
	Version: recaptcha.VersionV3, Enterprise: new(false),
})
if err != nil {
	return err
}
// Submit res.Token in the page's own form/header/JSON field, once and
// promptly, using the same full ua, proxy exit and target-page cookies.
```

This standard-v3 example needs a real page URL/key/action and working
`EVADE_PROXY` (for example `http://user:pass@host:port`); the replacement
sitekey is not usable. The API key needs reCAPTCHA access and `solve`
scope. All solves require `URL`, `SiteKey`, full `UserAgent` and `Proxy`;
the SDK adds `task: "recaptcha"`. UA listing is unmetered and describes
current support, not score ranking. No universally best UA is established.

`Version` is `v3` by default or `v2-invisible`. `v2-checkbox` is accepted
syntactically but cannot run on the public route: its witnessed first-party
context is unavailable (`502 solve_failed`). Visible image challenges are
refused (`422 challenged` / `challenge_unsupported`); the public route has
no image solver. There is no public `data-s` workaround.

`Enterprise` selects the loader surface (`true`: enterprise.js, `false`:
api.js) unless a loader is discovered in supplied `PageHTML`/`PageScripts`,
which wins. When neither is stated, a nonempty `Action` defaults to
enterprise. **Standard v3 sites with an action must explicitly set
`Enterprise: new(false)` absent a page loader.** Send the exact action the
page uses; omit it when none. `Host` defaults to `www.google.com` and also
accepts `recaptcha.net` / `www.recaptcha.net`; it is the loader host, not the
target hostname. There is no `apiDomain` field.

### Optional observed page facts

The server never fetches the target page. Without page facts it uses the
URL and its fetched reCAPTCHA loader; page scripts are **not mandatory**
for a plain source-only request. To supply a fuller page context, obtain
the page through your own client using the same UA/proxy, then
`recaptcha.PageScripts(pageURL, page, siteKey)` lists classic scripts in
document order. Fetch each external script whose `Body` is nil before
passing it; `[]byte` bodies encode as base64 JSON. `PageHTML` is the
document at execute (including inserted markup), not a different site's
template. `PageScript.Inserted` marks source added after initial load.

| Request fields | Meaning / omission |
|---|---|
| `Referrer`, `ReferrerPolicy` | Navigation referrer and observed response policy. Empty policy uses origin-only cross-origin referer; `no-referrer` / `same-origin` suppress it. Full-URL policies are refused. |
| `PageProtocol` | Actual navigation protocol, `h2` default / `http/1.1` / `h3`. |
| `FrameAssets` | `true` fetches the anchor webworker, not all frame assets; false/omission is the default. |
| `ExecuteAfterReady` | `nil` unstated; `new(false)` and `new(true)` preserve the actual execute/readiness fact. Not a wait-duration knob. |
| `PriorReleaseLoad` | Earlier release in this browser session; nil lets the live flow derive its fresh lifecycle. Offline/lab requirements do not add a mandatory public field. |
| `TokenCallback` | Callback source as served; nil unstated, `new("")` explicitly none. |
| `PageStylesheets` | Linked stylesheet URLs and source bodies in document order; absent bodies can produce `domains_partial` in the raw API response. |
| `Popup`, `PageNavigationMS` | `window.open` size and elapsed navigation clock. |
| `PageLoad` | Measured `loaderMs`, optional `blockingDoneMs`/`elapsedMs`, all on one navigation clock; mutually exclusive with nonzero `PageNavigationMS`. |
| `PageCookieNames` | Pointer to document.cookie names, not values or HttpOnly cookies. Nil unstated; pointer to empty slice explicitly none. |
| `PageElements`, `PageMutations` | Per-mint page-handler element state and observed DOM mutation windows (reload then bcn), not visitor interaction overrides. |
| `ValuedFields`, `TypedChars` | Per-mint nonempty input names and cumulative typed-character counts; stated empty inner field list / zero count are preserved. |
| `PageHistoryLength` | Pointer to actual history length, at least one. |
| `GoogleStorageKeys`, `AnchorSeen` | Both or neither; pointers preserve zero/false. |
| `PageHeap` | Actual fresh-page heap band and witnessed growth range, not a score preset. |

Do not supply private `profileId`, `region`, `research`, `synchronous`, or
caller interaction plans. They are not SDK request fields or public tuning
controls. Accurate page facts are not a Google-score guarantee.

### Result and errors

The call returns the token in one HTTP response; mandatory clr/bcn
telemetry may finish afterwards on the server. `Score` is always nil
(`score: null`), since only the site's server-side verification sees the
score. `Verification` is normally nil and is not proof of site acceptance
or public image solving. `ProfileID` is the selected device's output id,
not a public request selector. `GenMS` times native minting and reload-body
serialization only: own decode, device/exit lookup, waits and network are
excluded. Measure your own wall time for end-to-end latency.

`Solve` validates required fields/version/host locally, plus supplied
script bodies; optional page-fact relationships are validated by the
server. Errors are `*recaptcha.Error`, wrapping `*evade.APIError` for server
refusals. `site_unsupported` can mean unsupported page laws, not just a
wrong widget; do not automatically change versions. Quota exhaustion is
`429 quota_exceeded`, rate limiting `429 rate_limited`; auth is normal
bearer-key auth. `Retryable` is advisory, not an automatic solve retry.

The generic client defaults to a 60-second HTTP timeout and three retries
for 429/503. The example explicitly chooses 120 seconds and no retries;
that is a caller choice, **not** a server whole-flow deadline or a speed
promise. There is no public timeout/retry/synchronous field in solve JSON.
Only successful token issuance is billed; issuance is not site acceptance.

## User-Agents

Each solver lists the exact User-Agents its `/solve` runs on
(`GET /user-agents`). Pass one of them as the solve's User-Agent:

```go
all, err := client.UserAgents(ctx, shape.Task)
iphones, err := client.UserAgents(ctx, shape.Task, evade.IosSafari, evade.IosChrome)
desktop, err := client.UserAgents(ctx, datadome.Task, "windows", "macos")
akamaiUA, err := client.UserAgents(ctx, akamai.Task)
```

Named filters cover the common platforms: `Ios`, `IosSafari`, `IosChrome`,
`Mac`, `MacSafari`, `MacChrome`, `Windows`, `WindowsChrome`, `Android`,
`AndroidChrome`. A platform's own name is its default browser: `Ios` is
`IosSafari`, `Mac` is `MacSafari`, `Windows` and `Android` are their Chrome.

A filter is an OS (`windows`, `macos`, `linux`, `chromeos`, `android`, `ios`),
a browser (`chrome`, `safari`, `firefox`, `edge`, `opera`, `webview`), or
`<os>_<browser>` (`ios_safari`, `ios_chrome`, `macos_chrome`, ...). Several
filters keep values matching any of them, in the server's order; none keeps
all. `ios_chrome` is Chrome for iOS (`CriOS`). An unknown filter fails before
any request. While filtering, a listed User-Agent the SDK cannot classify fails
the call instead of being dropped.

## Retries

The client retries a request answered `429` or `503` (nothing else) and re-sends
the identical body each time:

- `Config.MaxRetries` (`*int`): retries after the first attempt. `nil` means 3,
  `new(0)` disables retrying, negative is a config error.
- `Config.MaxBackoff`: caps each wait; zero means 30 s. Without `Retry-After`
  the wait is exponential backoff with full jitter: uniform in
  `[0, min(MaxBackoff, 500ms × 2^(retry-1)))`.
- `Retry-After` (seconds or HTTP-date) is the wait when present. A hint longer
  than `MaxBackoff` is not waited out: the call returns the `*APIError`, whose
  `RateLimit.RetryAfter` says when to come back.
- `429 quota_exceeded` without `Retry-After` is an exhausted balance and is
  never retried.
- A wait that would pass the context deadline is not started: the call returns
  the last `*APIError`. Cancelling the context during a wait returns an error
  wrapping both the context error and that `*APIError`.

## Errors

A failed solve returns `*evade.APIError`. `Attempts` is how many requests were
sent, so above 1 the client already backed off:

```go
var apiErr *evade.APIError
if errors.As(err, &apiErr) && apiErr.RateLimit.RetryAfter > 0 {
	// The server's next-attempt hint, longer than MaxBackoff or past the deadline.
	time.Sleep(apiErr.RateLimit.RetryAfter)
}
```
