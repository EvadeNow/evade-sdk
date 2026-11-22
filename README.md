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

Synchronous: the server runs the whole reCAPTCHA flow (loader, release,
anchor, reload, clr, bcn; for v2 invisible the bframe and userverify, an
image challenge solved server-side) over your proxy as `UserAgent` and
answers the token. It never fetches your page: you send the page (`PageHTML`)
and its classic scripts (`PageScripts`), which the token's page share is read
from; a v3 solve without them fails `site_unsupported`. A Squarespace login
(v3 enterprise, action `login`), with `get` and `post` your own client on the
solve's proxy as `ua`:

```go
uas, err := client.UserAgents(ctx, recaptcha.Task)
ua, proxyURL := uas[0], "http://user:pass@host:port"

// 1. The page, through the proxy as ua; pageURL is where its redirects end.
pageURL, page := get("https://login.squarespace.com/")

// 2. The sitekey its loader renders; the action is the page bundle's.
loader := regexp.MustCompile(`enterprise\.js\?render=([0-9A-Za-z_-]+)`)
siteKey := loader.FindStringSubmatch(page)[1]

// 3. Its classic scripts in order; fetch the external ones the same way.
scripts, err := recaptcha.PageScripts(pageURL, page, siteKey)
for i := range scripts {
	if scripts[i].Body == nil {
		_, body := get(scripts[i].Name)
		scripts[i].Body = []byte(body)
	}
}

// 4. Solve.
res, err := recaptcha.Solve(ctx, client, recaptcha.Request{
	URL: pageURL, SiteKey: siteKey, Action: "login", UserAgent: ua, Proxy: proxyURL,
	Version: recaptcha.VersionV3, Enterprise: new(true), Host: "www.google.com",
	PageHTML: page, PageScripts: scripts,
})

// 5. Submit where the page does, same proxy and ua, within two minutes:
// Squarespace's JSON login POST carries it as squarespace-recaptcha-token.
answer := post("https://login.squarespace.com/api/1/login/user", loginJSON,
	"squarespace-recaptcha-token", res.Token)
```

Other pages take the token as the `g-recaptcha-response` form field or a
member of their own JSON call. `Proxy` is `scheme://user:pass@host:port`
(http, https, socks4, socks4a, socks5, socks5h) or `host:port:user:pass`.

There is one task name, `recaptcha`; the widget is `Version` (`v3` default,
`v2-invisible`, `v2-checkbox`; the checkbox is witnessed only on the
www.google.com/sorry first-party page, which `Solve` does not run, so it fails
`solve_failed`) and the surface — enterprise (loader `enterprise.js`) or api2
(loader `api.js`) — is resolved by the server: the loader the page states
when `PageHTML` or `PageScripts` carry it, else `Enterprise`, else a
hypothesis: an `Action` means enterprise. api2 sites with an action exist, so
set `Enterprise` whenever you know the page's loader. `Referrer`, `Popup` and
`PageNavigationMS` add the navigation's referrer, a popup window's size and
how long before the solve the page navigation started. The loader is fetched
from www.google.com; `Host: "recaptcha.net"` selects the other API host (the
site never observes which host served its widget; both issue the same
token). `score` is never answered: it is not observable client-side (only the
site's own siteverify call sees it). `Verification` is informational: nil, or
the image challenge the server answered (class, rounds, tiles); the token
already carries it. `ProfileID` names the stored device profile the solve ran
as.

`Solve` first runs `Request.Validate`, which refuses what the server would,
with its messages (an unknown version or host, an empty `URL`, `SiteKey`,
`UserAgent` or `Proxy`, a non-https `URL`), and a page script left unfetched.
Every refusal is a `*recaptcha.Error` with the server's code
(`invalid_request`, `device_unsupported`, `site_unsupported`,
`generation_failed`, `challenged`, `challenge_unsolved`, `proxy_failed`,
`proxy_timeout`, `target_error`, `storage_unavailable`, `solve_canceled`,
`solve_failed`, and the auth and quota codes), unwrapping to the
`*evade.APIError`; `Retryable` is true for `proxy_failed` and `proxy_timeout`
(with a fresh proxy endpoint), `storage_unavailable`, `quota_unavailable` and
`rate_limited`.

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
