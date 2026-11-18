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

`ua` must be the User-Agent `client.UserAgents(ctx, akamai.Task)` lists. The
first sensor call opens a session:

```go
req := akamai.SensorRequest{
	URL:       pageURL,
	UA:        ua,
	Abck:      abck,     // _abck cookie
	BmSz:      bmSz,     // bm_sz cookie
	ScriptID:  scriptID, // hex SHA-256 of sensorJS
	ScriptURL: sensorURL,
}
sensor, err := akamai.SolveSensor(ctx, client, req)
var apiErr *evade.APIError
var body akamai.ErrorResponse
if errors.As(err, &apiErr) && json.Unmarshal([]byte(apiErr.Message), &body) == nil &&
	body.ErrorCode == "script_cache_miss" {
	req.Script = sensorJS // the server lacks the script: resend its source
	sensor, err = akamai.SolveSensor(ctx, client, req)
}
// POST {"sensor_data": sensor.SensorData} to sensorURL with sensor.UA, sensor.Language,
// sensor.AcceptEncoding and every non-empty sensor.ClientHints value added.
```

Later sensor and SBSD calls pass `Session: sensor.Session`:

```go
sbsd, err := akamai.SolveSBSD(ctx, client, akamai.SBSDRequest{
	URL:       pageURL,
	UA:        ua,
	Script:    sbsdJS,
	ScriptURL: sbsdURL,
	SBSDo:     bmSo, // bm_so cookie
	Session:   sensor.Session,
})
// POST {"body": sbsd.Body} to sbsdURL without its query.
```

`/solve`'s own failures are not the shared error envelope: they return
`*evade.APIError` with an empty `Code` and the `akamai.ErrorResponse` JSON in
`Message`. Auth and quota refusals carry `Code` as for every solver.

## reCAPTCHA (task `recaptcha`)

Synchronous: the server runs the whole reCAPTCHA flow (loader, release,
anchor, reload, clr, bcn; for v2 invisible the bframe and userverify) over
your proxy as `UserAgent` and answers the token; it never fetches your page —
the token binds to `URL`'s origin and `Action`. `ua` must be a User-Agent
`client.UserAgents(ctx, recaptcha.Task)` lists.

```go
res, err := recaptcha.Solve(ctx, client, recaptcha.Request{
	URL:        "https://www.example.com/checkout", // the page the token is for
	SiteKey:    "6Lc…",                             // the sitekey the page renders
	Action:     "checkout",
	UserAgent:  ua,
	Proxy:      "http://user:pass@host:port",
	Version:    recaptcha.VersionV3, // or recaptcha.VersionV2Invisible; empty is v3
	Enterprise: new(true),           // the page loads enterprise.js (false: api.js)
})
// res.Token is the rresp token; res.Score and res.Verification are nil.
```

There is one task name, `recaptcha`; the widget is `Version` (`v3` default,
`v2-invisible`) and the surface — enterprise (loader `enterprise.js`) or api2
(loader `api.js`) — is resolved by the server: the loader the page states
when the page reaches the solver (the SDK request carries no page, so this
rule applies to in-house callers only), else `Enterprise`, else a hypothesis:
an `Action` means enterprise. api2 sites with an action exist, so set
`Enterprise` whenever you know the page's loader. `v2-invisible` on api2 is
refused `no_witness` (no capture of that pair yet). The loader is fetched from
www.google.com; `Host: "recaptcha.net"` selects the other API host (the site
never observes which host served its widget; both issue the same token).
`score` is never answered: it is not observable client-side (only the site's
own siteverify call sees it). Refusals are `*evade.APIError` with
`invalid_request` (a malformed field, an unknown task, version or host, a
non-boolean `enterprise`), `device_unsupported`, `site_unsupported`,
`no_witness`, `generation_failed` (decoder refusal or a SHORT token),
`proxy_failed`, `proxy_timeout`, `target_error`, `solve_canceled` or
`solve_failed`.

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
