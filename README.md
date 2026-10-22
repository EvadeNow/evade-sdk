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

## Shape

```go
res, err := shape.Solve(ctx, client, shape.Request{
	Proxy:           "http://user:pass@1.2.3.4:8080",
	TargetURL:       "https://www.example.com/login",
	ShapeJSURL:      "https://www.example.com/assets/shape.js",
	TargetAPI:       "https://www.example.com/api/login",
	TargetAPIMethod: "POST",
})
// Send your request to TargetAPI with res.Headers added.
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

## User-Agents

Each solver lists the exact User-Agents its `/solve` runs on
(`GET /user-agents`). Pass one of them as the solve's User-Agent:

```go
all, err := client.UserAgents(ctx, shape.Task)
iphones, err := client.UserAgents(ctx, shape.Task, evade.IosSafari, evade.IosChrome)
desktop, err := client.UserAgents(ctx, datadome.Task, "windows", "macos")
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
