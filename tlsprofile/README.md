# tlsprofile

`Resolver.Resolve` gives a browser the tls-client built-in profile of its network stack: the newest profile of the
stack whose major is at most the browser's release major. `transport.NewBrowser` binds it with the stack's
Accept-Encoding. A family on no modeled stack, or a release older than every profile of its stack, fails with
`*NoProfileError` naming the family; a User-Agent `useragent.Parse` cannot place fails with
`*useragent.UnsupportedError`.

## The rule (tls-client v1.18.1)

| Family | Releases | Profile | Accept-Encoding |
|---|---|---|---|
| Every Chromium shell (Chrome, Edge, Opera, Samsung Internet, Yandex, Android WebView, ...) on Windows, macOS, Linux, ChromeOS, Android | Chromium 154 and later | `chrome_154` | `gzip, deflate, br, zstd` |
| same | Chromium 103–153 | `chrome_<newest at most the Chromium major>` (151 → `chrome_150`, 153 → `chrome_152`) | `gzip, deflate, br, zstd` from 123, else without `zstd` |
| Safari on iPhone, iPad and Mac; Chrome, Edge and Firefox for iOS (CriOS/, EdgiOS/, FxiOS/: Apple's WebKit, read at their iOS release) | 26 and later | `safari_ios_26_0` | `gzip, deflate, br, zstd` from 26.4, else without `zstd` |
| same | 18.x | `safari_ios_18_5` | `gzip, deflate, br` |
| same | 15–17 | `safari_ios_<newest at most the major>` (17 → `safari_ios_17_0`, 16 → `safari_ios_16_0`, 15 → `safari_ios_15_6`) | `gzip, deflate, br` |
| Firefox on every OS | 102 and later | `firefox_<newest at most the major>` (148 and later → `firefox_148`) | `gzip, deflate, br, zstd` from 126, else without `zstd` |
| Any other family, or an older release | | `*NoProfileError` | |

The rule reads the registry, not a table: when tls-client ships `chrome_158`, Chromium 158 and later take it.
Every Chromium shell sends Chromium's BoringSSL hello, so the Chromium major alone picks the profile. Every
Chromium family needs its fingerprint's client hints before a request leaves (`transport.Browser.Complete`).

## Evidence

`testdata/<fixture>.json` are verbatim `https://tls.peet.ws/api/all` echoes of a top-level navigation on real
BrowserStack devices, all captured 2026-11-17. `GOWORK=off go test -tags witness ./tlsprofile/` (`device_test.go`)
replays each fixture's User-Agent and headers through `transport.NewBrowser` and `transport.New` against a local
TLS server and compares JA4 and JA4_r, cipher order, extension order (as a set where Chrome permutes it), supported
groups, point formats, peetprint, key-share groups and sizes, ALPS, the HTTP/2 Akamai fingerprint (SETTINGS and
order, WINDOW_UPDATE, PRIORITY frames, pseudo-header order), the HEADERS stream and priority, and Accept-Encoding.
Each row states the fields that differ; the witness fails when that set changes (a tls-client upgrade, a new
fixture). It is a regression witness, not a gate on the resolver.

| Fixture (BrowserStack device) | Profile | Differs on |
|---|---|---|
| `chrome-macos-154`, `-155`, `-156`, `-157` (OS X Tahoe); `chrome-windows-157` (Windows 11) | `chrome_154` | nothing: Chromium's ClientHello and HTTP/2 preface did not change from 154 to 157 |
| `edge-windows-157` (Windows 11, Edge 157) | `chrome_154` | trust_anchors (0xca34) absent where `chrome_154` sends it (JA4, extension set, peetprint) |
| `chrome-macos-151` (OS X Tahoe) | `chrome_150` | trust_anchors absent, as on Edge 157 |
| `chrome-macos-152` (OS X Tahoe); `chrome-android-152` (Pixel 10, Android 16; Galaxy S26 and Pixel 11 sent the same bytes) | `chrome_152` | nothing (their 32-anchor list against `chrome_152`'s 28 is not compared) |
| `safari-macos-26.4` (OS X Tahoe), `safari-ios-26.6` (iPhone 17), `safari-ipad-desktop-26.6.1` (iPad Air 13 2025), `safari-ios-27.2` (iPhone 18 Pro), `chrome-ios-149-ios-26.6` (iPhone 17, Chrome for iOS 149) | `safari_ios_26_0` | nothing: one Safari 26 stack on iPhone, iPad and Mac, Chrome for iOS included |
| `safari-ios-18.4.1` (iPhone 16 Pro), `-18.5` (iPhone 16), `-18.6` (iPhone 16 Plus) | `safari_ios_18_5` | nothing |
| `safari-ios-18.3` (iPhone 16e) | `safari_ios_18_5` | HTTP/2 SETTINGS: the device adds ENABLE_CONNECT_PROTOCOL (8:1) |
| `safari-ios-18.0.1` (iPhone 13 Pro Max) | `safari_ios_18_5` | the device adds the `ecdsa_sha1` signature algorithm; HTTP/2 SETTINGS order, WINDOW_UPDATE, pseudo-header order (m,s,p,a) and HEADERS weight |
| `safari-ipad-desktop-16.0` (iPad 10th, desktop mode, Macintosh User-Agent) | `safari_ios_16_0` | HEADERS priority: not exclusive, weight 255 |
| `firefox-windows-148` (Windows 11) | `firefox_148` | `firefox_148` adds DHE suites 0x0033/0x0039; HEADERS on stream 1 (Firefox: 3) |
| `firefox-windows-160` (Windows 11) | `firefox_148` | as 148, and Firefox 160 dropped the ECDSA CBC suites and the ffdhe groups |

trust_anchors is non-identifying: whether Chrome sends it, and the anchor list it carries, follow Chrome's
component updates on the device rather than the browser build (151 and Edge 157 without it, 152 with 32 anchors,
154–157 with `chrome_154`'s), so the witness compares neither the list nor counts its absence as another profile.

Accept-Encoding, one rule per stack: every Safari 18.x and 16.0 echo sends `gzip, deflate, br`; every Safari 26.4
to 27.2 echo (iPhone, iPad, Mac, Chrome for iOS) adds `zstd`; every Chromium and Firefox echo sends
`gzip, deflate, br, zstd`. Safari's bound is not 26.0: the iPhone 13 Safari 26.2 capture
(`shape/hars/target_login_iphone13-safari26.2_1_0912.har`) sends `gzip, deflate, br` on every request, the
iPhone 15 26.5 capture (`target_login_iphone15-safari26.5_1_0909.har`) and the macOS 26.4 echo add `zstd`, so
the rule switches at 26.4, the first release witnessed with it; 26.3 is unwitnessed
(HYPOTHESIS(safari_26_3_no_zstd), falsified by one 26.3 capture carrying `zstd`). The Chromium 123 and Firefox
126 bounds are those browsers' zstd releases.

## Adding a capture

1. `python .agents/skills/fp-sample/browserstack.py --echo --url https://tls.peet.ws/api/all --timeout-s 60 …`
   (device flags in the fp-sample skill), stdout to `testdata/<family>-<os>-<release>.json`, unmodified.
2. Add a `deviceFixtures` row in `device_test.go` with the profile the rule binds and the fields it differs on.
3. `GOWORK=off go test -tags witness ./tlsprofile/`.
