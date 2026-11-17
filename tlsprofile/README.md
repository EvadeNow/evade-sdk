# tlsprofile

`Resolver.Resolve` answers only for a browser release whose real-device ClientHello and HTTP/2 preface equal a
tls-client built-in profile. Every other release fails with `*NoProfileError`, whose `Nearest` names the closest
verified span: the release to re-capture against.

The evidence is `testdata/<fixture>.json`: verbatim `https://tls.peet.ws/api/all` echoes of a top-level navigation
on a real BrowserStack device. `TestResolveMatchesRealDevice` replays each fixture's User-Agent and headers through
`transport.New` with the resolved profile against a local TLS server and compares, field by field, JA4 and JA4_r,
cipher order, extension order (as a set where Chrome permutes it), supported groups, point formats, peetprint
(versions, ALPN, groups, signature algorithms, PSK modes, certificate compression), key-share groups and sizes,
ALPS, Chrome's trust_anchors list, the HTTP/2 Akamai fingerprint (SETTINGS and order, WINDOW_UPDATE, PRIORITY
frames, pseudo-header order), and the HEADERS stream id and priority. A tls-client upgrade that changes a verified
profile fails that test. `TestVerifiedBoundsAreCaptured` requires a fixture at both ends of every span.

## Verified spans

All captures: BrowserStack, 2026-11-17, tls-client v1.18.1.

| Profile | Families / OS | Span | Fixtures (BrowserStack device) |
|---|---|---|---|
| `chrome_154` | Chrome on Windows, macOS | 154–157 | `chrome-macos-154`, `-155`, `-156`, `-157` (OS X Tahoe, Chrome 154/155/156/157); `chrome-windows-157` (Windows 11, Chrome 157) |
| `safari_ios_26_0` | Safari on iOS and macOS (one Safari 26 stack: iPhone, iPad desktop mode, Mac) | 26.4–27.2 | `safari-macos-26.4` (OS X Tahoe, Safari 26.4); `safari-ios-26.6` (iPhone 17, iOS 26); `safari-ipad-desktop-26.6.1` (iPad Air 13 2025, iPadOS 26); `safari-ios-27.2` (iPhone 18 Pro, iOS 27); `chrome-ios-149-ios-26.6` (iPhone 17, iOS 26, Chrome for iOS 149, resolved by `transport.NewBrowser`) |
| `safari_ios_18_5` | Safari on iOS | 18.4–18.6 | `safari-ios-18.4.1` (iPhone 16 Pro, iOS 18); `safari-ios-18.5` (iPhone 16, iOS 18); `safari-ios-18.6` (iPhone 16 Plus, iOS 18) |

A release strictly inside a span is taken to send what both ends send: HYPOTHESIS(tls_release_span), falsified
by a capture inside a span that differs from its profile.

## Hypothesis spans

No capture states these. `Resolve` returns the profile with `Verified` false and `Hypothesis` naming the claim.

| Profile | Families / OS | Span | Hypothesis | Falsified by |
|---|---|---|---|---|
| `safari_ios_18_5` | Safari on iOS | 18.7 | HYPOTHESIS(ios_18_7_hello_equals_18_5): iOS 18.7 sends 18.6's ClientHello and HTTP/2 settings; 18.4, 18.5 and 18.6 all send `safari_ios_18_5` | one real iOS 18.7 echo differing on any compared field; an equal one turns 18.7 into the verified span's new end |

## Refused, with the capture that refuses it

| Fixture (BrowserStack device) | Former pick | Difference |
|---|---|---|
| `chrome-macos-151` (OS X Tahoe, Chrome 151) | `chrome_150` | no trust_anchors (0xca34) extension; `chrome_150` sends one |
| `chrome-macos-152` (OS X Tahoe, Chrome 152) | `chrome_152` | 32 trust anchors; `chrome_152` carries 28 |
| `chrome-android-152` (Google Pixel 10, Android 16; Galaxy S26 and Pixel 11 sent the same bytes) | `chrome_152` | as macOS 152; Android serves no newer Chrome |
| `edge-windows-157` (Windows 11, Edge 157) | `chrome_154` | no trust_anchors extension |
| `firefox-windows-148` (Windows 11, Firefox 148) | `firefox_148` | `firefox_148` adds DHE suites 0x0033/0x0039; HEADERS on stream 1 (Firefox: 3) |
| `firefox-windows-160` (Windows 11, Firefox 160) | `firefox_148` | as 148, and Firefox 160 dropped the ECDSA CBC suites and the ffdhe groups `firefox_148` sends |
| `safari-ios-18.0.1` (iPhone 13 Pro Max, iOS 18) | `safari_ios_18_0` | ClientHello equal; HTTP/2 SETTINGS, WINDOW_UPDATE, pseudo-header order (m,s,p,a) and HEADERS weight differ |
| `safari-ios-18.3` (iPhone 16e, iOS 18) | `safari_ios_18_0` | `safari_ios_18_0` adds the `ecdsa_sha1` signature algorithm (and so a different padding length) |
| `safari-ipad-desktop-16.0` (iPad 10th, iPadOS 16) | `safari_16_0` | iOS HTTP/2 settings under a Macintosh User-Agent, so a Macintosh Safari UA below 26 is a Mac or an iPad |

Never captured, so refused: Chrome on Android at 154 and later, on Linux and ChromeOS; Opera; Android WebView;
iOS Safari 26.0–26.3; macOS Safari below 26. iOS Safari 18.7 resolves only under its hypothesis: none of
BrowserStack's nine iOS 18 devices runs it (sampled 2026-11-17: iPhone 13 Pro Max 18.0.1, iPhone 16e 18.3,
iPhone 13 and 16 Pro 18.4.1, iPhone 16 18.5, iPhone 16 Plus 18.6, iPad 9th / Pro 11 2021 / Air 13 2025 18.6 in
desktop mode); one real-device echo on 18.7 settles it.

## Adding a release

1. Capture it: `python .agents/skills/fp-sample/browserstack.py --echo --url https://tls.peet.ws/api/all
   --timeout-s 60 …` (device flags in the fp-sample skill), stdout to `testdata/<family>-<os>-<release>.json`,
   unmodified.
2. Add the fixture to `deviceFixtures` in `device_test.go` with the profile it must resolve to, and widen or add
   the span in `verifiedProfiles` (`resolver.go`) so the new capture is one of its ends.
3. `GOWORK=off go test ./tlsprofile/`: the fixture must equal the profile field for field. If no built-in
   profile matches, record the fixture as refused with the profile it differs from instead.
