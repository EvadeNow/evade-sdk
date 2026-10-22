package evade

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/EvadeNow/evade-sdk/useragent"
)

// UserAgentFilter selects listed User-Agents by operating system, browser,
// or both joined by "_":
//
//	OS:      windows, macos, linux, chromeos, android, ios
//	browser: chrome, safari, firefox, edge, opera, webview
//	both:    ios_safari, ios_chrome, macos_chrome, windows_chrome, ...
//
// Matching is exact and lowercase. The browser is the product the
// User-Agent names (useragent.Classify): ios_chrome is Chrome for iOS.
type UserAgentFilter string

var (
	filterOS = []useragent.OS{useragent.OSWindows, useragent.OSMacOS, useragent.OSLinux,
		useragent.OSChromeOS, useragent.OSAndroid, useragent.OSIOS}
	filterBrowsers = []useragent.Browser{useragent.BrowserChrome, useragent.BrowserSafari,
		useragent.BrowserFirefox, useragent.BrowserEdge, useragent.BrowserOpera, useragent.BrowserWebView}
)

// userAgentMatch is a parsed UserAgentFilter; an empty field matches any.
type userAgentMatch struct {
	os      useragent.OS
	browser useragent.Browser
}

func (f UserAgentFilter) parse() (userAgentMatch, error) {
	invalid := func(reason string) (userAgentMatch, error) {
		return userAgentMatch{}, fmt.Errorf("evade: user-agent filter %q: %s", string(f), reason)
	}
	first, second, joined := strings.Cut(string(f), "_")
	if joined {
		if !slices.Contains(filterOS, useragent.OS(first)) {
			return invalid(fmt.Sprintf("%q is not an operating system (%v)", first, filterOS))
		}
		if !slices.Contains(filterBrowsers, useragent.Browser(second)) {
			return invalid(fmt.Sprintf("%q is not a browser (%v)", second, filterBrowsers))
		}
		return userAgentMatch{os: useragent.OS(first), browser: useragent.Browser(second)}, nil
	}
	switch {
	case slices.Contains(filterOS, useragent.OS(first)):
		return userAgentMatch{os: useragent.OS(first)}, nil
	case slices.Contains(filterBrowsers, useragent.Browser(first)):
		return userAgentMatch{browser: useragent.Browser(first)}, nil
	}
	return invalid(fmt.Sprintf("not an operating system (%v), a browser (%v), or <os>_<browser>", filterOS, filterBrowsers))
}

func (m userAgentMatch) matches(os useragent.OS, browser useragent.Browser) bool {
	return (m.os == "" || m.os == os) && (m.browser == "" || m.browser == browser)
}

// UserAgents lists the task solver's GET /user-agents: the exact
// User-Agent values its /solve runs on, in the server's order. With
// filters it keeps the values matching any one of them. task is the
// solver's Task constant (shape.Task, datadome.Task, cloudflare.Task): it
// routes the request on the hosted API, and a solver's own server ignores
// it. DataDome's list is what a first tags or interstitial solve pins a
// fingerprint for; a captcha solve further needs a capture of the page's
// own Worker and renderer.
//
// An invalid filter fails before any request. While filtering, a listed
// User-Agent useragent.Classify cannot place fails the call with its
// *useragent.UnsupportedError rather than be dropped or guessed.
func (c *Client) UserAgents(ctx context.Context, task string, filters ...UserAgentFilter) ([]string, error) {
	if task == "" {
		return nil, errors.New("evade: user-agents: task is required")
	}
	matches := make([]userAgentMatch, 0, len(filters))
	for _, f := range filters {
		m, err := f.parse()
		if err != nil {
			return nil, err
		}
		matches = append(matches, m)
	}
	var response struct {
		UserAgents []string `json:"user_agents"`
	}
	if _, err := c.Call(ctx, http.MethodGet, "/user-agents?task="+url.QueryEscape(task), nil, &response); err != nil {
		return nil, err
	}
	if response.UserAgents == nil {
		return nil, errors.New("evade: user-agents: response has no user_agents list")
	}
	if len(matches) == 0 {
		return response.UserAgents, nil
	}
	kept := make([]string, 0, len(response.UserAgents))
	for _, ua := range response.UserAgents {
		os, browser, err := useragent.Classify(ua)
		if err != nil {
			return nil, fmt.Errorf("evade: user-agents: %w", err)
		}
		if slices.ContainsFunc(matches, func(m userAgentMatch) bool { return m.matches(os, browser) }) {
			kept = append(kept, ua)
		}
	}
	return kept, nil
}
