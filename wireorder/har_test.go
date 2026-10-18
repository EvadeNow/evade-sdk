package wireorder

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var corpusGlobs = []string{
	"shape-old/harness/*.har",
	"shape-old/*.har",
	"shape/hars/*.har",
	"datadome/harness/*.har",
	"cloudflare/*.har",
	"gman2/harness/*.har",
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harEntry struct {
	Request struct {
		Method      string      `json:"method"`
		URL         string      `json:"url"`
		HTTPVersion string      `json:"httpVersion"`
		Headers     []harHeader `json:"headers"`
	} `json:"request"`
	Response *struct {
		Status      int         `json:"status"`
		RedirectURL string      `json:"redirectURL"`
		Headers     []harHeader `json:"headers"`
	} `json:"response"`
	CompatHTTP *struct {
		Request struct {
			HeaderFields []harHeader `json:"header_fields"`
		} `json:"request"`
	} `json:"_compat_http"`
}

type capture struct {
	HAR        string
	Entry      int
	Method     string
	URL        string
	HTTP2      bool
	UA         string
	Pseudo     []string
	Names      []string
	Mode, Dest string
	Location   string
	Redirected bool
}

func (c *capture) String() string { return fmt.Sprintf("%s#%d", c.HAR, c.Entry) }

func (c *capture) has(name string) bool { return slices.Contains(c.Names, name) }

// loadCorpus returns nil when any corpus directory is missing.
func loadCorpus() ([]*capture, error) {
	root := filepath.Join("..", "..")
	var paths []string
	for _, g := range corpusGlobs {
		m, err := filepath.Glob(filepath.Join(root, g))
		if err != nil {
			return nil, err
		}
		if len(m) == 0 {
			return nil, nil
		}
		paths = append(paths, m...)
	}
	var out []*capture
	seen := map[string]bool{}
	for _, p := range paths {
		name := strings.TrimSuffix(filepath.Base(p), ".har")
		if seen[name] {
			continue
		}
		seen[name] = true
		var lastNavigation *capture
		err := forEachHAREntry(p, func(i int, e *harEntry) {
			c := &capture{HAR: name, Entry: i, Method: e.Request.Method, URL: e.Request.URL,
				HTTP2: strings.Contains(e.Request.HTTPVersion, "2")}
			headers := e.Request.Headers
			if w := e.CompatHTTP; w != nil && len(w.Request.HeaderFields) != 0 {
				headers = w.Request.HeaderFields
			}
			for _, h := range headers {
				n := strings.ToLower(h.Name)
				switch {
				case strings.HasPrefix(n, ":"):
					c.Pseudo = append(c.Pseudo, n)
					continue
				case n == "user-agent":
					c.UA = h.Value
				case n == "sec-fetch-mode":
					c.Mode = h.Value
				case n == "sec-fetch-dest":
					c.Dest = h.Value
				}
				if n == "cookie" && c.has("cookie") {
					continue
				}
				c.Names = append(c.Names, n)
			}
			if r := e.Response; r != nil && r.Status >= 300 && r.Status < 400 {
				location := r.RedirectURL
				for _, h := range r.Headers {
					if location == "" && strings.EqualFold(h.Name, "location") {
						location = h.Value
					}
				}
				if base, err := url.Parse(c.URL); err == nil && location != "" {
					if target, err := base.Parse(location); err == nil {
						c.Location = target.String()
					}
				}
			}
			if c.Mode == "navigate" && c.Dest == "document" {
				c.Redirected = lastNavigation != nil && lastNavigation.Location == c.URL
				lastNavigation = c
			}
			out = append(out, c)
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	return out, nil
}

// forEachHAREntry streams log.entries so a HAR is never held in memory whole.
func forEachHAREntry(path string, fn func(int, *harEntry)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<16))
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		if key != "log" {
			if err := skipValue(dec); err != nil {
				return err
			}
			continue
		}
		if err := expectDelim(dec, '{'); err != nil {
			return err
		}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			if key != "entries" {
				if err := skipValue(dec); err != nil {
					return err
				}
				continue
			}
			if err := expectDelim(dec, '['); err != nil {
				return err
			}
			for i := 0; dec.More(); i++ {
				var e harEntry
				if err := dec.Decode(&e); err != nil {
					return fmt.Errorf("entry %d: %w", i, err)
				}
				fn(i, &e)
			}
			if err := expectDelim(dec, ']'); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("no log.entries")
}

func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != d {
		return fmt.Errorf("want %v, got %v", d, tok)
	}
	return nil
}

func skipValue(dec *json.Decoder) error {
	var skip json.RawMessage
	return dec.Decode(&skip)
}

var (
	chromeMajorRE = regexp.MustCompile(`Chrome/(\d+)\.`)
	safariMajorRE = regexp.MustCompile(`Version/(\d+)(?:\.(\d+))?[.\d]* (?:Mobile/\S+ )?Safari/`)
	shapeNameRE   = regexp.MustCompile(`^(.+-)([abcdfz])\d*$`)
)

func engineOf(ua string) (Engine, bool) {
	if strings.Contains(ua, "Firefox/") || strings.Contains(ua, "CriOS/") || strings.Contains(ua, "FxiOS/") || strings.Contains(ua, "EdgiOS/") {
		return Engine{}, false
	}
	if m := chromeMajorRE.FindStringSubmatch(ua); m != nil {
		major, _ := strconv.Atoi(m[1])
		return Engine{Kind: Chromium, Major: major}, true
	}
	if m := safariMajorRE.FindStringSubmatch(ua); m != nil {
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		return Engine{Kind: WebKit, Major: major, Minor: minor}, true
	}
	return Engine{}, false
}

func shapePrefix(names []string) string {
	suffixes := map[string]map[byte]bool{}
	var order []string
	for _, n := range names {
		m := shapeNameRE.FindStringSubmatch(n)
		if m == nil {
			continue
		}
		if suffixes[m[1]] == nil {
			suffixes[m[1]] = map[byte]bool{}
			order = append(order, m[1])
		}
		suffixes[m[1]][m[2][0]] = true
	}
	for _, p := range order {
		if len(suffixes[p]) >= 4 {
			return p
		}
	}
	return ""
}
