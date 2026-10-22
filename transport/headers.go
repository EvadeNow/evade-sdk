package transport

import (
	"fmt"
	"slices"
	"strings"

	"github.com/EvadeNow/evade-sdk/tlsprofile"
	"github.com/EvadeNow/evade-sdk/wireorder"
	fhttp "github.com/bogdanfinn/fhttp"
)

type Header struct {
	Name, Value string
}

// Headers is a header set in wire order; an empty Value reserves a slot (cookie, content-length) without writing it.
type Headers []Header

type AnchorError struct {
	Anchor string
}

func (e *AnchorError) Error() string {
	return fmt.Sprintf("transport: header %q is not in the list", e.Anchor)
}

// NoPseudoOrderError reports a profile without an HTTP/2 pseudo-header order; fhttp's fallbacks are fingerprints.
type NoPseudoOrderError struct {
	Profile string
}

func (e *NoPseudoOrderError) Error() string {
	return fmt.Sprintf("transport: tls-client profile %q has no pseudo-header order", e.Profile)
}

// With appends name: value; like the builtin append, the result may share h's backing array.
func (h Headers) With(name, value string) Headers {
	return append(h, Header{Name: name, Value: value})
}

// InsertBefore returns a copy of h with hs before the first header named anchor; it fails rather than appending.
func (h Headers) InsertBefore(anchor string, hs ...Header) (Headers, error) {
	for i, header := range h {
		if !strings.EqualFold(header.Name, anchor) {
			continue
		}
		result := make(Headers, 0, len(h)+len(hs))
		result = append(result, h[:i]...)
		result = append(result, hs...)
		return append(result, h[i:]...), nil
	}
	return nil, &AnchorError{Anchor: anchor}
}

func (h Headers) Names() []string {
	names := make([]string, len(h))
	for i, header := range h {
		names[i] = header.Name
	}
	return names
}

// Apply replaces req's headers with h (lowercased), setting HeaderOrderKey from h and PHeaderOrderKey from p.
func Apply(req *fhttp.Request, h Headers, p tlsprofile.Profile) error {
	pseudo := p.Client.GetPseudoHeaderOrder()
	if len(pseudo) == 0 {
		return &NoPseudoOrderError{Profile: p.Name}
	}
	header := make(fhttp.Header, len(h)+2)
	order := make([]string, 0, len(h))
	seen := make(map[string]bool, len(h))
	for _, entry := range h {
		name := strings.ToLower(entry.Name)
		// fhttp orders by a name's last index, so only the first occurrence is listed.
		if !seen[name] {
			seen[name] = true
			order = append(order, name)
		}
		if entry.Value != "" {
			header[name] = append(header[name], entry.Value)
		}
	}
	header[fhttp.HeaderOrderKey] = order
	header[fhttp.PHeaderOrderKey] = append([]string(nil), pseudo...)
	req.Header = header
	return nil
}

// stackWritten are wire names written after ApplyWireOrder, so a request need not carry them yet: host from the
// URL, cookie from the client's jar.
var stackWritten = []string{"host", "cookie"}

// WireOrderError reports request headers a wire order does not name exactly once: Extra are headers the request
// sends that the order omits (content-length when set explicitly or written by the stack), Missing order names the
// request will not send (stackWritten aside; content-length when neither set nor written), Repeated names the order
// lists twice or the request sets under two spellings.
type WireOrderError struct {
	Extra, Missing, Repeated []string
}

func (e *WireOrderError) Error() string {
	return fmt.Sprintf("transport: headers do not match the wire order: extra %q, missing %q, repeated %q", e.Extra, e.Missing, e.Repeated)
}

// ApplyWireOrder sets req's HeaderOrderKey to w.Header and PHeaderOrderKey to w.Pseudo, leaving every header value
// as it is, failing unless w.Header names each header req will send (one with a value; content-length when set
// explicitly or written by fhttp) exactly once. An explicit content-length lets a wire carry one fhttp would not
// write, as a WebKit preflight's "content-length: 0". An empty w.Pseudo (an HTTP/1.1 WebKit wire) is installed
// empty: neither the TLS profile's nor the transport's pseudo order applies.
func ApplyWireOrder(req *fhttp.Request, w wireorder.Wire) error {
	listed := make(map[string]int, len(w.Header))
	var repeated []string
	for _, name := range w.Header {
		if listed[name]++; listed[name] == 2 {
			repeated = append(repeated, name)
		}
	}
	sent := make(map[string]bool, len(req.Header)+1)
	var extra []string
	for key, values := range req.Header {
		if key == fhttp.HeaderOrderKey || key == fhttp.PHeaderOrderKey || len(values) == 0 {
			continue
		}
		name := strings.ToLower(key)
		switch {
		case sent[name]:
			repeated = append(repeated, name)
		case listed[name] == 0:
			extra = append(extra, name)
		}
		sent[name] = true
	}
	if !sent["content-length"] && sendsContentLength(req) {
		sent["content-length"] = true
		if listed["content-length"] == 0 {
			extra = append(extra, "content-length")
		}
	}
	var missing []string
	for _, name := range w.Header {
		if !sent[name] && !slices.Contains(stackWritten, name) && !slices.Contains(missing, name) {
			missing = append(missing, name)
		}
	}
	if extra != nil || missing != nil || repeated != nil {
		slices.Sort(extra)
		slices.Sort(repeated)
		return &WireOrderError{Extra: slices.Compact(extra), Missing: missing, Repeated: slices.Compact(repeated)}
	}
	if req.Header == nil {
		req.Header = make(fhttp.Header, 2)
	}
	req.Header[fhttp.HeaderOrderKey] = slices.Clone(w.Header)
	req.Header[fhttp.PHeaderOrderKey] = slices.Clone(w.Pseudo)
	return nil
}

// sendsContentLength is fhttp's rule for writing content-length (http2 shouldSendReqContentLength over
// actualContentLength, transferWriter.shouldSendContentLength over outgoingLength): a body of known positive
// length, or a known-empty POST, PUT or PATCH. A body of unknown length (ContentLength 0) sends none.
func sendsContentLength(req *fhttp.Request) bool {
	var length int64
	if req.Body != nil && req.Body != fhttp.NoBody {
		if length = req.ContentLength; length == 0 {
			length = -1
		}
	}
	if length != 0 {
		return length > 0
	}
	switch req.Method {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}
