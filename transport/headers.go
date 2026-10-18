package transport

import (
	"fmt"
	"strings"

	"github.com/EvadeNow/evade-sdk/tlsprofile"
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
