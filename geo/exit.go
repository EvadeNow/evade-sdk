// Package geo resolves a proxied session's exit IP, its MaxMind location, and its time zone's clock state.
package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
)

const exitIPURL = "https://api.ipify.org/?format=json"

const maxExitBody = 1 << 10

// Doer is satisfied by tls-client's HttpClient, keeping the lookup on the session's TLS fingerprint and proxy.
type Doer interface {
	Do(*fhttp.Request) (*fhttp.Response, error)
}

type ExitReason string

const (
	ExitTransport ExitReason = "transport"
	ExitStatus    ExitReason = "status"
	ExitOversized ExitReason = "oversized" // body over 1 KiB
	ExitMalformed ExitReason = "malformed"
	ExitEmpty     ExitReason = "empty"
	ExitNotPublic ExitReason = "not-public" // misrouted or intercepted request, not a real exit
)

type ExitError struct {
	Reason     ExitReason
	StatusCode int
	Address    string
	Err        error
}

func (e *ExitError) Error() string {
	switch e.Reason {
	case ExitStatus:
		return fmt.Sprintf("geo: exit IP lookup returned HTTP %d", e.StatusCode)
	case ExitNotPublic:
		return fmt.Sprintf("geo: exit IP %q is not a public unicast address", e.Address)
	}
	if e.Err != nil {
		return fmt.Sprintf("geo: exit IP lookup %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("geo: exit IP lookup %s", e.Reason)
}

func (e *ExitError) Unwrap() error { return e.Err }

// ExitIP observes the public address c egresses from; pass the session's own client so it travels the same proxy route.
func ExitIP(ctx context.Context, c Doer) (netip.Addr, error) {
	request, err := fhttp.NewRequestWithContext(ctx, fhttp.MethodGet, exitIPURL, nil)
	if err != nil {
		return netip.Addr{}, &ExitError{Reason: ExitTransport, Err: err}
	}
	request.Header.Set("accept", "application/json")
	// identity: the 1 KiB cap must bound wire bytes, not a decompressed expansion.
	request.Header.Set("accept-encoding", "identity")
	response, err := c.Do(request)
	if err != nil {
		return netip.Addr{}, &ExitError{Reason: ExitTransport, Err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != fhttp.StatusOK {
		return netip.Addr{}, &ExitError{Reason: ExitStatus, StatusCode: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxExitBody+1))
	if err != nil {
		return netip.Addr{}, &ExitError{Reason: ExitTransport, Err: err}
	}
	if len(body) > maxExitBody {
		return netip.Addr{}, &ExitError{Reason: ExitOversized}
	}
	var observed struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &observed); err != nil {
		return netip.Addr{}, &ExitError{Reason: ExitMalformed, Err: err}
	}
	text := strings.TrimSpace(observed.IP)
	if text == "" {
		return netip.Addr{}, &ExitError{Reason: ExitEmpty}
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, &ExitError{Reason: ExitMalformed, Address: text, Err: err}
	}
	addr = addr.Unmap()
	if addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() {
		return netip.Addr{}, &ExitError{Reason: ExitNotPublic, Address: text}
	}
	return addr, nil
}
