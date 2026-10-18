// Package proxy acquires per-session proxy routes; each Acquire mints a fresh sticky session unless the request pins one.
package proxy

import "context"

// RTCPolicy is how WebRTC UDP can leave through a lease.
type RTCPolicy uint8

const (
	RTCPolicyUnknown   RTCPolicy = iota // never valid on a lease
	RTCPolicyProxyOnly                  // no UDP path
	RTCPolicyDirectUDP
	RTCPolicySOCKS5UDP // via SOCKS5 UDP ASSOCIATE
)

type Lease struct {
	URL       string // includes credentials
	SessionID string // sticky id in URL, or a caller label when URL has none
	Country   string
	RTC       RTCPolicy
}

type Request struct {
	Country string // ISO 3166-1 alpha-2
	City    string // rejected by providers that cannot target cities
	Session string // pins a sticky session; empty mints a fresh one
}

type Provider interface {
	Acquire(ctx context.Context, r Request) (Lease, error)
}
