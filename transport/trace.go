package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httptrace"
	tlsclient "github.com/bogdanfinn/tls-client"
	"golang.org/x/net/proxy"
)

// ConnectTrace reports proxy CONNECT and tunneled TLS start as httptrace events and counts proxy-link bytes per target host.
type ConnectTrace struct {
	mu    sync.Mutex
	hosts map[string]*hostCounter
}

// NetworkBytes is one target host's proxy-link traffic, CONNECT and TLS overhead included.
type NetworkBytes struct {
	Read, Wrote int64
}

type ProxyConnectError struct {
	StatusCode int    // set on a non-200 answer
	Status     string // set on a non-200 answer
	Err        error  // set when the exchange itself failed
}

func (e *ProxyConnectError) Error() string {
	if e.Err != nil {
		return "transport: proxy CONNECT: " + e.Err.Error()
	}
	return "transport: proxy CONNECT returned " + e.Status
}

func (e *ProxyConnectError) Unwrap() error {
	return e.Err
}

type hostCounter struct {
	read  atomic.Int64
	wrote atomic.Int64
}

func NewConnectTrace() *ConnectTrace {
	return &ConnectTrace{hosts: make(map[string]*hostCounter)}
}

func (t *ConnectTrace) Snapshot() map[string]NetworkBytes {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make(map[string]NetworkBytes, len(t.hosts))
	for host, counter := range t.hosts {
		result[host] = NetworkBytes{Read: counter.read.Load(), Wrote: counter.wrote.Load()}
	}
	return result
}

func (t *ConnectTrace) counter(address string) *hostCounter {
	host := address
	if parsed, _, err := net.SplitHostPort(address); err == nil {
		host = parsed
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	counter := t.hosts[host]
	if counter == nil {
		counter = &hostCounter{}
		t.hosts[host] = counter
	}
	return counter
}

// tls-client refuses a proxy URL beside a dialer factory and calls the factory with an empty URL, so it carries its own.
func (t *ConnectTrace) dialerFactory(proxyURL string) tlsclient.ProxyDialerFactory {
	return func(_ string, timeout time.Duration, localAddr *net.TCPAddr, connectHeader fhttp.Header, _ tlsclient.Logger) (proxy.ContextDialer, error) {
		return newConnectDialer(proxyURL, timeout, localAddr, connectHeader, t)
	}
}

// connectDialer reproduces tls-client's CONNECT exactly; the first tunneled write is the ClientHello, so it marks TLS start.
type connectDialer struct {
	proxyHost     string
	timeout       time.Duration
	dialer        net.Dialer
	connectHeader fhttp.Header
	trace         *ConnectTrace
}

func newConnectDialer(proxyURL string, timeout time.Duration, localAddr *net.TCPAddr, connectHeader fhttp.Header, trace *ConnectTrace) (*connectDialer, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("transport: traced proxy URL: %w", err)
	}
	if parsed.Scheme != "http" || parsed.Host == "" {
		return nil, fmt.Errorf("transport: CONNECT tracing requires an http:// proxy, got scheme %q", parsed.Scheme)
	}
	host := parsed.Host
	if parsed.Port() == "" {
		host = net.JoinHostPort(parsed.Hostname(), "80")
	}
	header := connectHeader.Clone()
	if header == nil {
		header = make(fhttp.Header)
	}
	if parsed.User != nil && parsed.User.Username() != "" {
		password, _ := parsed.User.Password()
		header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(parsed.User.Username()+":"+password)))
	}
	return &connectDialer{
		proxyHost:     host,
		timeout:       timeout,
		dialer:        net.Dialer{Timeout: timeout, LocalAddr: localAddr},
		connectHeader: header,
		trace:         trace,
	}, nil
}

func (d *connectDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *connectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	request := &fhttp.Request{
		Method: fhttp.MethodConnect,
		URL:    &url.URL{Host: address},
		Header: d.connectHeader.Clone(),
		Host:   address,
	}
	clientTrace := httptrace.ContextClientTrace(ctx)
	if clientTrace != nil && clientTrace.ConnectStart != nil {
		clientTrace.ConnectStart(network, d.proxyHost)
	}
	raw, err := d.dialer.DialContext(ctx, network, d.proxyHost)
	if err != nil {
		return nil, &ProxyConnectError{Err: err}
	}
	counter := d.trace.counter(address)
	connection := &countingConn{Conn: raw, counter: counter}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = connection.Close()
		}
	}()
	if err := connection.SetDeadline(time.Now().Add(d.timeout)); err != nil {
		return nil, &ProxyConnectError{Err: err}
	}
	if err := request.Write(connection); err != nil {
		return nil, &ProxyConnectError{Err: err}
	}
	response, err := fhttp.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return nil, &ProxyConnectError{Err: err}
	}
	if response.StatusCode != fhttp.StatusOK {
		_ = response.Body.Close()
		return nil, &ProxyConnectError{StatusCode: response.StatusCode, Status: response.Status}
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, &ProxyConnectError{Err: err}
	}
	closeOnError = false
	return &tlsStartConn{Conn: connection, trace: clientTrace}, nil
}

type countingConn struct {
	net.Conn
	counter *hostCounter
}

func (c *countingConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	c.counter.read.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.counter.wrote.Add(int64(n))
	return n, err
}

type tlsStartConn struct {
	net.Conn
	trace *httptrace.ClientTrace
	wrote bool
}

func (c *tlsStartConn) Write(data []byte) (int, error) {
	if !c.wrote {
		c.wrote = true
		if c.trace != nil && c.trace.TLSHandshakeStart != nil {
			c.trace.TLSHandshakeStart()
		}
	}
	return c.Conn.Write(data)
}
