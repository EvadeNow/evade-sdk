package tlsprofile_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/EvadeNow/evade-sdk/tlsprofile"
	"github.com/EvadeNow/evade-sdk/transport"
	"github.com/EvadeNow/evade-sdk/useragent"
	fhttp "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// deviceFixture is a tls.peet.ws/api/all echo of a navigation from a real BrowserStack device (fp-sample
// browserstack.py --echo), stored verbatim as testdata/<fixture>.json. want is the profile the solver path must
// pick for the fixture's User-Agent, and that profile's emitted ClientHello and HTTP/2 preface must equal the
// fixture's; an empty want is a release the resolver must refuse, and refused names the profile the former
// newest-not-above rule picked there, which must differ from the fixture so the refusal stays evidence.
type deviceFixture struct {
	fixture string
	want    string
	refused string
	// noAESHardware: the host has no AES instructions, so BoringSSL puts its ChaCha20 suites first; the cipher
	// order is then a property of the machine, compared as a set (the same build on a Mac sends the profile's order).
	noAESHardware bool
}

var deviceFixtures = []deviceFixture{
	{fixture: "chrome-macos-151", refused: "chrome_150"},
	{fixture: "chrome-macos-152", refused: "chrome_152"},
	{fixture: "chrome-macos-154", want: "chrome_154"},
	{fixture: "chrome-macos-155", want: "chrome_154"},
	{fixture: "chrome-macos-156", want: "chrome_154"},
	{fixture: "chrome-macos-157", want: "chrome_154"},
	{fixture: "chrome-windows-157", want: "chrome_154", noAESHardware: true},
	{fixture: "chrome-android-152", refused: "chrome_152"},
	{fixture: "edge-windows-157", refused: "chrome_154", noAESHardware: true},
	{fixture: "firefox-windows-148", refused: "firefox_148"},
	{fixture: "firefox-windows-160", refused: "firefox_148"},
	{fixture: "safari-macos-26.4", want: "safari_ios_26_0"},
	{fixture: "safari-ipad-desktop-26.6.1", want: "safari_ios_26_0"},
	{fixture: "safari-ipad-desktop-16.0", refused: "safari_16_0"},
	{fixture: "safari-ios-26.6", want: "safari_ios_26_0"},
	{fixture: "safari-ios-27.2", want: "safari_ios_26_0"},
	{fixture: "safari-ios-18.5", want: "safari_ios_18_5"},
	{fixture: "safari-ios-18.6", want: "safari_ios_18_5"},
	{fixture: "safari-ios-18.4.1", want: "safari_ios_18_5"},
	{fixture: "safari-ios-18.3", refused: "safari_ios_18_0"},
	{fixture: "safari-ios-18.0.1", refused: "safari_ios_18_0"},
	{fixture: "chrome-ios-149-ios-26.6", want: "safari_ios_26_0"},
}

func TestEveryDeviceFixtureIsChecked(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		if !slices.ContainsFunc(deviceFixtures, func(d deviceFixture) bool { return d.fixture == name }) {
			t.Errorf("testdata/%s.json is in no deviceFixtures row", name)
		}
	}
}

func TestResolveMatchesRealDevice(t *testing.T) {
	r, err := tlsprofile.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range deviceFixtures {
		t.Run(tt.fixture, func(t *testing.T) {
			fx := readFixture(t, tt.fixture)
			profile, err := solverProfile(r, fx.UserAgent)
			if tt.want == "" {
				var noProfile *tlsprofile.NoProfileError
				if !errors.As(err, &noProfile) {
					t.Fatalf("resolved %q (%v); want *NoProfileError: the real device differs from %s", profile.Name, err, tt.refused)
				}
				candidate, err := r.Named(tt.refused)
				if err != nil {
					t.Fatal(err)
				}
				if diffs := compareDevice(fx, emit(t, candidate, fx), candidate.Behavior, tt.noAESHardware); len(diffs) == 0 {
					t.Fatalf("%s now equals the real device; verify the release instead of refusing it", tt.refused)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if profile.Name != tt.want || !profile.Verified || profile.Hypothesis != "" {
				t.Fatalf("resolved %q (verified %t, hypothesis %q), want verified %q", profile.Name, profile.Verified, profile.Hypothesis, tt.want)
			}
			if diffs := compareDevice(fx, emit(t, profile, fx), profile.Behavior, tt.noAESHardware); len(diffs) > 0 {
				t.Fatalf("%s differs from the real device:\n%s", profile.Name, strings.Join(diffs, "\n"))
			}
		})
	}
}

// solverProfile is the profile a session for ua presents: Chrome for iOS through transport.NewBrowser (useragent.Parse
// refuses CriOS), every other User-Agent through the resolver.
func solverProfile(r *tlsprofile.Resolver, ua string) (tlsprofile.Profile, error) {
	if strings.Contains(ua, " CriOS/") {
		b, err := transport.NewBrowser(ua)
		return b.TLS, err
	}
	a, err := useragent.Parse(ua)
	if err != nil {
		return tlsprofile.Profile{}, err
	}
	return r.Resolve(a)
}

type fixture struct {
	UserAgent string `json:"user_agent"`
	TLS       struct {
		Extensions []map[string]any `json:"extensions"`
		JA3        string           `json:"ja3"`
		JA4        string           `json:"ja4"`
		JA4R       string           `json:"ja4_r"`
		Peetprint  string           `json:"peetprint"`
	} `json:"tls"`
	HTTP2 struct {
		Akamai string `json:"akamai_fingerprint"`
		Frames []struct {
			Type     string   `json:"frame_type"`
			StreamID uint32   `json:"stream_id"`
			Headers  []string `json:"headers"`
			Priority *struct {
				Weight    int `json:"weight"`
				DependsOn int `json:"depends_on"`
				Exclusive int `json:"exclusive"`
			} `json:"priority"`
		} `json:"sent_frames"`
	} `json:"http2"`
}

func readFixture(t *testing.T, name string) fixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx fixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return fx
}

// observed is what one connection of ours put on the wire: the ClientHello record and the HTTP/2 frames up to the
// request's HEADERS.
type observed struct {
	hello      []byte
	settings   []http2.Setting
	window     uint32
	priorities []string
	stream     uint32
	priority   http2.PriorityParam
	hasPrio    bool
	pseudo     []string
}

// emit sends the fixture's navigation (its own headers, in its own order) through transport.New with profile to a
// local TLS server that records the connection.
func emit(t *testing.T, profile tlsprofile.Profile, fx fixture) observed {
	t.Helper()
	cert, pool := serverCert(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan observed, 1)
	serverErr := make(chan error, 1)
	go func() {
		obs, err := serve(listener, cert)
		result <- obs
		serverErr <- err
	}()

	var headers transport.Headers
	for _, frame := range fx.HTTP2.Frames {
		if frame.Type != "HEADERS" {
			continue
		}
		for _, line := range frame.Headers {
			if strings.HasPrefix(line, ":") {
				continue
			}
			name, value, _ := strings.Cut(line, ": ")
			headers = append(headers, transport.Header{Name: name, Value: value})
		}
		break
	}
	req, err := fhttp.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Apply(req, headers, profile); err != nil {
		t.Fatal(err)
	}
	client, _, err := transport.New(transport.Config{
		Profile: profile, UserAgent: fx.UserAgent, Timeout: 10 * time.Second, DisableCompression: true, CaptureCA: pool,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request with %s: %v", profile.Name, err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	obs := <-result
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
	return obs
}

func serverCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tls.peet.ws"}, DNSNames: []string{"tls.peet.ws"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// serve accepts one connection, records its ClientHello record, completes TLS and reads HTTP/2 frames through the
// first request's HEADERS, then answers 200 and drains until the client closes.
func serve(listener net.Listener, cert tls.Certificate) (observed, error) {
	var obs observed
	raw, err := listener.Accept()
	if err != nil {
		return obs, err
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return obs, err
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(raw, header); err != nil {
		return obs, err
	}
	record := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(raw, record); err != nil {
		return obs, err
	}
	obs.hello = record
	conn := tls.Server(&replayConn{Conn: raw, r: io.MultiReader(bytes.NewReader(header), bytes.NewReader(record), raw)},
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err := conn.Handshake(); err != nil {
		return obs, err
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return obs, err
	}
	if string(preface) != http2.ClientPreface {
		return obs, fmt.Errorf("negotiated %q, not HTTP/2", conn.ConnectionState().NegotiatedProtocol)
	}
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	for obs.stream == 0 {
		frame, err := framer.ReadFrame()
		if err != nil {
			return obs, err
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := f.ForeachSetting(func(s http2.Setting) error { obs.settings = append(obs.settings, s); return nil }); err != nil {
					return obs, err
				}
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				obs.window = f.Increment
			}
		case *http2.PriorityFrame:
			obs.priorities = append(obs.priorities, fmt.Sprintf("%d:%d:%d:%d", f.StreamID, b2i(f.Exclusive), f.StreamDep, int(f.Weight)+1))
		case *http2.MetaHeadersFrame:
			obs.stream, obs.priority, obs.hasPrio = f.StreamID, f.Priority, f.HasPriority()
			for _, field := range f.Fields {
				if field.IsPseudo() {
					obs.pseudo = append(obs.pseudo, field.Name)
				}
			}
		}
	}
	if err := framer.WriteSettings(); err != nil {
		return obs, err
	}
	if err := framer.WriteSettingsAck(); err != nil {
		return obs, err
	}
	var block bytes.Buffer
	if err := hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
		return obs, err
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: obs.stream, BlockFragment: block.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
		return obs, err
	}
	for {
		if _, err := framer.ReadFrame(); err != nil {
			return obs, nil // the client closed the connection
		}
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

type extension struct {
	typ  uint16
	data []byte
}

type clientHello struct {
	ciphers    []uint16
	extensions []extension
}

func parseHello(record []byte) (clientHello, error) {
	var h clientHello
	if len(record) < 4 || record[0] != 1 {
		return h, errors.New("first handshake message is not a ClientHello")
	}
	body := record[4:]
	if int(record[1])<<16|int(record[2])<<8|int(record[3]) != len(body) {
		return h, errors.New("ClientHello spans TLS records")
	}
	s := cursor{b: body[34:]} // legacy_version, random
	s.vector(1)               // legacy_session_id
	ciphers := s.vector(2)
	for i := 0; i+1 < len(ciphers); i += 2 {
		h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(ciphers[i:]))
	}
	s.vector(1) // legacy_compression_methods
	exts := cursor{b: s.vector(2)}
	for len(exts.b) > 0 && exts.err == nil {
		typ := exts.u16()
		h.extensions = append(h.extensions, extension{typ: typ, data: exts.vector(2)})
	}
	return h, cmpErr(s.err, exts.err)
}

func cmpErr(errs ...error) error { return errors.Join(errs...) }

type cursor struct {
	b   []byte
	err error
}

func (c *cursor) u16() uint16 {
	if len(c.b) < 2 {
		c.err = io.ErrUnexpectedEOF
		c.b = nil
		return 0
	}
	v := binary.BigEndian.Uint16(c.b)
	c.b = c.b[2:]
	return v
}

func (c *cursor) vector(width int) []byte {
	if len(c.b) < width {
		c.err = io.ErrUnexpectedEOF
		c.b = nil
		return nil
	}
	n := int(c.b[0])
	if width == 2 {
		n = int(binary.BigEndian.Uint16(c.b))
	}
	c.b = c.b[width:]
	if len(c.b) < n {
		c.err = io.ErrUnexpectedEOF
		c.b = nil
		return nil
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}

func grease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func (h clientHello) ext(typ uint16) ([]byte, bool) {
	for _, e := range h.extensions {
		if e.typ == typ {
			return e.data, true
		}
	}
	return nil, false
}

// u16List reads a vector of uint16 with a width-byte length prefix.
func u16List(data []byte, width int) []uint16 {
	c := cursor{b: data}
	v := c.vector(width)
	out := make([]uint16, 0, len(v)/2)
	for i := 0; i+1 < len(v); i += 2 {
		out = append(out, binary.BigEndian.Uint16(v[i:]))
	}
	return out
}

func decimal(vs []uint16, keepGrease bool) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		switch {
		case !grease(v):
			parts = append(parts, strconv.Itoa(int(v)))
		case keepGrease:
			parts = append(parts, "GREASE")
		}
	}
	return strings.Join(parts, "-")
}

func hexList(vs []uint16) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		if !grease(v) {
			parts = append(parts, fmt.Sprintf("%04x", v))
		}
	}
	return strings.Join(parts, ",")
}

func sortedHex(vs []uint16) []uint16 {
	out := slices.DeleteFunc(slices.Clone(vs), grease)
	slices.Sort(out)
	return out
}

func alpn(h clientHello, typ uint16) []string {
	data, ok := h.ext(typ)
	if !ok {
		return nil
	}
	c := cursor{b: data}
	list := cursor{b: c.vector(2)}
	var protocols []string
	for len(list.b) > 0 && list.err == nil {
		protocols = append(protocols, string(list.vector(1)))
	}
	return protocols
}

// ja4 is FoxIO JA4 and its raw form over our ClientHello.
func ja4(h clientHello) (string, string) {
	types := make([]uint16, 0, len(h.extensions))
	for _, e := range h.extensions {
		types = append(types, e.typ)
	}
	versions, _ := h.ext(43)
	version := "00"
	for _, v := range u16List(versions, 1) {
		if !grease(v) && v == 0x0304 {
			version = "13"
			break
		}
	}
	sni := "i"
	if _, ok := h.ext(0); ok {
		sni = "d"
	}
	first := "00"
	if protocols := alpn(h, 16); len(protocols) > 0 && protocols[0] != "" {
		p := protocols[0]
		first = p[:1] + p[len(p)-1:]
	}
	exts := slices.DeleteFunc(sortedHex(types), func(v uint16) bool { return v == 0x0000 || v == 0x0010 })
	sigData, _ := h.ext(13)
	prefix := fmt.Sprintf("t%s%s%02d%02d%s", version, sni, min(len(sortedHex(h.ciphers)), 99), min(len(sortedHex(types)), 99), first)
	ciphers := hexList(sortedHex(h.ciphers))
	tail := hexList(exts) + "_" + hexList(u16List(sigData, 2))
	sum := func(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:])[:12] }
	return prefix + "_" + sum(ciphers) + "_" + sum(tail), prefix + "_" + ciphers + "_" + tail
}

// peetprint is tls.peet.ws's peetprint over our ClientHello.
func peetprint(h clientHello) string {
	ext := func(typ uint16) []byte { data, _ := h.ext(typ); return data }
	var protocols []string
	for _, p := range alpn(h, 16) {
		protocols = append(protocols, strings.TrimPrefix(strings.TrimPrefix(p, "http/"), "h"))
	}
	pskModes := cursor{b: ext(45)}
	var modes []string
	for _, m := range pskModes.vector(1) {
		modes = append(modes, strconv.Itoa(int(m)))
	}
	compression := cursor{b: ext(27)}
	var algorithms []uint16
	if raw := compression.vector(1); len(raw)%2 == 0 {
		for i := 0; i < len(raw); i += 2 {
			algorithms = append(algorithms, binary.BigEndian.Uint16(raw[i:]))
		}
	}
	var types []string
	for _, e := range h.extensions {
		if grease(e.typ) {
			types = append(types, "GREASE")
		} else {
			types = append(types, strconv.Itoa(int(e.typ)))
		}
	}
	slices.Sort(types)
	return strings.Join([]string{
		decimal(u16List(ext(43), 1), true), strings.Join(protocols, "-"), decimal(u16List(ext(10), 2), true),
		decimal(u16List(ext(13), 2), true), strings.Join(modes, "-"), decimal(algorithms, true),
		decimal(h.ciphers, true), strings.Join(types, "-"),
	}, "|")
}

var codeRe = regexp.MustCompile(`\((\d+)\)$`)

// keyShares lists key_share groups with key lengths, GREASE as such, from our ClientHello and from the fixture.
func keyShares(h clientHello) []string {
	data, _ := h.ext(51)
	c := cursor{b: data}
	list := cursor{b: c.vector(2)}
	var out []string
	for len(list.b) > 0 && list.err == nil {
		group := list.u16()
		key := list.vector(2)
		name := strconv.Itoa(int(group))
		if grease(group) {
			name = "GREASE"
		}
		out = append(out, fmt.Sprintf("%s[%d]", name, len(key)))
	}
	return out
}

func fixtureKeyShares(fx fixture) []string {
	var out []string
	for _, e := range fx.TLS.Extensions {
		shares, ok := e["shared_keys"].([]any)
		if !ok {
			continue
		}
		for _, share := range shares {
			for group, key := range share.(map[string]any) {
				name := "GREASE"
				if m := codeRe.FindStringSubmatch(group); m != nil && !strings.HasPrefix(group, "TLS_GREASE") {
					name = m[1]
				}
				out = append(out, fmt.Sprintf("%s[%d]", name, len(key.(string))/2))
			}
		}
	}
	return out
}

func fixtureExtension(fx fixture, code int) map[string]any {
	suffix := fmt.Sprintf("(%d)", code)
	unknown := fmt.Sprintf("Unknown extension %d", code)
	for _, e := range fx.TLS.Extensions {
		if name, _ := e["name"].(string); strings.HasSuffix(name, suffix) || name == unknown {
			return e
		}
	}
	return nil
}

func akamai(o observed) string {
	settings := make([]string, 0, len(o.settings))
	for _, s := range o.settings {
		settings = append(settings, fmt.Sprintf("%d:%d", s.ID, s.Val))
	}
	priorities := "0"
	if len(o.priorities) > 0 {
		priorities = strings.Join(o.priorities, ",")
	}
	window := "00"
	if o.window != 0 {
		window = strconv.Itoa(int(o.window))
	}
	pseudo := make([]string, 0, len(o.pseudo))
	for _, p := range o.pseudo {
		pseudo = append(pseudo, p[1:2])
	}
	return strings.Join([]string{strings.Join(settings, ";"), window, priorities, strings.Join(pseudo, ",")}, "|")
}

// compareDevice lists every field where our connection differs from the fixture's.
func compareDevice(fx fixture, o observed, behavior tlsprofile.Behavior, noAESHardware bool) []string {
	var diffs []string
	field := func(name, real, ours string) {
		if real != ours {
			diffs = append(diffs, fmt.Sprintf("%s:\n  real %s\n  ours %s", name, real, ours))
		}
	}
	h, err := parseHello(o.hello)
	if err != nil {
		return []string{fmt.Sprintf("ClientHello: %v", err)}
	}
	ja4Hash, ja4Raw := ja4(h)
	field("ja4", fx.TLS.JA4, ja4Hash)
	field("ja4_r", fx.TLS.JA4R, ja4Raw)

	ja3 := strings.Split(fx.TLS.JA3, ",")
	if len(ja3) != 5 {
		return append(diffs, fmt.Sprintf("fixture ja3 %q has no five fields", fx.TLS.JA3))
	}
	types := make([]uint16, 0, len(h.extensions))
	for _, e := range h.extensions {
		types = append(types, e.typ)
	}
	sortedDecimal := func(list string) string {
		parts := strings.Split(list, "-")
		slices.SortFunc(parts, func(a, b string) int { x, _ := strconv.Atoi(a); y, _ := strconv.Atoi(b); return x - y })
		return strings.Join(parts, "-")
	}
	if noAESHardware {
		field("cipher set", sortedDecimal(ja3[1]), decimal(sortedHex(h.ciphers), false))
	} else {
		field("cipher order", ja3[1], decimal(h.ciphers, false))
	}
	if behavior.RandomizeExtensionOrder {
		field("extension set", sortedDecimal(ja3[2]), decimal(sortedHex(types), false))
	} else {
		field("extension order", ja3[2], decimal(types, false))
	}
	groups, _ := h.ext(10)
	field("supported groups", ja3[3], decimal(u16List(groups, 2), false))
	points, _ := h.ext(11)
	var formats []string
	for _, p := range (&cursor{b: points}).vector(1) {
		formats = append(formats, strconv.Itoa(int(p)))
	}
	field("point formats", ja3[4], strings.Join(formats, "-"))

	realPeet, ourPeet := strings.Split(fx.TLS.Peetprint, "|"), strings.Split(peetprint(h), "|")
	if noAESHardware && len(realPeet) == 8 && len(ourPeet) == 8 {
		realPeet[6], ourPeet[6] = "", "" // cipher order; the set is compared above
	}
	field("peetprint (versions|alpn|groups|sigalgs|psk|cert compression|ciphers|extensions)", strings.Join(realPeet, "|"), strings.Join(ourPeet, "|"))
	field("key shares", strings.Join(fixtureKeyShares(fx), ","), strings.Join(keyShares(h), ","))
	alps := ""
	if e := fixtureExtension(fx, 17613); e != nil {
		alps = fmt.Sprint(e["protocols"])
	}
	ourALPS := ""
	if protocols := alpn(h, 17613); protocols != nil {
		ourALPS = fmt.Sprint(protocols)
	}
	field("application_settings", alps, ourALPS)
	// Chrome's trust_anchors list; its content is the browser's root store, not covered by any fingerprint hash.
	anchors := ""
	if e := fixtureExtension(fx, 51764); e != nil {
		anchors, _ = e["data"].(string)
	}
	ourAnchors := ""
	if data, ok := h.ext(51764); ok {
		ourAnchors = hex.EncodeToString(data)
	}
	field("trust_anchors data", anchors, ourAnchors)

	field("http2 akamai", fx.HTTP2.Akamai, akamai(o))
	for _, frame := range fx.HTTP2.Frames {
		if frame.Type != "HEADERS" {
			continue
		}
		field("HEADERS stream", strconv.Itoa(int(frame.StreamID)), strconv.Itoa(int(o.stream)))
		real, ours := "none", "none"
		if frame.Priority != nil {
			real = fmt.Sprintf("dep=%d exclusive=%d weight=%d", frame.Priority.DependsOn, frame.Priority.Exclusive, frame.Priority.Weight)
		}
		if o.hasPrio {
			ours = fmt.Sprintf("dep=%d exclusive=%d weight=%d", o.priority.StreamDep, b2i(o.priority.Exclusive), int(o.priority.Weight)+1)
		}
		field("HEADERS priority", real, ours)
		break
	}
	return diffs
}
