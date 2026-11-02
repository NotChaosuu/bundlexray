package fetch

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// DefaultMaxBody caps a single download. Anything longer is flagged as truncated.
const DefaultMaxBody = 25 << 20

// DefaultUserAgent names the tool but reads as a browser to CDNs that refuse
// anything without "Mozilla" (several serve their chunks only to browsers).
const DefaultUserAgent = "Mozilla/5.0 (compatible; bundlexray/1.0; +https://github.com/NotChaosuu/bundlexray)"

// BrowserUserAgent is used once more for a script that answered 403 or 404
// to the default, when the caller did not choose a user agent.
const BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// Options configures a Client.
type Options struct {
	Insecure  bool
	Timeout   time.Duration
	UserAgent string
	// AllowPrivate permits loopback, RFC 1918, link-local and similar
	// destinations. Off by default so a scanned page cannot point the tool at
	// internal services.
	AllowPrivate bool
	// SameSite restricts every request to the target's registrable domain
	// (plus AllowHosts).
	SameSite   bool
	AllowHosts []string
	// MaxBody overrides DefaultMaxBody.
	MaxBody int
}

// Client fetches pages and scripts under the scan's scope and address policy.
type Client struct {
	hc       *http.Client
	opts     Options
	site     string
	ua       string
	retryGap time.Duration
	deadline time.Time
	// privateOK holds the target's own private addresses and port; only
	// those are reachable without --allow-private.
	privateOK map[netip.AddrPort]bool
}

// BlockedError is returned when a request would reach a private address or an
// out-of-scope host. It is policy, not a fetch failure.
type BlockedError struct {
	Host   string
	Reason string
}

func (e *BlockedError) Error() string { return fmt.Sprintf("%s: %s", e.Host, e.Reason) }

// HTTPError carries the status of a non-2xx response.
type HTTPError struct {
	URL    string
	Status int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status) }

// StatusOf returns the HTTP status behind err, or 0.
func StatusOf(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

// NoSuchHost reports whether err is a DNS lookup that found no such host.
func NoSuchHost(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// IsBlocked reports whether err is a scope/private-address refusal.
func IsBlocked(err error) bool {
	var be *BlockedError
	return errors.As(err, &be)
}

// New returns a Client. The address check runs in the dialer, after DNS, so
// it also covers redirects and hostnames that resolve to internal addresses.
func New(o Options) *Client {
	c := &Client{opts: o, ua: o.UserAgent, retryGap: 500 * time.Millisecond}
	if c.ua == "" {
		c.ua = DefaultUserAgent
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: c.guard}
	c.hc = &http.Client{
		Timeout: o.Timeout,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: o.Insecure},
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConnsPerHost: 8,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			return c.inScope(req.URL)
		},
	}
	return c
}

// SetTarget records the scan target. When the target itself is on a private
// address (a dev server, an intranet host), that address and port, and only
// that one, becomes reachable: a target that also resolves to 127.0.0.1 must
// not unlock 169.254.169.254, nor another service on the same host.
func (c *Client) SetTarget(u *url.URL) {
	c.site = registrable(u.Hostname())
	c.privateOK = map[netip.AddrPort]bool{}
	port := uint16(80)
	if u.Scheme == "https" {
		port = 443
	}
	if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 && p < 65536 {
		port = uint16(p)
	}
	allow := func(ip netip.Addr) {
		if isPrivate(ip) {
			c.privateOK[netip.AddrPortFrom(ip.Unmap(), port)] = true
		}
	}
	host := strings.Trim(u.Hostname(), "[]")
	if ip, err := netip.ParseAddr(host); err == nil {
		allow(ip)
		return
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		allow(netip.MustParseAddr("127.0.0.1"))
		allow(netip.MustParseAddr("::1"))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return
	}
	for _, a := range addrs {
		allow(a)
	}
}

// SetDeadline makes every request after t fail, so a scan's time limit also
// bounds requests already in flight.
func (c *Client) SetDeadline(t time.Time) { c.deadline = t }

// RetryUA returns the user agent to retry a refused script with, or "" when
// the caller chose the user agent.
func (c *Client) RetryUA() string {
	if c.opts.UserAgent != "" {
		return ""
	}
	return BrowserUserAgent
}

// AllowsPrivate reports whether every private destination is permitted.
func (c *Client) AllowsPrivate() bool { return c.opts.AllowPrivate }

// SameSite reports whether rawURL is on the target's registrable domain.
func (c *Client) SameSite(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && c.site != "" && registrable(u.Hostname()) == c.site
}

func registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

func (c *Client) inScope(u *url.URL) error {
	if !c.opts.SameSite || c.site == "" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range c.opts.AllowHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && (host == h || strings.HasSuffix(host, "."+h)) {
			return nil
		}
	}
	if registrable(host) == c.site {
		return nil
	}
	return &BlockedError{Host: host, Reason: "outside " + c.site + " (--same-site)"}
}

// guard runs after DNS resolution, so a hostname that resolves to an internal
// address is caught as well as a literal one.
func (c *Client) guard(_, address string, _ syscall.RawConn) error {
	if c.opts.AllowPrivate {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	ip, host := ap.Addr(), ap.Addr().String()
	if isPrivate(ip) && !c.privateOK[netip.AddrPortFrom(ip.Unmap(), ap.Port())] {
		return &BlockedError{Host: host, Reason: "private or internal address (use --allow-private)"}
	}
	return nil
}

// extraPrivate holds special-purpose ranges that netip has no predicate for.
var extraPrivate = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"; 0.0.0.0 reaches localhost on Linux
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved
}

// nat64 addresses embed an IPv4 address in the low 32 bits; it is checked
// as IPv4 so 64:ff9b::7f00:1 cannot reach 127.0.0.1.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func isPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, p := range extraPrivate {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Response is one downloaded resource.
type Response struct {
	Body            []byte
	SourceMapHeader string
	FinalURL        string
	ContentType     string
	Truncated       bool
}

// NotScript explains why a 200 response at a script URL is not JavaScript
// (an error or block page, an image, a stylesheet, an empty body, a storage
// error document), or returns "". Such a response means the real script was
// never seen.
func NotScript(r *Response) string { return notScript(r, false) }

// NotJSONModule is NotScript for an import with {type:"json"}.
func NotJSONModule(r *Response) string { return notScript(r, true) }

func notScript(r *Response, jsonModule bool) string {
	b := bytes.TrimPrefix(r.Body, []byte("\xef\xbb\xbf"))
	b = bytes.TrimSpace(b)
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.ContentType, ";", 2)[0]))
	jsType := strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
	switch {
	case jsonModule && ct == "application/json" || jsonModule && ct == "" && json.Valid(b):
		if json.Valid(b) {
			return ""
		}
		return "invalid JSON for a JSON module"
	case strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "font/") || ct == "text/css" || ct == "application/pdf":
		return "a " + ct + " response, not JavaScript"
	case binary(b):
		return "binary data, not JavaScript"
	case len(b) == 0:
		if jsType {
			// Rollup emits empty chunks; an empty script is still a script.
			return ""
		}
		return "empty response"
	case LooksLikeHTML(b) || ct == "text/html" && !looksLikeJS(b):
		return "HTML page, not JavaScript (error page, bot challenge or SPA fallback)"
	case bytes.HasPrefix(b, []byte("<?xml")) || bytes.Contains(bytes.ToLower(b[:min(len(b), 512)]), []byte("<error>")):
		return "XML error document, not JavaScript (e.g. S3 AccessDenied)"
	case b[0] == '{' && json.Valid(b):
		return "JSON document, not JavaScript (likely an API error)"
	case (ct == "text/plain" || ct == "application/xml" || ct == "text/xml") && !looksLikeJS(b):
		return "a " + ct + " response, not JavaScript: " + strconv.Quote(string(b[:min(len(b), 40)]))
	case !jsType && !looksLikeJS(b):
		return "not JavaScript: " + strconv.Quote(string(b[:min(len(b), 40)]))
	}
	return ""
}

// binary spots image and other binary bodies: a NUL in the first bytes, or a
// known file signature.
func binary(b []byte) bool {
	head := b[:min(len(b), 512)]
	if bytes.IndexByte(head, 0) >= 0 {
		return true
	}
	for _, sig := range [][]byte{[]byte("\x89PNG"), []byte("GIF8"), []byte("\xff\xd8\xff"), []byte("RIFF"), []byte("%PDF"), []byte("wOFF"), []byte("wOF2")} {
		if bytes.HasPrefix(b, sig) {
			return true
		}
	}
	return false
}

// jsShapes are constructs that only code has. Prose and block messages
// ("Forbidden (403)", "Access Denied (code=1020)") have brackets and the odd
// "=", but not a declaration, a function, an arrow or a member call.
var jsShapes = regexp.MustCompile(`\b(?:var|let|const)\s+[\w$\[{]|\bfunction\s*\*?\s*[\w$]*\s*\([^)]*\)\s*\{|=>|` +
	`\b(?:import|export)\s*[\w${*"'(]|\b(?:typeof|instanceof)\b|["']use strict["']|//[#@] ?sourceMappingURL|` +
	`[\w$\])]\.[A-Za-z_$][\w$]*\s*(?:\(|=[^=])|[\w$]\([^()\n]*\)\s*;|\breturn\s[^\n;]{0,80};`)

// looksLikeJS is a cheap sniff for an unlabelled or mislabelled body. A
// licence or banner comment of any length is skipped first.
func looksLikeJS(b []byte) bool {
	b = skipComments(b)
	return jsShapes.Match(b[:min(len(b), 2048)])
}

// skipComments drops leading whitespace and comments.
func skipComments(b []byte) []byte {
	for {
		b = bytes.TrimLeft(b, " \t\r\n")
		switch {
		case bytes.HasPrefix(b, []byte("/*")):
			e := bytes.Index(b[2:], []byte("*/"))
			if e < 0 {
				return nil
			}
			b = b[e+4:]
		case bytes.HasPrefix(b, []byte("//")) && !bytes.HasPrefix(b, []byte("//#")) && !bytes.HasPrefix(b, []byte("//@")):
			e := bytes.IndexByte(b, '\n')
			if e < 0 {
				return nil
			}
			b = b[e+1:]
		default:
			return b
		}
	}
}

// LooksLikeHTML sniffs the start of a body for an HTML document, skipping
// leading HTML comments (<!-- build 2026 --> before the doctype). A
// JavaScript file that opens with a legacy <!-- comment is not HTML.
func LooksLikeHTML(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	for i := 0; i < 8; i++ {
		b = bytes.TrimLeft(b, " \t\r\n")
		if !bytes.HasPrefix(b, []byte("<!--")) {
			break
		}
		end := bytes.Index(b, []byte("-->"))
		if end < 0 {
			return false
		}
		b = b[end+3:]
	}
	if len(b) > 64 {
		b = b[:64]
	}
	l := bytes.ToLower(b)
	for _, p := range []string{"<!doctype html", "<html", "<head", "<body", "<title", "<meta", "<h1", "<p>", "<div", "<center"} {
		if bytes.HasPrefix(l, []byte(p)) {
			return true
		}
	}
	return false
}

// Get downloads rawURL, retrying once on a network error, 429 or 5xx.
func (c *Client) Get(rawURL string) (*Response, error) { return c.GetAs(rawURL, c.ua) }

// GetAs is Get with another user agent.
func (c *Client) GetAs(rawURL, ua string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := c.inScope(u); err != nil {
		return nil, err
	}
	resp, err := c.get(rawURL, ua)
	if err != nil && retryable(err) && (c.deadline.IsZero() || time.Now().Add(c.retryGap).Before(c.deadline)) {
		time.Sleep(c.retryGap)
		resp, err = c.get(rawURL, ua)
	}
	return resp, err
}

func retryable(err error) bool {
	if IsBlocked(err) {
		return false
	}
	switch s := StatusOf(err); {
	case s == 0:
		return true
	case s == 429 || s >= 500:
		return true
	}
	return false
}

func (c *Client) get(rawURL, ua string) (*Response, error) {
	ctx := context.Background()
	if !c.deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, c.deadline)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Drain a little so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, &HTTPError{URL: rawURL, Status: resp.StatusCode}
	}
	limit := c.opts.MaxBody
	if limit <= 0 {
		limit = DefaultMaxBody
	}
	// net/http only undoes the gzip it asked for itself. Servers also send
	// deflate, double gzip or gzip nobody asked for, so decode those here.
	// Anything else (br, zstd) would be scanned as compressed bytes and find
	// nothing, so it is an error.
	body, err := decodeBody(resp.Body, resp.Header.Get("Content-Encoding"))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %v", rawURL, err)
	}
	b, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	out := &Response{
		FinalURL:    resp.Request.URL.String(),
		ContentType: resp.Header.Get("Content-Type"),
	}
	if len(b) > limit {
		b = b[:limit]
		out.Truncated = true
	}
	out.Body = b
	out.SourceMapHeader = resp.Header.Get("SourceMap")
	if out.SourceMapHeader == "" {
		out.SourceMapHeader = resp.Header.Get("X-SourceMap")
	}
	return out, nil
}

// decodeBody undoes a Content-Encoding chain ("gzip", "deflate",
// "gzip, deflate"), last applied first.
func decodeBody(r io.Reader, header string) (io.Reader, error) {
	var codings []string
	for _, c := range strings.Split(header, ",") {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" && c != "identity" {
			codings = append(codings, c)
		}
	}
	for i := len(codings) - 1; i >= 0; i-- {
		switch codings[i] {
		case "gzip", "x-gzip":
			z, err := gzip.NewReader(r)
			if err != nil {
				return nil, fmt.Errorf("bad gzip body: %v", err)
			}
			r = z
		case "deflate":
			// Meant to be zlib-wrapped, but some servers send raw deflate.
			// A zlib header has CM=8 in the low nibble and the first two
			// bytes divisible by 31.
			br := bufio.NewReader(r)
			if head, err := br.Peek(2); err == nil && head[0]&0x0f == 8 && (uint16(head[0])<<8|uint16(head[1]))%31 == 0 {
				z, err := zlib.NewReader(br)
				if err != nil {
					return nil, fmt.Errorf("bad deflate body: %v", err)
				}
				r = z
			} else {
				r = flate.NewReader(br)
			}
		default:
			return nil, fmt.Errorf("unsupported Content-Encoding %q", header)
		}
	}
	return r, nil
}

// Inline is a script whose code is in the page itself: a <script> body or a
// data: URL in src.
type Inline struct {
	Label string
	Code  []byte
}

// Page is what Enumerate found in an HTML page.
type Page struct {
	URL      string
	FinalURL string
	// Base is what relative references in the page resolve against: the
	// final URL, or <base href> when the page sets one.
	Base    string
	Scripts []string
	Inline  []Inline
	Frames  []string
	// ImportMap is the page's <script type="importmap">.
	ImportMap *ImportMap
	// HTML is the page itself, scanned for secrets outside scripts.
	HTML []byte
	// Direct is set when the target URL is itself a script.
	Direct *Response
	// Challenge is set when the page looks like a bot-management interstitial
	// rather than the site itself.
	Challenge string
	Truncated bool
	// Hints are script URLs named outside <script src>: island and hydration
	// attributes (Astro component-url, Qwik on:click, Vite legacy data-src)
	// and any other attribute holding a .js URL.
	Hints []Hint
	// Refresh is the target of a <meta http-equiv="refresh">.
	Refresh string
}

// Hint is a script URL found in an attribute. Exact hints come from
// attributes a framework loads from; the rest are guesses.
type Hint struct {
	URL   string
	Exact bool
}

// Enumerate fetches pageURL and lists its scripts, frames and import map. A
// URL that serves JavaScript comes back as Page.Direct instead.
func (c *Client) Enumerate(pageURL string) (*Page, error) { return c.EnumerateAs(pageURL, c.ua) }

// EnumerateAs is Enumerate with another user agent.
func (c *Client) EnumerateAs(pageURL, ua string) (*Page, error) {
	resp, err := c.GetAs(pageURL, ua)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(resp.FinalURL)
	if err != nil {
		return nil, err
	}
	if isDirectScript(base, resp) {
		return &Page{URL: pageURL, FinalURL: resp.FinalURL, Base: resp.FinalURL, Direct: resp, Truncated: resp.Truncated}, nil
	}
	p := enumerate(pageURL, base, resp.Body)
	p.FinalURL = resp.FinalURL
	p.Truncated = resp.Truncated
	p.HTML = resp.Body
	return p, nil
}

// isDirectScript reports whether the target URL served JavaScript rather than
// a page, so it is scanned as a bundle instead of parsed as HTML.
func isDirectScript(u *url.URL, r *Response) bool {
	if LooksLikeHTML(r.Body) {
		return false
	}
	ct := strings.ToLower(r.ContentType)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".cjs")
}

// enumerate uses the html tokenizer rather than a regex so commented-out
// scripts, unquoted src attributes and '>' inside inline code parse the way a
// browser parses them.
func enumerate(pageURL string, base *url.URL, body []byte) *Page {
	p := &Page{URL: pageURL, ImportMap: &ImportMap{}}
	var st pageStats
	defer func() {
		p.Base = base.String()
		p.Challenge = challenge(body, st)
	}()
	seen := map[string]bool{}
	baseSet := false
	// Qwik names its chunks relative to the q:base of the container they
	// sit in; a page can hold several containers.
	type qref struct{ file, base string }
	type qscope struct {
		depth int
		base  string
	}
	qBase := ""
	var qwik []qref
	var qStack []qscope
	depth := 0
	hinted := map[string]bool{}
	hint := func(ref string, exact bool) {
		if abs := resolve(base, ref); abs != "" && !hinted[abs] && !seen[abs] {
			hinted[abs] = true
			p.Hints = append(p.Hints, Hint{URL: abs, Exact: exact})
		}
	}
	defer func() {
		for _, q := range qwik {
			qb, b := base, q.base
			if b == "" {
				b = qBase
			}
			if u, err := url.Parse(strings.TrimSpace(b)); err == nil && b != "" {
				qb = base.ResolveReference(u)
			}
			if abs := resolve(qb, q.file); abs != "" && !hinted[abs] {
				hinted[abs] = true
				p.Hints = append(p.Hints, Hint{URL: abs, Exact: true})
			}
		}
	}()
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if strings.HasPrefix(strings.ToLower(ref), "data:") {
			if code := DecodeDataURI(ref); len(bytes.TrimSpace(code)) > 0 {
				p.Inline = append(p.Inline, Inline{Label: fmt.Sprintf("(data: script #%d)", len(p.Inline)+1), Code: code})
			}
			return
		}
		if abs := resolve(base, ref); abs != "" && !seen[abs] {
			seen[abs] = true
			p.Scripts = append(p.Scripts, abs)
		}
	}
	tz := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := tz.Next()
		if tt == html.ErrorToken {
			return p
		}
		if tt == html.EndTagToken {
			depth--
			for len(qStack) > 0 && qStack[len(qStack)-1].depth > depth {
				qStack = qStack[:len(qStack)-1]
			}
			continue
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := tz.TagName()
		attrs := map[string]string{}
		for hasAttr {
			var k, v []byte
			k, v, hasAttr = tz.TagAttr()
			key := strings.ToLower(string(k))
			if _, dup := attrs[key]; !dup {
				attrs[key] = string(v)
			}
		}
		void := tt == html.SelfClosingTagToken || voidElements[string(name)]
		if !void {
			depth++
		}
		if b, ok := attrs["q:base"]; ok {
			if qBase == "" {
				qBase = b
			}
			if !void {
				qStack = append(qStack, qscope{depth, b})
			}
		}
		for k, v := range attrs {
			switch {
			case k == "q:base":
			case strings.HasPrefix(k, "on:") || strings.HasPrefix(k, "on-window:") || strings.HasPrefix(k, "on-document:"):
				// on:click="q-Ab12.js#s_click[0]", one or more per line.
				cur := ""
				if len(qStack) > 0 {
					cur = qStack[len(qStack)-1].base
				}
				for _, part := range strings.Fields(v) {
					if f, _, _ := strings.Cut(part, "#"); jsURL(f) {
						qwik = append(qwik, qref{f, cur})
					}
				}
			case k == "component-url" || k == "renderer-url" || k == "before-hydration-url" || k == "data-src" && string(name) == "script":
				if jsURL(v) {
					hint(v, true)
				}
			case k == "src" && string(name) == "script", k == "href" && string(name) == "link", k == "src" && (string(name) == "iframe" || string(name) == "frame"):
				// Handled per tag below.
			case k == "content" && strings.EqualFold(attrs["http-equiv"], "refresh"):
				if _, u, ok := strings.Cut(v, "="); ok && strings.Contains(strings.ToLower(v), "url") {
					if abs := resolve(base, strings.Trim(strings.TrimSpace(u), `'"`)); abs != "" {
						p.Refresh = abs
					}
				}
			default:
				if jsURL(v) && (strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "http")) {
					hint(v, false)
				}
			}
		}
		switch string(name) {
		case "form":
			st.forms++
		case "input":
			switch strings.ToLower(attrs["type"]) {
			case "hidden":
				st.hidden++
			case "submit", "button", "image":
			default:
				st.visible++
			}
		case "button", "select", "textarea":
			// Something to click or choose: a page for people, not a
			// token round-trip.
			st.visible++
		case "a", "img", "nav", "article", "section", "main", "p", "h1", "h2", "ul":
			st.content++
		case "base":
			// Only the first <base href> counts, as in a browser.
			if h, ok := attrs["href"]; ok && !baseSet {
				if u, err := url.Parse(strings.TrimSpace(h)); err == nil {
					base = base.ResolveReference(u)
					baseSet = true
				}
			}
		case "iframe", "frame":
			if abs := resolve(base, attrs["src"]); abs != "" {
				p.Frames = append(p.Frames, abs)
			}
		case "link":
			rel := " " + strings.ToLower(attrs["rel"]) + " "
			if strings.Contains(rel, " modulepreload ") ||
				(strings.Contains(rel, " preload ") && strings.EqualFold(strings.TrimSpace(attrs["as"]), "script")) {
				add(attrs["href"])
			}
		case "script":
			if src, ok := attrs["src"]; ok && strings.TrimSpace(src) != "" {
				st.scripts++
				add(src)
				continue
			}
			if strings.EqualFold(strings.TrimSpace(attrs["type"]), "importmap") {
				if tz.Next() == html.TextToken {
					parseImportMap(tz.Text(), base, p.ImportMap)
				}
				continue
			}
			if tt == html.SelfClosingTagToken {
				continue
			}
			// The tokenizer returns an inline script's body as the next text token.
			if tz.Next() == html.TextToken {
				if inner := tz.Text(); len(bytes.TrimSpace(inner)) > 0 {
					p.Inline = append(p.Inline, Inline{
						Label: fmt.Sprintf("(inline script #%d)", len(p.Inline)+1),
						Code:  append([]byte(nil), inner...),
					})
				}
			}
		}
	}
}

// voidElements have no end tag.
var voidElements = map[string]bool{"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true}

// jsURL reports whether an attribute value is a script URL: no spaces, and
// a path ending in .js or .mjs before any query or fragment.
func jsURL(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, " \t\n<>\"'`") {
		return false
	}
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	return strings.HasSuffix(v, ".js") || strings.HasSuffix(v, ".mjs")
}

// challengeMarkers are strings only a bot-management interstitial carries; a
// scan of such a page has not seen the site. Vendor scripts, preconnects, CSS
// rules and title words also appear on ordinary pages behind the same vendor
// (Cloudflare's challenge-platform/.../scripts/jsd/ bot detection, a DataDome
// preconnect, a #px-captcha CSS rule, an Incapsula resource script, a blog
// post quoting "Pardon Our Interruption"), so none of those count.
var challengeMarkers = []struct{ needle, vendor string }{
	{"window._cf_chl_opt", "Cloudflare challenge"},
	{"challenge-platform/h/b/orchestrate/", "Cloudflare challenge"},
	{"challenge-platform/h/g/orchestrate/", "Cloudflare challenge"},
	{"captcha-delivery.com/captcha", "DataDome challenge"},
	{"ct.captcha-delivery.com/c.js", "DataDome challenge"},
	{`id="px-captcha"`, "PerimeterX challenge"},
	{"captcha.px-cdn.net", "PerimeterX challenge"},
	{"incapsula incident id", "Imperva challenge"},
	{"sec-if-cpt-container", "Akamai challenge"},
	{"/_sec/verify?provider=interstitial", "Akamai challenge"},
	{"<title>pardon our interruption</title>", "Imperva (Distil) block page"},
}

// weakChallengeMarkers also turn up on ordinary pages (sites load the AWS WAF
// SDK for bot control), so they count only on a page shaped like an
// interstitial.
var weakChallengeMarkers = []struct{ needle, vendor string }{
	{"awswaf.com/", "AWS WAF challenge"},
	{"js_challenge", "JavaScript challenge"},
	{"jsc_token", "JavaScript challenge"},
	{"challenge-form", "challenge"},
	{"checking your browser", "browser check"},
	{"verify you are human", "human verification"},
	{"please enable javascript and cookies", "browser check"},
	{"proof-of-work", "proof-of-work challenge"},
	{"bm-verify", "Akamai challenge"},
	{"kpsdk", "Kasada challenge"},
	{"ips.js?kp_uidz", "Kasada challenge"},
}

// ChallengeMarker names the bot-management vendor whose interstitial body is, or "".
func ChallengeMarker(body []byte) string {
	head := body
	if len(head) > 64<<10 {
		head = head[:64<<10]
	}
	l := bytes.ToLower(head)
	for _, m := range challengeMarkers {
		if bytes.Contains(l, []byte(m.needle)) {
			return m.vendor
		}
	}
	return ""
}

type pageStats struct{ forms, hidden, visible, scripts, content int }

// challenge decides whether a page is an interstitial rather than the site.
// Besides vendor markers, the general shape is a small page whose only form
// is hidden fields (a proof-of-work or token round-trip) and that has almost
// no content or scripts of its own.
func challenge(body []byte, st pageStats) string {
	if v := ChallengeMarker(body); v != "" {
		return v
	}
	small := len(body) < 64<<10 && st.scripts <= 3 && st.content <= 10
	if !small {
		return ""
	}
	l := bytes.ToLower(body)
	for _, m := range weakChallengeMarkers {
		if bytes.Contains(l, []byte(m.needle)) {
			return m.vendor
		}
	}
	if st.forms > 0 && st.hidden >= 2 && st.visible == 0 && st.scripts <= 1 {
		return "hidden-form challenge"
	}
	return ""
}

// ImportMap holds a page's import map with its keys normalised the way a
// browser does it: a URL-like key ("/assets/x.js", "./lib/") is resolved
// against the page, so it matches the specifiers that resolve to it.
type ImportMap struct {
	Imports map[string]string
	Scopes  map[string]map[string]string
}

// parseImportMap adds one <script type="importmap"> to m. When a page has
// several, an earlier entry wins.
func parseImportMap(raw []byte, base *url.URL, m *ImportMap) {
	var im struct {
		Imports map[string]string            `json:"imports"`
		Scopes  map[string]map[string]string `json:"scopes"`
	}
	if json.Unmarshal(raw, &im) != nil {
		return
	}
	norm := func(dst map[string]string, src map[string]string) map[string]string {
		if dst == nil {
			dst = map[string]string{}
		}
		for k, v := range src {
			if nk := normalizeSpecifier(base, k); nk != "" {
				if _, dup := dst[nk]; !dup {
					if abs := resolve(base, v); abs != "" {
						dst[nk] = abs
					}
				}
			}
		}
		return dst
	}
	m.Imports = norm(m.Imports, im.Imports)
	for scope, imports := range im.Scopes {
		if s := resolve(base, scope); s != "" {
			if m.Scopes == nil {
				m.Scopes = map[string]map[string]string{}
			}
			m.Scopes[s] = norm(m.Scopes[s], imports)
		}
	}
}

// urlLike reports whether a specifier is a URL or a path ("/x", "./x",
// "../x") rather than a bare name.
func urlLike(spec string) bool {
	if strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
		return true
	}
	u, err := url.Parse(spec)
	return err == nil && u.Scheme != "" && u.Opaque == "" && u.Host != ""
}

func normalizeSpecifier(base *url.URL, spec string) string {
	if urlLike(spec) {
		return resolve(base, spec)
	}
	return spec
}

// Resolve maps a module specifier imported by referrer the way a browser
// does: a URL-like specifier is first resolved against the referrer; then
// the most specific scope that covers the referrer, and then the top-level
// imports, are searched for the exact key or the longest key ending in "/".
// It returns "" for a bare specifier the map does not cover.
func (m *ImportMap) Resolve(spec, referrer string) string {
	key := spec
	asURL := ""
	if urlLike(spec) {
		asURL = Resolve(referrer, spec)
		if asURL == "" {
			return ""
		}
		key = asURL
	}
	if m != nil {
		scopes := make([]string, 0, len(m.Scopes))
		for sc := range m.Scopes {
			if referrer == sc || strings.HasSuffix(sc, "/") && strings.HasPrefix(referrer, sc) {
				scopes = append(scopes, sc)
			}
		}
		sort.Slice(scopes, func(i, j int) bool { return len(scopes[i]) > len(scopes[j]) })
		for _, sc := range scopes {
			if v := ResolveBare(m.Scopes[sc], key); v != "" {
				return v
			}
		}
		if v := ResolveBare(m.Imports, key); v != "" {
			return v
		}
	}
	return asURL
}

// ResolveBare looks a specifier up in one import-map table: an exact key,
// or the longest key ending in "/" that prefixes it.
func ResolveBare(m map[string]string, spec string) string {
	if v, ok := m[spec]; ok {
		return v
	}
	best := ""
	for k := range m {
		if strings.HasSuffix(k, "/") && strings.HasPrefix(spec, k) && len(k) > len(best) {
			best = k
		}
	}
	if best == "" {
		return ""
	}
	return m[best] + spec[len(best):]
}

// The spec form is a line comment; some bundlers emit the /*# ... */ form.
var sourceMapRe = regexp.MustCompile(`(?m)(?://[#@]|/\*[#@])[ \t]*sourceMappingURL=([^\s'"` + "`" + `*]+)`)

// FindSourceMapURL returns the map reference for a script. The SourceMap
// header wins over the comment, and the last comment wins over earlier ones.
func FindSourceMapURL(js []byte, header string) string {
	if h := strings.TrimSpace(header); h != "" {
		return h
	}
	m := sourceMapRe.FindAllSubmatch(js, -1)
	for i := len(m) - 1; i >= 0; i-- {
		ref := strings.TrimSpace(string(m[i][1]))
		// A bundler that writes the comment itself (source-map libraries,
		// dev tooling) leaves string concatenation behind, not a URL.
		if ref == "" || !strings.HasPrefix(ref, "data:") && strings.ContainsAny(ref, "+${}()<>\\") {
			continue
		}
		return ref
	}
	return ""
}

// DecodeDataURI returns the payload of a data: URL, or nil if it is malformed.
func DecodeDataURI(u string) []byte {
	i := strings.IndexByte(u, ',')
	if i < 0 {
		return nil
	}
	meta, payload := strings.ToLower(u[:i]), u[i+1:]
	if strings.HasSuffix(meta, ";base64") {
		payload = strings.TrimSpace(payload)
		if p, err := url.PathUnescape(payload); err == nil {
			payload = p
		}
		payload = strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, payload)
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(payload); err == nil {
				return b
			}
		}
		return nil
	}
	if p, err := url.PathUnescape(payload); err == nil {
		return []byte(p)
	}
	return []byte(payload)
}

// Resolve resolves ref against pageURL. It returns "" for anything that is
// not http(s), except data: URLs, which are returned as-is.
func Resolve(pageURL, ref string) string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	return resolve(base, ref)
}

func resolve(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(strings.ToLower(ref), "data:") {
		return ref
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}
