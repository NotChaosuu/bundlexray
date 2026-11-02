package fetch

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func local() *Client {
	c := New(Options{Timeout: 5 * time.Second, AllowPrivate: true})
	c.retryGap = time.Millisecond
	return c
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestEnumerateFindsScriptsAndInline(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head>
			<script src="/assets/app.js"></script>
			<script src="https://cdn.example.com/vendor.js"></script>
			<script>window.API="/api/v1";</script>
			</head></html>`))
	})
	p, err := local().Enumerate(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Scripts) != 2 || !strings.HasSuffix(p.Scripts[0], "/assets/app.js") {
		t.Fatalf("want 2 resolved external scripts, got %v", p.Scripts)
	}
	if len(p.Inline) != 1 || !strings.Contains(string(p.Inline[0].Code), "/api/v1") {
		t.Errorf("inline script not captured: %v", p.Inline)
	}
}

// Cases a regex-based extractor gets wrong.
func TestEnumerateTrickyMarkup(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head>
			<!-- <script src="/should-not-count.js"></script> -->
			<script src=/unquoted/app.js></script>
			<script type="module" src="/mod.js"></script>
			<script>if (a > b) { fetch("/api/secret"); }</script>
			</head></html>`))
	})
	p, err := local().Enumerate(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(p.Scripts, " ")
	if strings.Contains(joined, "should-not-count") {
		t.Errorf("a commented-out <script> must not be extracted: %v", p.Scripts)
	}
	if !strings.Contains(joined, "/unquoted/app.js") || !strings.Contains(joined, "/mod.js") {
		t.Errorf("unquoted or module src missing: %v", p.Scripts)
	}
	if len(p.Inline) != 1 || !strings.Contains(string(p.Inline[0].Code), "/api/secret") {
		t.Errorf("inline script with '>' not captured whole: %v", p.Inline)
	}
}

// Relative scripts resolve against the page the browser lands on after
// redirects, and against <base href> when the page sets one.
func TestEnumerateResolvesLikeABrowser(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/en/home/", http.StatusFound)
		case "/en/home/":
			w.Write([]byte(`<script src="app.js"></script>`))
		case "/b":
			w.Write([]byte(`<base href="/static/v2/"><script src="main.js"></script>`))
		}
	})
	p, err := local().Enumerate(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Scripts) != 1 || p.Scripts[0] != srv.URL+"/en/home/app.js" {
		t.Errorf("relative src must resolve against the final URL: %v", p.Scripts)
	}
	p, _ = local().Enumerate(srv.URL + "/b")
	if len(p.Scripts) != 1 || p.Scripts[0] != srv.URL+"/static/v2/main.js" {
		t.Errorf("<base href> ignored: %v", p.Scripts)
	}
}

// A data: src is code in the page, not something to download.
func TestEnumerateDataAndPreloadScripts(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<script src="data:text/javascript,var%20a%3D%22/api/x%22"></script>
			<script src="data:text/javascript;base64,dmFyIGI9MQ=="></script>
			<link rel="modulepreload" href="/chunk-a.js"><link rel="preload" as="script" href="/chunk-b.js">
			<link rel="preload" as="style" href="/x.css">`))
	})
	p, err := local().Enumerate(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Inline) != 2 || string(p.Inline[0].Code) != `var a="/api/x"` || string(p.Inline[1].Code) != "var b=1" {
		t.Errorf("data: scripts not decoded inline: %+v", p.Inline)
	}
	if len(p.Scripts) != 2 {
		t.Errorf("want the two preloaded chunks only, got %v", p.Scripts)
	}
}

func TestEnumerateFlagsChallengePage(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><title>Just a moment...</title></head><body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/x.js"></script></body></html>`))
	})
	p, err := local().Enumerate(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if p.Challenge == "" {
		t.Error("a Cloudflare interstitial must be flagged")
	}
}

func TestGetReportsStatusAndSourceMapHeader(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gone.js" {
			http.Error(w, "nope", http.StatusForbidden)
			return
		}
		w.Header().Set("SourceMap", "app.js.map")
		w.Write([]byte("console.log(1)"))
	})
	resp, err := local().Get(srv.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "console.log(1)" || resp.SourceMapHeader != "app.js.map" {
		t.Errorf("got body %q header %q", resp.Body, resp.SourceMapHeader)
	}
	_, err = local().Get(srv.URL + "/gone.js")
	if StatusOf(err) != 403 {
		t.Errorf("want HTTP 403 in the error, got %v", err)
	}
}

func TestGetRetriesTransientFailures(t *testing.T) {
	var n int32
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	if _, err := local().Get(srv.URL + "/x.js"); err != nil || n != 2 {
		t.Errorf("want success on the retry, got err=%v after %d requests", err, n)
	}
}

func TestGetFlagsTruncationAndEncodedBodies(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/br.js" {
			w.Header().Set("Content-Encoding", "br")
		}
		w.Write([]byte(strings.Repeat("a", 100)))
	})
	c := New(Options{Timeout: 5 * time.Second, AllowPrivate: true, MaxBody: 10})
	resp, err := c.Get(srv.URL + "/big.js")
	if err != nil || !resp.Truncated || len(resp.Body) != 10 {
		t.Errorf("want a truncated 10-byte body, got %v %+v", err, resp)
	}
	if _, err := c.Get(srv.URL + "/br.js"); err == nil {
		t.Error("an undecoded Content-Encoding must be an error, not scanned as text")
	}
}

// A page can point at internal services; they are refused unless the
// target itself is internal or --allow-private is set.
func TestPrivateAddressesBlocked(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret")) })
	c := New(Options{Timeout: 5 * time.Second})
	_, err := c.Get(srv.URL + "/metadata.js")
	if !IsBlocked(err) {
		t.Fatalf("loopback fetch must be blocked by default, got %v", err)
	}
	u, _ := url.Parse(srv.URL)
	c.SetTarget(u)
	if _, err := c.Get(srv.URL + "/metadata.js"); err != nil {
		t.Errorf("a loopback target should allow loopback fetches: %v", err)
	}
}

func TestIsPrivate(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "192.168.0.1": true, "169.254.169.254": true,
		"100.64.0.1": true, "::1": true, "fd00::1": true, "::ffff:10.0.0.1": true, "64:ff9b::a9fe:a9fe": true,
		"8.8.8.8": false, "2606:4700::1111": false,
	} {
		if got := isPrivate(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPrivate(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestSameSiteScope(t *testing.T) {
	c := New(Options{SameSite: true, AllowHosts: []string{"cdn.example.net"}})
	c.SetTarget(&url.URL{Scheme: "https", Host: "www.shop.co.uk"})
	for raw, ok := range map[string]bool{
		"https://static.shop.co.uk/a.js":   true,
		"https://cdn.example.net/a.js":     true,
		"https://img.cdn.example.net/a.js": true,
		"https://evil.co.uk/a.js":          false,
		"https://shop.co.uk.attacker.io/x": false,
	} {
		u, _ := url.Parse(raw)
		if err := c.inScope(u); (err == nil) != ok {
			t.Errorf("inScope(%s) = %v, want allowed=%v", raw, err, ok)
		}
	}
}

func TestFindSourceMapURL(t *testing.T) {
	js := []byte("var x=1;\n//# sourceMappingURL=app.min.js.map\n")
	if got := FindSourceMapURL(js, ""); got != "app.min.js.map" {
		t.Errorf("from comment: got %q", got)
	}
	if got := FindSourceMapURL(js, "header.map"); got != "header.map" {
		t.Errorf("header should win: got %q", got)
	}
	if got := FindSourceMapURL([]byte("no map here"), ""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
	// A library that writes the comment itself leaves concatenation behind.
	lib := []byte(`e+="\n//# sourceMappingURL="+t;` + "\n/*# sourceMappingURL=real.js.map */")
	if got := FindSourceMapURL(lib, ""); got != "real.js.map" {
		t.Errorf("want the real map, got %q", got)
	}
	inline := []byte("x\n//# sourceMappingURL=data:application/json;base64,eyJ2+ZXJ/zaW9uIjozfQ==")
	if got := FindSourceMapURL(inline, ""); !strings.HasPrefix(got, "data:") || !strings.Contains(got, "+") {
		t.Errorf("inline base64 map must survive the filter: %q", got)
	}
}

func TestResolve(t *testing.T) {
	if got := Resolve("https://x.com/a/b.html", "../assets/app.js"); got != "https://x.com/assets/app.js" {
		t.Errorf("resolve = %q", got)
	}
	if got := Resolve("https://x.com/", "javascript:void(0)"); got != "" {
		t.Errorf("non-http scheme should resolve empty, got %q", got)
	}
}

// A private target unlocks its own address only, never the metadata service
// or the rest of the private ranges.
func TestPrivateTargetUnlocksOnlyItself(t *testing.T) {
	c := New(Options{Timeout: time.Second})
	c.SetTarget(&url.URL{Scheme: "http", Host: "127.0.0.1:8080"})
	if err := c.guard("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Errorf("target's own address blocked: %v", err)
	}
	for _, a := range []string{"169.254.169.254:80", "10.0.0.1:80", "192.168.1.1:443", "[::1]:80"} {
		if err := c.guard("tcp", a, nil); !IsBlocked(err) {
			t.Errorf("%s reachable after a 127.0.0.1 target", a)
		}
	}
}

func TestNotScript(t *testing.T) {
	cases := map[string]bool{
		"":                                true,
		"  \n":                            true,
		"<!-- x --><!DOCTYPE html>":       true,
		`{"error":"forbidden"}`:           true,
		"<?xml version=\"1.0\"?><Error/>": true,
		"<title>403</title>":              true,
		"var a=1;":                        false,
		"(function(){})()":                false,
		// An unlabelled body needs something only code has; a bare
		// object literal or a bracketed status message is not enough.
		"{a:1}":                                             true,
		"Forbidden (403)":                                   true,
		"Error (429): Too Many Requests":                    true,
		"Access Denied (code=1020)":                         true,
		"Request blocked (ref: 18.5c2e). Bye.":              true,
		"You cannot access this page (error: 1020); sorry.": true,
		"a.b=1;":        false,
		"x({\"a\":1});": false,
		"/*! lic */\n" + strings.Repeat("// licence text\n", 300) + "var q=1;": false,
		"'use strict';exports.x=1": false,
	}
	for body, want := range cases {
		if got := NotScript(&Response{Body: []byte(body)}) != ""; got != want {
			t.Errorf("NotScript(%q) = %v, want %v", body, got, want)
		}
	}
}

// The private allowance covers the target's own address and port only.
func TestPrivateAllowanceIsPortScoped(t *testing.T) {
	c := New(Options{Timeout: time.Second})
	c.SetTarget(&url.URL{Scheme: "http", Host: "127.0.0.1:8080"})
	if err := c.guard("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Errorf("target port blocked: %v", err)
	}
	for _, a := range []string{"127.0.0.1:6379", "[::ffff:127.0.0.1]:8081", "127.0.0.1:80"} {
		if err := c.guard("tcp", a, nil); !IsBlocked(err) {
			t.Errorf("%s reachable from a 127.0.0.1:8080 target", a)
		}
	}
	if err := c.guard("tcp", "[::ffff:127.0.0.1]:8080", nil); err != nil {
		t.Errorf("mapped form of the target blocked: %v", err)
	}
}

func TestResolveBare(t *testing.T) {
	m := map[string]string{"app": "https://x/app.js", "lib/": "https://x/vendor/", "lib/deep/": "https://y/d/"}
	for spec, want := range map[string]string{
		"app": "https://x/app.js", "lib/u.js": "https://x/vendor/u.js", "lib/deep/k.js": "https://y/d/k.js", "other": "",
	} {
		if got := ResolveBare(m, spec); got != want {
			t.Errorf("ResolveBare(%q) = %q, want %q", spec, got, want)
		}
	}
}

// Interstitials from Akamai, Kasada and Imperva are caught; a normal page
// with Cloudflare's detection script, a Rails button_to form or a language
// form is not an interstitial.
func TestChallengeDetection(t *testing.T) {
	u, _ := url.Parse("https://shop.example/")
	cases := map[string]bool{
		`<html><body><script>xhr.open('POST','/_sec/verify?provider=interstitial',false)</script></body></html>`:                                                                                                                                                                                   true,
		`<html><head><script>window.KPSDK={};</script><script src="/1/2/ips.js?KP_UIDz=a"></script></head><body></body></html>`:                                                                                                                                                                    true,
		`<html><head><script>window.KPSDK={};KPSDK.start=1;</script><script src="/1/2/p.js"></script></head><body></body></html>`:                                                                                                                                                                  true,
		`<html><head><title>Pardon Our Interruption</title></head><body><h1>Pardon Our Interruption</h1></body></html>`:                                                                                                                                                                            true,
		`<html><body><form method=post><input type=hidden name=a><input type=hidden name=b></form></body></html>`:                                                                                                                                                                                  true,
		`<html><head><script src="/app.js"></script></head><body><div id=root></div><script>a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'</script></body></html>`:                                                                                                                        false,
		`<html><head><script src="/app.js"></script></head><body><h1>Signed in</h1><form class="button_to" method="post"><input type="hidden" name="_method" value="delete"><button type="submit">Sign out</button><input type="hidden" name="authenticity_token" value="x"></form></body></html>`: false,
		`<html><head><script src="/app.js"></script></head><body><form method="post"><input type="hidden" name="csrf"><input type="hidden" name="r"><select name="lang"><option>en</option></select></form></body></html>`:                                                                         false,
	}
	for body, want := range cases {
		if got := enumerate(u.String(), u, []byte(body)).Challenge != ""; got != want {
			t.Errorf("challenge=%v want %v: %.90s", got, want, body)
		}
	}
}

// Import maps resolve URL-like specifiers and keys, prefixes and scopes the
// way a browser does.
func TestImportMapResolve(t *testing.T) {
	base, _ := url.Parse("https://x.com/app/")
	m := &ImportMap{}
	parseImportMap([]byte(`{"imports":{"/a.js":"/a-1.js","./lib/":"/v2/lib/","react":"https://cdn/react.js"},"scopes":{"/admin/":{"react":"/admin/react.js"}}}`), base, m)
	cases := []struct{ spec, ref, want string }{
		{"/a.js", "https://x.com/app/main.js", "https://x.com/a-1.js"},
		{"../a.js", "https://x.com/app/main.js", "https://x.com/a-1.js"},
		{"./lib/u.js", "https://x.com/app/main.js", "https://x.com/v2/lib/u.js"},
		{"react", "https://x.com/app/main.js", "https://cdn/react.js"},
		{"react", "https://x.com/admin/p.js", "https://x.com/admin/react.js"},
		{"./other.js", "https://x.com/app/main.js", "https://x.com/app/other.js"},
		{"unmapped", "https://x.com/app/main.js", ""},
	}
	for _, c := range cases {
		if got := m.Resolve(c.spec, c.ref); got != c.want {
			t.Errorf("Resolve(%q from %q) = %q, want %q", c.spec, c.ref, got, c.want)
		}
	}
}

// Vendor scripts, preconnects, CSS rules and quoted words on an ordinary
// page are not interstitials; the interstitials themselves still are.
func TestChallengeMarkersNeedTheInterstitial(t *testing.T) {
	u, _ := url.Parse("https://blog.example/")
	normal := []string{
		`<html><head><link rel="preconnect" href="https://geo.captcha-delivery.com"></head><body><p>post</p><script src="/app.js"></script></body></html>`,
		`<html><head><style>#px-captcha{margin:0}</style></head><body><p>post</p><script src="/app.js"></script></body></html>`,
		`<html><head><script src="/_Incapsula_Resource?SWJIYLWA=1"></script></head><body><p>post</p><script src="/app.js"></script></body></html>`,
		`<html><body><p>Distil shows a page titled "Pardon Our Interruption".</p><script src="/app.js"></script></body></html>`,
		`<html><head><title>Just a moment...</title></head><body><p>a story</p><script src="/app.js"></script></body></html>`,
		`<html><body><script>a.src='/cdn-cgi/challenge-platform/h/b/scripts/jsd/e0c9/main.js'</script><script src="/app.js"></script></body></html>`,
	}
	for _, b := range normal {
		if c := enumerate(u.String(), u, []byte(b)).Challenge; c != "" {
			t.Errorf("%s: flagged %q", b[:70], c)
		}
	}
	interstitial := []string{
		`<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={cvId:"3"}</script></body></html>`,
		`<html><body><script src="https://ct.captcha-delivery.com/c.js"></script><iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=x"></iframe></body></html>`,
		`<html><body><div id="px-captcha"></div></body></html>`,
		`<html><body><iframe id="main-iframe" src="/_Incapsula_Resource?x=1"></iframe>Request unsuccessful. Incapsula incident ID: 1-2</body></html>`,
		`<html><head><title>Pardon Our Interruption</title></head><body></body></html>`,
	}
	for _, b := range interstitial {
		if c := enumerate(u.String(), u, []byte(b)).Challenge; c == "" {
			t.Errorf("%s: not flagged", b[:70])
		}
	}
}

// Attributes that name scripts become hints; q:base may come after the
// handlers that use it.
func TestAttributeHints(t *testing.T) {
	u, _ := url.Parse("https://s.example/app/")
	p := enumerate(u.String(), u, []byte(`<button on:click="q-A.js#s_1">x</button><div q:base="/build/"></div>`+
		`<astro-island component-url="/_astro/C.js"></astro-island><div data-x="./w.mjs?v=1"></div><img src="/i.png">`))
	got := map[string]bool{}
	for _, h := range p.Hints {
		got[h.URL] = h.Exact
	}
	want := map[string]bool{"https://s.example/build/q-A.js": true, "https://s.example/_astro/C.js": true, "https://s.example/app/w.mjs?v=1": false}
	if len(got) != len(want) {
		t.Fatalf("hints %v", got)
	}
	for k, v := range want {
		if e, ok := got[k]; !ok || e != v {
			t.Errorf("%s: got %v %v", k, e, ok)
		}
	}
}

// Each Qwik handler resolves against the q:base of its own container.
func TestQwikContainers(t *testing.T) {
	u, _ := url.Parse("https://q.example/")
	p := enumerate(u.String(), u, []byte(`<html q:base="/build/"><body><button on:click="q-A.js#s">a</button>`+
		`<div q:container="paused" q:base="/builder/"><img src="x.png"><button on:click="q-B.js#s">b</button></div>`+
		`<button on:click="q-C.js#s">c</button></body></html>`))
	var got []string
	for _, h := range p.Hints {
		got = append(got, h.URL)
	}
	want := "https://q.example/build/q-A.js https://q.example/builder/q-B.js https://q.example/build/q-C.js"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v", got)
	}
}
