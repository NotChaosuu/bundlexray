package scan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NotChaosuu/bundlexray/pkg/fetch"
)

// Loaders that pass the id through unmapped are evaluated for the ids the
// code loads (r.e(123)); with no such ids anywhere the scan is incomplete.
func TestPassThroughLoaders(t *testing.T) {
	cases := map[string]struct {
		pages    map[string]string
		complete bool
	}{
		"named map": {map[string]string{
			"/":         `<script src="/rt.js"></script>`,
			"/rt.js":    `(()=>{var r={};r.p="/";r.u=e=>({12:"about"}[e]||e)+".js";r.e=function(e){};r.e(12);r.e(45)})();`,
			"/about.js": `var a=1;`,
			"/45.js":    `var k="` + stripeKey + `";`,
		}, true},
		"ternary, ids in another script": {map[string]string{
			"/":              `<script src="/rt.js"></script><script src="/main.js"></script>`,
			"/rt.js":         `(()=>{var r={};r.p="/";r.u=e=>792===e?"vendors.js":e+".bundle.js";r.e=function(){}})();`,
			"/main.js":       `n.e(/*! import() */ 123).then(n.bind(n,5));`,
			"/vendors.js":    `var v=1;`,
			"/123.bundle.js": `var k="` + stripeKey + `";`,
		}, true},
		"if/return body": {map[string]string{
			"/": `<script src="/rt.js"></script>`,
			"/rt.js": "var __webpack_require__={};__webpack_require__.p=\"/\";\n__webpack_require__.u = (chunkId) => {\n" +
				"  // not based on template\n  if ({\"792\":1}[chunkId]) return \"vendors-\" + chunkId + \".js\";\n" +
				"  if (chunkId === 800) { return \"admin.js\"; }\n  // based on template\n" +
				"  return \"\" + chunkId + \".\" + {\"123\":\"abc1\"}[chunkId] + \".js\";\n};",
			"/vendors-792.js": `var v=1;`,
			"/admin.js":       `var k="` + stripeKey + `";`,
			"/123.abc1.js":    `var x=1;`,
		}, true},
		"ids before the loader": {map[string]string{
			"/":              `<script>n.e(123)</script><script src="/rt.js"></script>`,
			"/rt.js":         `(()=>{var r={};r.p="/";r.u=e=>792===e?"vendors.js":e+".bundle.js";r.e=function(){}})();`,
			"/vendors.js":    `var v=1;`,
			"/123.bundle.js": `var k="` + stripeKey + `";`,
		}, true},
		"webpack 4 jsonp": {map[string]string{
			"/":        `<script src="/rt.js"></script>`,
			"/rt.js":   `var a={};a.p="/";function u(e){return a.p+"js/"+({}[e]||e)+".js"}a.e(5);`,
			"/js/5.js": `var k="` + stripeKey + `";`,
		}, true},
		"data: module": {map[string]string{
			"/": `<script type="importmap">{"imports":{"stub":"data:text/javascript,import './real.js';"}}</script>` +
				`<script type="module">import "stub";</script>`,
			"/real.js": `var k="` + stripeKey + `";`,
		}, true},
		"build hash prefix": {map[string]string{
			"/":                          `<script src="/rt.js"></script>`,
			"/rt.js":                     `var s={};s.p="/";s.u=e=>""+(({279:"vendors"})[e]||e)+"_app_"+s.h().slice(0,6)+"_1.0.js",s.h=()=>"6f6780a77584d55f";s.e(12);`,
			"/vendors_app_6f6780_1.0.js": `var v=1;`,
			"/12_app_6f6780_1.0.js":      `var k="` + stripeKey + `";`,
		}, true},
		"no ids anywhere": {map[string]string{
			"/":      `<script src="/rt.js"></script>`,
			"/rt.js": "var __webpack_require__={};__webpack_require__.p=\"/\";__webpack_require__.u=(chunkId)=>{return \"\"+chunkId+\".bundle.js\"};",
		}, false},
	}
	for name, c := range cases {
		r := run(t, site{pages: c.pages}.start(t).URL+"/", "")
		if r.Complete != c.complete || c.complete && len(r.Secrets) != 1 {
			t.Errorf("%s: complete=%v secrets=%d reasons=%v scripts=%v", name, r.Complete, len(r.Secrets), r.Incomplete, r.Scripts)
		}
	}
}

// An X.u assignment that cannot be evaluated, whatever its shape, is a gap;
// Babel's .concat() and a map held in a variable are read.
func TestOtherLoaderForms(t *testing.T) {
	r := run(t, site{pages: map[string]string{
		"/":      `<script src="/rt.js"></script>`,
		"/rt.js": `(()=>{var r={};r.p="/";r.u=e=>window.__CHUNK_MANIFEST__[e];})();`,
	}}.start(t).URL+"/", "")
	if r.Complete {
		t.Fatalf("manifest loader: complete")
	}
	r = run(t, site{pages: map[string]string{
		"/":                          `<script src="/app.js"></script><script src="/boot.js"></script>`,
		"/app.js":                    `var r={};r.p="/";r.u=function(e){return"static/js/".concat(e,".").concat({5:"f00d"}[e],".chunk.js")};`,
		"/static/js/5.f00d.chunk.js": `var k="` + stripeKey + `";`,
		"/boot.js":                   `var H={7:"c0"};function load(id){var s=document.createElement("script");s.src="/c/"+id+"."+H[id]+".js"}`,
		"/c/7.c0.js":                 `const g="` + ghToken + `";`,
	}}.start(t).URL+"/", "")
	if !r.Complete || len(r.Secrets) != 2 {
		t.Fatalf("concat and map variable: complete=%v secrets=%d reasons=%v", r.Complete, len(r.Secrets), r.Incomplete)
	}
	// A library's own t.u = function is not a webpack loader.
	lib := `var t={};t.u=function(e){return e.toUpperCase()};`
	if ls := chunkLoaders(lib, nonCode(lib)); len(ls.unparsed) != 0 {
		t.Fatalf("library u: %v", ls.unparsed)
	}
}

// Framework manifests and attributes: React Router / Remix route modules,
// VitePress page chunks, Astro islands, Qwik handlers, Vite legacy entries.
func TestFrameworkManifestsAndAttributes(t *testing.T) {
	srv := site{pages: map[string]string{
		"/": `<html q:base="/build/"><body><script type="module">import "/assets/manifest-1.js";</script>` +
			`<astro-island component-url="/_astro/Admin.c1.js" renderer-url="/_astro/client.r1.js?dpl=x"></astro-island>` +
			`<button on:click="q-Ab12.js#s_click[0]&#10;q-Cd34.js#s_x">Go</button>` +
			`<script nomodule id="vite-legacy-entry" data-src="/assets/index-legacy-L3.js">System.import(1)</script>` +
			`<script src="/assets/chunks/metadata.m1.js"></script></body></html>`,
		"/assets/manifest-1.js":          `window.__reactRouterManifest={"entry":{"module":"/assets/entry-e1.js","imports":["/assets/shared-s1.js"]},"routes":{"admin":{"module":"/assets/admin-a1.js","imports":[]}}};`,
		"/assets/entry-e1.js":            `var e=1;`,
		"/assets/shared-s1.js":           `var s=1;`,
		"/assets/admin-a1.js":            `var k1="` + stripeKey + `";`,
		"/_astro/Admin.c1.js":            `const g="` + ghToken + `";`,
		"/_astro/client.r1.js":           `var c=1;`,
		"/build/q-Ab12.js":               `var q="sk_` + `live_QwIk9Xp2Lm7Rt4Vb8Nc3Kd6Fh1Js5Gy0";`,
		"/build/q-Cd34.js":               `var q2=1;`,
		"/assets/index-legacy-L3.js":     `var l=1;`,
		"/assets/chunks/metadata.m1.js":  `window.__VP_HASH_MAP__=JSON.parse("{\"guide_index.md\":\"Dk2s\"}");`,
		"/assets/guide_index.md.Dk2s.js": `var v="sk_` + `live_ViTePrEsS9x2Lm7Rt4Vb8Nc3Kd6";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 4 || r.ScriptsScanned != 11 {
		t.Fatalf("complete=%v scanned=%d secrets=%d reasons=%v scripts=%v", r.Complete, r.ScriptsScanned, len(r.Secrets), r.Incomplete, r.Scripts)
	}
}

// A same-site .js path in inline JSON or any attribute is read as a guess;
// a full chunk URL inside data (a consent tool's table) is only a guess too.
func TestInlineAndAttributeGuesses(t *testing.T) {
	srv := site{pages: map[string]string{
		"/": `<div data-module="/js/widget-w1.js"></div><a href="/dl/old.js">x</a>` +
			`<script type="application/json" id="__DATA__">{"chunk":"\/js\/late-l1.js","cdn":"https://other.invalid/x.js"}</script>` +
			`<script>var osano=["https://cdn.other.invalid/_next/static/chunks/1-a.js"];</script>`,
		"/js/widget-w1.js": `var k="` + stripeKey + `";`,
		"/js/late-l1.js":   `const g="` + ghToken + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 2 {
		t.Fatalf("complete=%v secrets=%d reasons=%v errors=%v scripts=%v", r.Complete, len(r.Secrets), r.Incomplete, r.Errors, r.Scripts)
	}
}

// A site that refuses the tool's user agent, or serves it a crawler page,
// is read again as a browser; a chosen --user-agent is left alone. A page
// with no scripts and a meta refresh is followed.
func TestPageReadAsBrowser(t *testing.T) {
	full := `<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script><script src="/d.js"></script>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chrome := strings.Contains(r.UserAgent(), "Chrome/")
		switch r.URL.Path {
		case "/deny/":
			if !chrome {
				http.Error(w, "no", http.StatusForbidden)
				return
			}
			w.Write([]byte(`<script src="/a.js"></script>`))
		case "/crawler/":
			if !chrome {
				w.Write([]byte(`<body class="crawler"><p>static text</p><script src="/a.js"></script></body>`))
				return
			}
			w.Write([]byte(full))
		case "/refresh/":
			w.Write([]byte(`<meta http-equiv="refresh" content="0; url=/deny/">`))
		case "/a.js", "/b.js", "/c.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("var a=1;"))
		case "/d.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`var k="` + stripeKey + `";`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	if r := run(t, srv.URL+"/deny/", ""); !r.Complete || r.ScriptsScanned != 1 {
		t.Fatalf("403 page: complete=%v scanned=%d", r.Complete, r.ScriptsScanned)
	}
	if r := run(t, srv.URL+"/crawler/", ""); r.ScriptsScanned != 4 || len(r.Secrets) != 1 || !strings.Contains(strings.Join(r.Warnings, " "), "smaller page") {
		t.Fatalf("crawler page: scanned=%d secrets=%d warnings=%v", r.ScriptsScanned, len(r.Secrets), r.Warnings)
	}
	if r := run(t, srv.URL+"/refresh/", ""); r.ScriptsScanned != 1 {
		t.Fatalf("meta refresh: scanned=%d reasons=%v", r.ScriptsScanned, r.Incomplete)
	}
	if _, err := Run(srv.URL+"/deny/", Options{Fetch: fetch.Options{UserAgent: "ci"}}); err == nil {
		t.Fatal("a chosen user agent was overridden")
	}
}

// A source map refused to the tool is asked for once more as a browser.
func TestMapRetriedAsBrowser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<script src="/a.js"></script>`))
		case "/a.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("var a=1;\n//# sourceMappingURL=a.js.map"))
		case "/a.js.map":
			if !strings.Contains(r.UserAgent(), "Chrome/") {
				http.Error(w, "no", http.StatusForbidden)
				return
			}
			w.Write([]byte(`{"version":3,"sources":["s.js"],"sourcesContent":["var x=1"],"mappings":"AAAA"}`))
		}
	}))
	t.Cleanup(srv.Close)
	if r := run(t, srv.URL+"/", ""); !r.Complete || len(r.SourceMaps) != 1 || r.SourceMaps[0].Status != "exposed" {
		t.Fatalf("complete=%v maps=%+v", r.Complete, r.SourceMaps)
	}
}

// A computed name longer than the walk limit is reported, not skipped.
func TestLongExpressionReported(t *testing.T) {
	code := "x=" + strings.Repeat("a+", 600000) + `".js";`
	if ls := chunkLoaders(code, nonCode(code)); len(ls.unparsed) != 1 || !strings.Contains(ls.unparsed[0], "1 MB") {
		t.Fatalf("unparsed=%v", ls.unparsed)
	}
}

// webpack's automatic public path written as a replace chain resolves to
// the running script's folder.
func TestAutoPublicPathChain(t *testing.T) {
	code := `if(!c)throw Error("Automatic publicPath is not supported in this browser");return s.p=c=c.replace(/^blob:/,"").replace(/#.*$/,"").replace(/\/[^\/]+$/,"/"),e={349:0}`
	if pub, auto, literal := publicPath(code, "s"); !auto || !literal || pub != "" {
		t.Fatalf("pub=%q auto=%v literal=%v", pub, auto, literal)
	}
}
