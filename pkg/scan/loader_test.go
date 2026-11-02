package scan

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/NotChaosuu/bundlexray/pkg/fetch"
)

// The chunk-filename shapes of webpack 4 and 5, rspack, Create React App,
// Angular, Next.js pages and Docusaurus, minified and not, all evaluate to
// the same file names the browser would request.
func TestChunkLoaderShapes(t *testing.T) {
	cases := map[string][]string{
		`r.u=e=>"static/js/"+e+"."+{12:"a1",34:"b2"}[e]+".chunk.js"`:                                                                                                                         {"static/js/12.a1.chunk.js", "static/js/34.b2.chunk.js"},
		`function u(e){return a.p+"static/js/"+({}[e]||e)+"."+{12:"a1"}[e]+".chunk.js"}`:                                                                                                     {"static/js/12.a1.chunk.js"},
		`o.u=e=>(76===e?"common":e)+"."+{76:"c3",412:"d4"}[e]+".js",o.p=""`:                                                                                                                  {"412.d4.js", "common.c3.js"},
		`r.u=e=>"assets/js/"+(({17:"a7bd"})[e]||e)+"."+({17:"1f",99:"cc"})[e]+".js"`:                                                                                                         {"assets/js/99.cc.js", "assets/js/a7bd.1f.js"},
		`d.u=function(e){return 2272===e?"static/chunks/2272-ab.js":"static/chunks/"+e+"."+({12:"a1"})[e]+".js"}`:                                                                            {"static/chunks/12.a1.js", "static/chunks/2272-ab.js"},
		"r.u=e=>`static/js/${e}.${{12:\"a1\",34:\"b2\"}[e]}.js`":                                                                                                                             {"static/js/12.a1.js", "static/js/34.b2.js"},
		"__webpack_require__.u = (chunkId) => {\n  // return url for filenames based on template\n  return \"js/\" + chunkId + \".\" + {\"7\":\"e5\"}[chunkId] + \".js\";\n};":               {"js/7.e5.js"},
		"function jsonpScriptSrc(chunkId) {\n  return __webpack_require__.p + \"\" + ({\"main\":\"main\"}[chunkId]||chunkId) + \".\" + {\"0\":\"aa\",\"main\":\"bb\"}[chunkId] + \".js\"\n}": {"0.aa.js", "main.bb.js"},
		`r.u=e=>"js/"+{1:"vendors-lodash",2:"src_admin"}[e]+"."+{1:"x1",2:"x2"}[e]+".js"`:                                                                                                    {"js/src_admin.x2.js", "js/vendors-lodash.x1.js"},
		`r.u=e=>1===e?"a/"+e+".js":"b/"+e+"."+{1:"x",2:"y"}[e]+".js"`:                                                                                                                        {"a/1.js", "b/2.y.js"},
	}
	for code, want := range cases {
		got, unparsed := loaderFiles(code)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") || len(unparsed) > 0 {
			t.Errorf("%s\n  got  %v %v\n  want %v", code, got, unparsed, want)
		}
	}
}

// A loader the evaluator recognises but cannot read is reported, never
// dropped; a plain computed URL elsewhere is only counted.
func TestUnreadableLoadersAreReported(t *testing.T) {
	for _, code := range []string{
		`r.u=e=>"js/"+e+"."+r.h()+".js"`,
		`n.u=function(e){return"js/"+e+"."+t[e]+".js"}`,
		`x.y=a+"/"+{1:"q"}[e]+"."+g(e)+".chunk.js"`,
	} {
		if files, unparsed := loaderFiles(code); len(files) != 0 || len(unparsed) != 1 {
			t.Errorf("%s: files=%v unparsed=%v", code, files, unparsed)
		}
	}
	// A loader with no id list passes every id through: it is kept, and the
	// scan decides from the chunk ids the code loads.
	code := `__webpack_require__.u = (chunkId) => { return "" + chunkId + ".js"; };`
	if ls := chunkLoaders(code, nonCode(code)); len(ls.loaders) != 1 || !ls.loaders[0].pass || len(ls.unparsed) != 0 {
		t.Errorf("pass-through loader: %+v", ls)
	}
	ls := chunkLoaders(`var s=base+name+".js";`, nonCode(`var s=base+name+".js";`))
	if len(ls.unparsed) != 0 || ls.computed != 1 {
		t.Errorf("plain computed URL: %+v", ls)
	}
}

// End to end: CRA and Angular lazy chunks are fetched and scanned, and a
// loader that cannot be read makes the scan incomplete.
func TestChunkLoadersEndToEnd(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":                            `<script src="/static/js/main.js"></script><script src="/ng/runtime.js"></script>`,
		"/static/js/main.js":           `!function(){var r={};r.p="/";r.u=function(e){return"static/js/"+e+"."+{412:"9f8e"}[e]+".chunk.js"}}();`,
		"/static/js/412.9f8e.chunk.js": `var c={k:"` + stripeKey + `"};`,
		"/ng/runtime.js":               `(()=>{var o={};o.u=e=>(76===e?"common":e)+"."+{76:"aa",9:"bb"}[e]+".js",o.p="/ng/"})();`,
		"/ng/common.aa.js":             `var x=1;`,
		"/ng/9.bb.js":                  `const g="` + ghToken + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 2 || r.ScriptsScanned != 5 {
		t.Fatalf("complete=%v scanned=%d secrets=%d reasons=%v", r.Complete, r.ScriptsScanned, len(r.Secrets), r.Incomplete)
	}
	srv = site{pages: map[string]string{
		"/":     `<script src="/m.js"></script>`,
		"/m.js": `var r={};r.p="/";r.u=e=>"js/"+e+"."+r.h()+".js";`,
	}}.start(t)
	if r := run(t, srv.URL+"/", ""); r.Complete || !strings.Contains(strings.Join(r.Incomplete, " "), "not understood") {
		t.Fatalf("unreadable loader: complete=%v reasons=%v", r.Complete, r.Incomplete)
	}
}

// The public path comes from the loader's own runtime object, and one set
// at run time is a guess: when its chunks do not exist the scan says so.
func TestPublicPath(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":                `<script src="/app/main.js"></script>`,
		"/app/main.js":     `var t={};t.p="https://cdn.invalid/x/";!function(){var r={};r.p="/app/";r.u=e=>"js/"+e+"."+{12:"a1"}[e]+".js"}();`,
		"/app/js/12.a1.js": `var c="` + stripeKey + `";`,
	}}.start(t)
	if r := run(t, srv.URL+"/", ""); !r.Complete || len(r.Secrets) != 1 {
		t.Fatalf("own runtime object: complete=%v secrets=%d reasons=%v", r.Complete, len(r.Secrets), r.Incomplete)
	}
	// Runtime path with a working fallback: read, with a warning.
	srv = site{pages: map[string]string{
		"/":              `<script src="/v/js/app.js"></script>`,
		"/v/js/app.js":   `!function(){var r={};r.p=window.__CDN__||"/v/";r.u=e=>"js/"+e+"."+{12:"a1"}[e]+".js"}();`,
		"/v/js/12.a1.js": `var c="` + stripeKey + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 1 || !strings.Contains(strings.Join(r.Warnings, " "), "run time") {
		t.Fatalf("runtime path, fallback works: complete=%v secrets=%d warnings=%v", r.Complete, len(r.Secrets), r.Warnings)
	}
	// Runtime path whose guesses miss: incomplete.
	srv = site{pages: map[string]string{
		"/":                 `<script src="/w/js/app.js"></script>`,
		"/w/js/app.js":      `!function(){var r={};r.p=window.__CDN__;r.u=e=>"js/"+e+"."+{12:"a1",13:"b2"}[e]+".js"}();`,
		"/w/js/js/12.a1.js": `var c=1;`,
	}}.start(t)
	r = run(t, srv.URL+"/", "")
	if r.Complete || !strings.Contains(strings.Join(r.Incomplete, " "), "public path at run time") {
		t.Fatalf("runtime path, guesses miss: complete=%v reasons=%v", r.Complete, r.Incomplete)
	}
	// webpack 5's automatic public path: the runtime's folder plus a suffix.
	srv = site{pages: map[string]string{
		"/":                 `<script src="/b/js/runtime.js"></script>`,
		"/b/js/runtime.js":  `(()=>{var e;var t=document;e=t.currentScript.src;e=e.replace(/\/[^\/]+$/,"/"),r.p=e+"../"})();r.u=e=>"chunks/"+e+"."+{5:"f0"}[e]+".js";`,
		"/b/chunks/5.f0.js": `var c="` + stripeKey + `";`,
	}}.start(t)
	if r := run(t, srv.URL+"/", ""); !r.Complete || len(r.Secrets) != 1 {
		t.Fatalf("auto public path: complete=%v secrets=%d reasons=%v scripts=%v", r.Complete, len(r.Secrets), r.Incomplete, r.Scripts)
	}
}

// A path from a list the bundler wrote is a real file: a 404 is a gap, not
// a wrong guess.
func TestListedChunkMissingIsIncomplete(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":                   `<script src="/assets/index-a1.js"></script>`,
		"/assets/index-a1.js": `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/admin-c3.js","assets/b-e5.js"])))=>i.map(i=>d[i]);`,
		"/assets/b-e5.js":     `var b=1;`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if r.Complete || len(r.Unconfirmed) != 0 {
		t.Fatalf("listed 404: complete=%v unconfirmed=%v reasons=%v", r.Complete, r.Unconfirmed, r.Incomplete)
	}
}

// A CDN that serves chunks to browsers only is asked once more as one.
func TestBrowserRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Write([]byte(`<script src="/main.js"></script>`))
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`var r={};r.p="/";r.u=e=>"c/"+e+"."+{3:"f1"}[e]+".js";`))
		case r.URL.Path == "/c/3.f1.js" && strings.Contains(r.UserAgent(), "Chrome/"):
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`var k="` + stripeKey + `";`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	if r := run(t, srv.URL+"/", ""); !r.Complete || len(r.Secrets) != 1 {
		t.Fatalf("browser retry: complete=%v secrets=%d reasons=%v", r.Complete, len(r.Secrets), r.Incomplete)
	}
	// A user agent the caller chose is not overridden.
	r := runWith(t, srv.URL+"/", Options{Fetch: fetch.Options{UserAgent: "ci-scanner"}})
	if r.Complete || len(r.Secrets) != 0 {
		t.Fatalf("chosen UA: complete=%v secrets=%d", r.Complete, len(r.Secrets))
	}
}

// Import maps apply to URL-like specifiers too (Remix maps every
// "/assets/x.js" to its hashed file), by exact key, prefix and scope.
func TestImportMapURLKeys(t *testing.T) {
	srv := site{pages: map[string]string{
		"/": `<script type="importmap">{"imports":{"/assets/entry.js":"/assets/entry-H1.js","/lib/":"/lib-v2/"},` +
			`"scopes":{"/admin/":{"/admin/x.js":"/admin/x-H3.js"}}}</script>` +
			`<script type="module">import "/assets/entry.js";import "./lib/util.js";import "/admin/a.js";</script>`,
		"/assets/entry-H1.js": `var k="` + stripeKey + `";`,
		"/lib-v2/util.js":     `export const u=1;`,
		"/admin/a.js":         `import "./x.js";`,
		"/admin/x-H3.js":      `const g="` + ghToken + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 2 || r.ScriptsScanned != 4 {
		t.Fatalf("import map: complete=%v scanned=%d secrets=%d reasons=%v scripts=%v", r.Complete, r.ScriptsScanned, len(r.Secrets), r.Incomplete, r.Scripts)
	}
}

// Next.js chunk lists under any /_next/static/**/chunks/ folder, including
// App Router flight data with escaped quotes in an inline script.
func TestNextChunkLists(t *testing.T) {
	srv := site{pages: map[string]string{
		"/docs": `<script src="/_next/static/immutable/chunks/main-1.js"></script>` +
			`<script>self.__next_f.push([1,"3:I[1,[\"static/chunks/app/admin/page-d.js\"],\"default\"]\n"])</script>`,
		"/_next/static/immutable/chunks/main-1.js": `["static/immutable/chunks/a7.js"].map(t=>s.l(t));`,
		"/_next/static/immutable/chunks/a7.js":     `var k="` + stripeKey + `";`,
		"/_next/static/chunks/app/admin/page-d.js": `const g="` + ghToken + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/docs", "")
	if !r.Complete || len(r.Secrets) != 2 {
		t.Fatalf("next: complete=%v secrets=%d reasons=%v scripts=%v", r.Complete, len(r.Secrets), r.Incomplete, r.Scripts)
	}
}

// Parcel manifests, SystemJS dependencies and module-federation entries.
func TestOtherBundlerLists(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":                  `<script src="/d/index.js"></script><script src="/s/app.js"></script>`,
		"/d/index.js":        `require("./bundle-manifest").register(new __parcel__URL__("").toString(),JSON.parse('["a1","admin.56ef.js"]'));`,
		"/d/admin.56ef.js":   `var k="` + stripeKey + `";`,
		"/s/app.js":          `System.register("app",["./dep-a1.js"],function(e){return{execute:function(){}}});var r={remotes:{shop:"shop@/mf/remoteEntry.js"}};`,
		"/s/dep-a1.js":       `const g="` + ghToken + `";`,
		"/mf/remoteEntry.js": `var shop=1;`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 2 || r.ScriptsScanned != 5 {
		t.Fatalf("lists: complete=%v scanned=%d secrets=%d reasons=%v scripts=%v", r.Complete, r.ScriptsScanned, len(r.Secrets), r.Incomplete, r.Scripts)
	}
}

// return/'/.test(s) holds a regex, not a division: the import after it is
// real code.
func TestRegexAfterKeyword(t *testing.T) {
	for _, code := range []string{
		`function f(s){return/'/.test(s)}const m=import("./lazy.js");var z='x';`,
		`if(typeof/"/.source)x();import("./lazy.js");var q="y";`,
		"function g(){yield/`/.test(a)}import(\"./lazy.js\");var w=`z`;",
	} {
		refs := findRefs(code)
		if len(refs) != 1 || !refs[0].strong {
			t.Errorf("%s: %+v", code, refs)
		}
	}
	// a.return/2 is still a division.
	if refs := findRefs(`x=a.return/2;var s="import('./b.js')/";`); len(refs) != 1 || refs[0].strong {
		t.Errorf("division after a property: %+v", refs)
	}
}

// --max-time bounds the source-map phase too, including maps that never
// answer.
func TestMaxTimeBoundsMaps(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Write([]byte(`<script src="/a.js"></script><script src="/b.js"></script>`))
		case strings.HasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("var a=1;\n//# sourceMappingURL=" + r.URL.Path + ".map"))
		default:
			select {
			case <-block:
			case <-r.Context().Done():
			}
		}
	}))
	t.Cleanup(srv.Close)
	start := time.Now()
	r := runWith(t, srv.URL+"/", Options{MaxTime: 1500 * time.Millisecond, Concurrency: 1})
	if d := time.Since(start); d > 5*time.Second || r.Complete || !hasKind(r, "limit") {
		t.Fatalf("took %s, complete=%v reasons=%v", d, r.Complete, r.Incomplete)
	}
}

// A request cut off by --max-time counts as not fetched, not as a script
// that failed, and the totals add up to what the page listed.
func TestTimeLimitCountsInFlight(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte(`<script src="/1.js"></script><script src="/2.js"></script><script src="/3.js"></script><script src="/4.js"></script>`))
			return
		}
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var a=1;"))
	}))
	t.Cleanup(srv.Close)
	r := runWith(t, srv.URL+"/", Options{MaxTime: time.Second, Concurrency: 2, NoGuessMaps: true})
	if len(r.Scripts)+r.ScriptsNotFetched != 4 || len(r.Errors) != 0 || r.Complete {
		t.Fatalf("scripts=%d notFetched=%d errors=%v complete=%v", len(r.Scripts), r.ScriptsNotFetched, r.Errors, r.Complete)
	}
}

// Vite's preload list in a large app is longer than any fixed window.
func TestLongViteList(t *testing.T) {
	var names []string
	for i := 0; i < 400; i++ {
		names = append(names, `"./C`+strings.Repeat("x", 3)+string(rune('a'+i%26))+string(rune('a'+i/26))+`.js"`)
	}
	code := `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=[` + strings.Join(names, ",") + `])))=>i.map(i=>d[i]);`
	refs, unparsed := findRefsIn(code, nonCode(code))
	if len(refs) != 400 || len(unparsed) != 0 {
		t.Fatalf("refs=%d unparsed=%v", len(refs), unparsed)
	}
}

// Paths quoted inside documentation text are not lists the bundler wrote,
// and import samples in strings that point at hosts that do not exist or at
// private addresses are not gaps.
func TestDocsTextIsNotAList(t *testing.T) {
	srv := site{pages: map[string]string{
		"/": `<script src="/docs.js"></script>`,
		"/docs.js": `var md="remotes: { app1: 'app1@http://localhost:3001/remoteEntry.js' }, see \"static/chunks/old.js\" and remoteEntry.js";` +
			`var ex="import x from 'https://analytics.nosuchhost.invalid/api/v1.js'";var r={remotes:{app2:"app2@/mf/remoteEntry.js"}};` +
			`var j=jsx(code,{children:"remoteEntry.js"});jsx(span,{children:"app1@http://localhost:3001/remoteEntry.js"});`,
		"/mf/remoteEntry.js": `var app2=1;`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || r.ScriptsScanned != 2 {
		t.Fatalf("docs text: complete=%v scanned=%d reasons=%v errors=%v scripts=%v", r.Complete, r.ScriptsScanned, r.Incomplete, r.Errors, r.Scripts)
	}
}

// Crafted bundles that would make the loader search quadratic are cut off
// and reported, not left to run for hours.
func TestHostileLoaderInputIsBounded(t *testing.T) {
	for name, code := range map[string]string{
		"brackets": strings.Repeat("(", 100) + strings.Repeat(")", 1<<20) + strings.Repeat(`a+".js"+`, 50000) + "1",
		"chain":    strings.Repeat(`"x"+e+".js"+`, 200000) + "1",
	} {
		start := time.Now()
		ls := chunkLoaders(code, nonCode(code))
		if d := time.Since(start); d > 5*time.Second || len(ls.unparsed) == 0 {
			t.Errorf("%s: took %s, unparsed=%v", name, d, ls.unparsed)
		}
	}
}

// A Vite preload list the scan cannot read is reported.
func TestUnreadableViteList(t *testing.T) {
	code := `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=window.__deps)))=>i.map(i=>d[i]);`
	if _, unparsed := findRefsIn(code, nonCode(code)); len(unparsed) != 1 {
		t.Fatalf("unparsed=%v", unparsed)
	}
}

// A remote the federation runtime loads is a listed file: a 404 is a gap.
func TestFederationRuntimeRemoteIsListed(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":     `<script src="/h.js"></script>`,
		"/h.js": `module.exports=new Promise((t,r)=>{n.l("/mf/remoteEntry.js",e=>{t()},"app1")});`,
	}}.start(t)
	if r := run(t, srv.URL+"/", ""); r.Complete || len(r.Errors) != 1 {
		t.Fatalf("complete=%v errors=%v", r.Complete, r.Errors)
	}
}
