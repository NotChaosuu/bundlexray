package scan

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NotChaosuu/bundlexray/pkg/model"
)

// chunkSite serves a webpack runtime whose chunk map lists n chunks; status
// decides what each chunk answers.
func chunkSite(t *testing.T, n int, status func(i int) (int, string)) *httptest.Server {
	t.Helper()
	var pairs []string
	for i := 0; i < n; i++ {
		pairs = append(pairs, `"`+string(rune('a'+i))+`":"h`+string(rune('a'+i))+`"`)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/main.js"></script>`))
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`n.p="/";n.u=function(e){return"c/"+{` + strings.Join(pairs, ",") + `}[e]+".js"};`))
		case strings.HasPrefix(r.URL.Path, "/c/h"):
			i := int(r.URL.Path[4] - 'a')
			st, body := status(i)
			if st != 200 {
				http.Error(w, body, st)
				return
			}
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// A guessed chunk that 404s is listed; when every chunk a loader names is
// missing, the loader's chunks were not read, so the scan is incomplete. A
// 403, a 500 or a block page means a real chunk was not read.
func TestChunkListFailures(t *testing.T) {
	for name, c := range map[string]struct {
		status     func(int) (int, string)
		incomplete bool
		unconf     int
	}{
		"all 404":      {func(int) (int, string) { return 404, "nf" }, true, 3},
		"one 404":      {func(i int) (int, string) { return map[bool]int{true: 404, false: 200}[i == 1], "var x=1;" }, false, 1},
		"all 403":      {func(int) (int, string) { return 403, "Forbidden" }, true, 0},
		"one 500":      {func(i int) (int, string) { return map[bool]int{true: 500, false: 200}[i == 1], "var x=1;" }, true, 0},
		"block page":   {func(int) (int, string) { return 200, "<!doctype html><html><body>blocked</body></html>" }, true, 0},
		"all readable": {func(int) (int, string) { return 200, "var y=1;" }, false, 0},
	} {
		r := run(t, chunkSite(t, 3, c.status).URL+"/", "")
		if !r.Complete != c.incomplete || len(r.Unconfirmed) != c.unconf {
			t.Errorf("%s: complete=%v unconfirmed=%d reasons=%v", name, r.Complete, len(r.Unconfirmed), r.Incomplete)
		}
	}
}

// Reaching --max-scripts with chunk-list entries still queued is a gap.
func TestChunkListCapIsIncomplete(t *testing.T) {
	srv := chunkSite(t, 10, func(i int) (int, string) {
		if i == 9 {
			return 200, `var k="` + stripeKey + `";`
		}
		return 200, "var c=1;"
	})
	r := runWith(t, srv.URL+"/", Options{MaxScripts: 5})
	if r.Complete || !hasKind(r, model.GapLimit) {
		t.Fatalf("cap with chunk refs left: complete=%v kinds=%v", r.Complete, r.IncompleteKinds)
	}
}

// Real imports go first: a long chunk list cannot use up the budget a static
// import needs.
func TestStrongRefsBeforeChunkGuesses(t *testing.T) {
	var pairs []string
	for i := 0; i < 20; i++ {
		pairs = append(pairs, `"`+string(rune('a'+i))+`":"g`+string(rune('a'+i))+`"`)
	}
	srv := site{pages: map[string]string{
		"/":        `<script src="/main.js"></script>`,
		"/main.js": `n.u=function(e){return"c/"+{` + strings.Join(pairs, ",") + `}[e]+".js"};import "./dep.js";`,
		"/dep.js":  `var k="` + stripeKey + `";`,
	}}.start(t)
	r := runWith(t, srv.URL+"/", Options{MaxScripts: 3})
	if len(r.Secrets) != 1 {
		t.Fatalf("static import starved by chunk guesses: secrets=%v scripts=%v", r.Secrets, r.Scripts)
	}
}

func TestTimeLimitIsIncomplete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<script src="/a.js"></script>`))
			return
		}
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`import "./b.js";import "./c.js";import "./d.js";`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	r := runWith(t, srv.URL+"/", Options{MaxTime: 150 * time.Millisecond, Concurrency: 1})
	if r.Complete || !hasKind(r, model.GapLimit) || !strings.Contains(strings.Join(r.Incomplete, " "), "time limit") {
		t.Fatalf("time limit: complete=%v reasons=%v", r.Complete, r.Incomplete)
	}
}

// Bare specifiers resolve through <script type="importmap"> (the Rails 7
// default), exactly and by prefix.
func TestImportMap(t *testing.T) {
	srv := site{pages: map[string]string{
		"/": `<script type="importmap">{"imports":{"app":"/js/real-app.js","lib/":"/vendor/"}}</script>` +
			`<script type="module">import "app";import {x} from "lib/util.js";import "unmapped";</script>`,
		"/js/real-app.js": `var k="` + stripeKey + `";`,
		"/vendor/util.js": `export const x="` + ghToken + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 2 || r.ScriptsScanned != 2 {
		t.Fatalf("import map: complete=%v scanned=%d secrets=%v", r.Complete, r.ScriptsScanned, r.Secrets)
	}
}

// Workers and service workers take a plain filename resolved against the
// page; importScripts resolves against the worker script.
func TestPlainFilenameWorkers(t *testing.T) {
	srv := site{pages: map[string]string{
		"/app/":           `<script src="/static/boot.js"></script>`,
		"/static/boot.js": `navigator.serviceWorker.register("sw.js");new Worker("worker.js");new SharedWorker("shared.mjs");`,
		"/app/sw.js":      `importScripts("helper.js");`,
		"/app/worker.js":  `var w=1;`,
		"/app/shared.mjs": `var s=1;`,
		"/app/helper.js":  `var k="` + stripeKey + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/app/", "")
	if !r.Complete || r.ScriptsScanned != 5 || len(r.Secrets) != 1 {
		t.Fatalf("workers: complete=%v scanned=%d scripts=%v errors=%v", r.Complete, r.ScriptsScanned, r.Scripts, r.Errors)
	}
}

func TestNestedAndScriptFrames(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":          `<iframe src="/f1.html"></iframe><iframe src="/direct.js"></iframe><script src="/top.js"></script>`,
		"/f1.html":   `<iframe src="/f2.html"></iframe><script src="/one.js"></script>`,
		"/f2.html":   `<iframe src="/f3.html"></iframe><script src="/two.js"></script>`,
		"/f3.html":   `<script src="/three.js"></script>`,
		"/top.js":    "var t=1;",
		"/one.js":    "var o=1;",
		"/two.js":    "var w=1;",
		"/three.js":  `var k="` + stripeKey + `";`,
		"/direct.js": `var g="` + ghToken + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 2 {
		t.Fatalf("frames: complete=%v secrets=%v scripts=%v", r.Complete, r.Secrets, r.Scripts)
	}
}

// Two frames each with an "(inline script #1)" carrying a different inline
// map: both maps are read.
func TestFrameInlineMapsKeptApart(t *testing.T) {
	m := func(content string) string {
		return "data:application/json;base64," + b64(`{"version":3,"sources":["s.js"],"sourcesContent":["`+content+`"]}`)
	}
	srv := site{pages: map[string]string{
		"/":       "<script>var a=1;\n//# sourceMappingURL=" + m("var a=1;") + "</script><iframe src=\"/f.html\"></iframe>",
		"/f.html": "<script>var b=2;\n//# sourceMappingURL=" + m(`const k='`+stripeKey+`';`) + "</script>",
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if len(r.SourceMaps) != 2 || len(r.Secrets) != 1 {
		t.Fatalf("frame inline maps: maps=%+v secrets=%v", r.SourceMaps, r.Secrets)
	}
}

// Import text inside a string (sample code, docs) is only a guess, and paths
// a browser would never fetch as a script are dropped.
func TestOnlyRealImportsAreStrong(t *testing.T) {
	srv := site{pages: map[string]string{
		"/": `<script src="/s.js"></script>`,
		"/s.js": `var demo='import App from "./demo/App.js";';` + "\n" +
			`const t=x=>import(` + "`./nodes/${x}.js`" + `);` +
			`var j="{\"src\":\"\\/front\\/build\\/a.js\"}";` +
			`import "./styles.css";import Btn from "./Button.svelte";import add from "./add";` +
			`import cfg from "./cfg.json" with {type:"json"};`,
		"/cfg.json": `{"apiKey":"x"}`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Unconfirmed) != 1 || r.ScriptsScanned != 2 {
		t.Fatalf("complete=%v scanned=%d scripts=%v unconfirmed=%v errors=%v", r.Complete, r.ScriptsScanned, r.Scripts, r.Unconfirmed, r.Errors)
	}
}

// A small page whose only form is hidden fields is an interstitial (Reddit's
// proof-of-work page); a normal page that loads the AWS WAF SDK is not.
func TestChallengeShapes(t *testing.T) {
	// No vendor string at all: only the shape gives it away.
	challenge := `<!doctype html><html><head><title>site</title></head><body>` +
		`<form method="POST" action="/"><input type="hidden" name="answer" value=""><input type="hidden" name="t" value="9f2c"></form>` +
		`<script>var c=crypto.subtle;</script></body></html>`
	marked := `<!doctype html><html><body><form hidden><input type="hidden" name="js_challenge" value="1"></form>` +
		`<script src="/app.js"></script><script src="/b.js"></script></body></html>`
	normal := `<!doctype html><html><head><script src="https://abc.edge.sdk.awswaf.com/abc/challenge.js"></script>` +
		`<script src="/app.js"></script></head><body><nav></nav><main><h1>Models</h1><p>a</p><p>b</p></main>` +
		strings.Repeat(`<a href="/m">m</a>`, 20) + `</body></html>`
	for name, c := range map[string]struct {
		page string
		want bool
	}{"hidden-form interstitial": {challenge, true}, "marked interstitial": {marked, true}, "normal page with WAF SDK": {normal, false}} {
		srv := site{pages: map[string]string{"/": c.page, "/app.js": "var a=1;", "/b.js": "var b=1;"}}.start(t)
		r := runWith(t, srv.URL+"/", Options{})
		if got := hasKind(r, model.GapPage) && strings.Contains(strings.Join(r.Incomplete, " "), "interstitial"); got != c.want {
			t.Errorf("%s: challenge=%v want %v (reasons %v)", name, got, c.want, r.Incomplete)
		}
	}
}

// An SPA fallback that opens with a comment is still the app shell, not a map.
func TestCommentedSPAFallbackIsNotAMap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("var a=1;"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			w.Write([]byte(`<script src="/app.js"></script>`))
			return
		}
		w.Write([]byte("<!-- build 2026 -->\n<!doctype html><html><body>spa</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	r := runWith(t, srv.URL+"/", Options{})
	if !r.Complete || len(r.SourceMaps) != 0 {
		t.Fatalf("SPA fallback: complete=%v maps=%+v", r.Complete, r.SourceMaps)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Vite's preload list is relative to the build base, which can be a CDN path:
// the entries must be fetched next to the script that lists them.
func TestViteListOnCDNBase(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":                             `<script type="module" src="/cdn/build/assets/entry-a1.js"></script>`,
		"/cdn/build/assets/entry-a1.js": `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/chunk-b2.js"])))=>i.map(i=>d[i]);`,
		"/cdn/build/assets/chunk-b2.js": `var k="` + stripeKey + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 1 || len(r.Unconfirmed) != 0 {
		t.Fatalf("vite on CDN base: complete=%v secrets=%v unconfirmed=%v scripts=%v", r.Complete, r.Secrets, r.Unconfirmed, r.Scripts)
	}
}

// SvelteKit lists chunks relative to the importing file (../chunks/x.js); a
// list entry whose folder is not in the script's path is relative to the
// build root, the parent of the script's folder.
func TestViteListShapes(t *testing.T) {
	srv := site{pages: map[string]string{
		"/": `<link rel="modulepreload" href="./_app/immutable/entry/start.js">` +
			`<script type="module" src="/b/entry/main.js"></script>`,
		"/_app/immutable/entry/start.js":   `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["../chunks/K1.js","./payload.js"])))=>i.map(i=>d[i]);`,
		"/_app/immutable/chunks/K1.js":     `var k="` + stripeKey + `";`,
		"/_app/immutable/entry/payload.js": "var p=1;",
		"/b/entry/main.js":                 `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["chunks/G2.js"])))=>i.map(i=>d[i]);`,
		"/b/chunks/G2.js":                  `var g="` + ghToken + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 2 || len(r.Unconfirmed) != 0 {
		t.Fatalf("complete=%v secrets=%d unconfirmed=%v scripts=%v", r.Complete, len(r.Secrets), r.Unconfirmed, r.Scripts)
	}
}

func TestChunkIDNumbers(t *testing.T) {
	got, _ := loaderFiles(`e.u=e=>"js/"+e+"-"+{5e3:"e91d",1e4:"ff00",42:"aa"}[e]+".js"`)
	if strings.Join(got, ",") != "js/10000-ff00.js,js/42-aa.js,js/5000-e91d.js" {
		t.Errorf("got %v", got)
	}
}

// Turbopack lists chunks as plain strings relative to /_next/.
func TestTurbopackChunkLists(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":                               `<script src="/_next/static/chunks/main-1a.js"></script>`,
		"/_next/static/chunks/main-1a.js": `(globalThis.TURBOPACK=[]).push([0,1,s=>{s.v(t=>Promise.all(["static/chunks/2wo.js","static/chunks/0hl.js"].map(t=>s.l(t))))}]);var p="static/chunks/"+e;`,
		"/_next/static/chunks/2wo.js":     "var a=1;",
		"/_next/static/chunks/0hl.js":     `var k="` + stripeKey + `";`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.Secrets) != 1 || r.ScriptsScanned != 3 {
		t.Fatalf("turbopack: complete=%v scanned=%d secrets=%v scripts=%v unconfirmed=%v", r.Complete, r.ScriptsScanned, r.Secrets, r.Scripts, r.Unconfirmed)
	}
}
