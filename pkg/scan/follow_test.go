package scan

import (
	"encoding/json"

	"strings"
	"testing"
	"time"

	"github.com/NotChaosuu/bundlexray/pkg/fetch"
	"github.com/NotChaosuu/bundlexray/pkg/model"
)

var stripeKey = "sk_" + "live_" + "51Hq8ZbT3kLm9QwErTyUiOp2AsDfGhJkLzXcVbNm7Qp4Rs"

func runWith(t *testing.T, target string, o Options) *model.Report {
	t.Helper()
	o.Fetch.Timeout = 5 * time.Second
	if o.Concurrency == 0 {
		o.Concurrency = 4
	}
	r, err := Run(target, o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hasKind(r *model.Report, kind string) bool {
	for _, k := range r.IncompleteKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// A 200 that is not JavaScript means the real script was never seen.
// What a script URL answered decides whether anything was read: an error or
// block page, an image or a stylesheet is a failure; real JavaScript is
// accepted even when it looks odd or is mislabelled.
func TestScriptBodies(t *testing.T) {
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + strings.Repeat("\x00", 32)
	cases := []struct {
		name, body, ct string
		fail           bool
	}{
		{"empty text", "", "text/plain", true},
		{"blank", "\n\n   \n", "text/plain", true},
		{"comment then doctype", "<!-- cdn error --><!DOCTYPE html><html><body>Access denied</body></html>", "application/javascript", true},
		{"json error", `{"error":"forbidden","code":403}`, "application/javascript", true},
		{"title page", "<title>403 Forbidden</title><h1>Forbidden</h1>", "text/html", true},
		{"s3 xml", `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code></Error>`, "application/xml", true},
		{"plain access denied", "Access denied", "text/plain", true},
		{"tagless block page", "Request blocked. Reference #18.5c2e", "text/html", true},
		{"png", png, "image/png", true},
		{"png labelled js", png, "application/javascript", true},
		{"unknown binary labelled js", "AB\x00\x00\x07\x00CD\x01", "application/javascript", true},
		{"stylesheet", "body{margin:0}.btn{color:red}", "text/css", true},
		{"plain 404", "404 Not Found", "text/plain", true},
		{"unlabelled word", "Forbidden", "application/octet-stream", true},
		{"gif unlabelled", "GIF89a\x01\x00\x01\x00\x00", "application/octet-stream", true},
		{"nginx page", "<center>nginx</center>", "text/html", true},
		{"font", "wOF2\x00\x01", "font/woff2", true},
		{"empty js chunk", "", "application/javascript", false},
		{"legacy comment js", "<!-- legacy hide\nvar a={k:1};", "application/javascript", false},
		{"json-valid js", `["use strict"]`, "application/javascript", false},
		{"bom js", "\xef\xbb\xbf\n\n  var c=1;", "text/javascript", false},
		{"comment mid js", "\n  <!--x-->\nvar d=1;", "application/javascript", false},
		{"mislabelled js", "var a=1;function f(){return a}", "text/plain", false},
		{"unlabelled module", "export{};import'./x.js';", "application/octet-stream", false},
	}
	for _, c := range cases {
		srv := site{
			pages: map[string]string{"/": `<script src="/a.js"></script>`, "/a.js": c.body, "/x.js": "var x=1;"},
			types: map[string]string{"/a.js": c.ct},
		}.start(t)
		r := run(t, srv.URL+"/", "")
		failed := r.ScriptsScanned == 0 && hasKind(r, model.GapScripts)
		if failed != c.fail {
			t.Errorf("%s: failed=%v want %v (complete=%v scanned=%d errors=%+v)", c.name, failed, c.fail, r.Complete, r.ScriptsScanned, r.Errors)
		}
	}
}

func TestPageWithoutScriptsIsIncomplete(t *testing.T) {
	for name, body := range map[string]string{
		"empty":     "",
		"softblock": "<html><body><h1>Access denied</h1>Reference #18.abc</body></html>",
	} {
		srv := site{pages: map[string]string{"/": body}}.start(t)
		r := run(t, srv.URL+"/", "")
		if r.Complete || !hasKind(r, model.GapPage) {
			t.Errorf("%s page: complete=%v kinds=%v", name, r.Complete, r.IncompleteKinds)
		}
	}
}

// A target URL that is itself a script is scanned as one.
func TestDirectScriptTarget(t *testing.T) {
	srv := site{
		pages: map[string]string{"/app.js": `var k="` + stripeKey + `";`},
		types: map[string]string{"/app.js": "application/javascript"},
	}.start(t)
	r := run(t, srv.URL+"/app.js", "")
	if !r.Complete || r.ScriptsScanned != 1 || len(r.Secrets) != 1 {
		t.Fatalf("direct .js target: complete=%v scanned=%d secrets=%+v", r.Complete, r.ScriptsScanned, r.Secrets)
	}
}

// Scripts refused by --same-site were not read; the scan cannot vouch for them.
func TestScopeSkippedScriptsAreIncomplete(t *testing.T) {
	srv := site{pages: map[string]string{"/": `<script src="https://cdn.other-site.example/x.js"></script>`}}.start(t)
	r := runWith(t, srv.URL+"/", Options{Fetch: fetch.Options{SameSite: true}})
	if r.Complete || !hasKind(r, model.GapScope) || len(r.Skipped) != 1 {
		t.Fatalf("scope skip: complete=%v kinds=%v skipped=%v", r.Complete, r.IncompleteKinds, r.Skipped)
	}
}

// Secrets inside a map's sourcesContent are reported.
func TestSecretsInSourcesContent(t *testing.T) {
	m, _ := json.Marshal(map[string]any{"version": 3, "sources": []string{"src/config.ts"}, "sourcesContent": []string{`export const k = "` + stripeKey + `";`}})
	srv := site{pages: map[string]string{
		"/":         `<script src="/a.js"></script>`,
		"/a.js":     "var a=1;\n//# sourceMappingURL=a.js.map",
		"/a.js.map": string(m),
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if len(r.Secrets) != 1 || !strings.Contains(r.Secrets[0].Source, "src/config.ts") {
		t.Fatalf("secret in sourcesContent not found: %+v", r.Secrets)
	}
}

// What a script loads is followed: static and dynamic imports, workers, an
// inline module's import(), a same-site frame, Vite's dependency list and a
// webpack chunk map.
func TestFollowsWhatScriptsLoad(t *testing.T) {
	keys := 0
	key := func() string {
		keys++
		return "var k" + string(rune('a'+keys)) + `="` + stripeKey + `";`
	}
	srv := site{pages: map[string]string{
		"/": `<script type="module" src="/entry.js"></script>` +
			`<script type="module">import("/inline-chunk.js")</script>` +
			`<iframe src="/frame.html"></iframe><iframe src="https://www.youtube.example/embed/x"></iframe>`,
		"/entry.js": `import "./static-dep.js";const r=()=>import("./lazy.js");navigator.serviceWorker.register("/sw.js");` +
			`new Worker("./worker.js");const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/vite-chunk.js"])))=>i.map(i=>d[i]);` +
			`__webpack_require__.p="/";__webpack_require__.u=e=>"chunks/"+{12:"a1b2c3"}[e]+".js";`,
		"/static-dep.js":        key(),
		"/lazy.js":              key(),
		"/sw.js":                key(),
		"/worker.js":            key(),
		"/inline-chunk.js":      key(),
		"/frame.html":           `<script src="/framejs.js"></script>`,
		"/framejs.js":           key(),
		"/assets/vite-chunk.js": key(),
		"/chunks/a1b2c3.js":     key(),
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete {
		t.Fatalf("incomplete: %v %+v", r.Incomplete, r.Errors)
	}
	// Every file carries the same key under a different name; all 8 must be
	// read for the finding to list 8 locations.
	if len(r.Secrets) != 1 || 1+len(r.Secrets[0].AlsoIn) != 8 {
		var srcs []string
		for _, s := range r.Secrets {
			srcs = append(srcs, s.Source)
			srcs = append(srcs, s.AlsoIn...)
		}
		t.Fatalf("want the key from 8 followed files, got %v (scripts %v)", srcs, r.Scripts)
	}
	if r.ScriptsFollowed < 8 {
		t.Errorf("scripts_followed = %d", r.ScriptsFollowed)
	}
}

// Running out of script budget is a gap in coverage, not a clean result.
func TestScriptLimitIsIncomplete(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":     `<script src="/a.js"></script>`,
		"/a.js": `import "./b.js";import "./c.js";import "./d.js";`,
		"/b.js": "1", "/c.js": "2", "/d.js": "3",
	}}.start(t)
	r := runWith(t, srv.URL+"/", Options{MaxScripts: 2})
	if r.Complete || !hasKind(r, model.GapLimit) {
		t.Fatalf("limit: complete=%v kinds=%v", r.Complete, r.IncompleteKinds)
	}
}

// webpack's hidden-source-map writes the .map without a comment pointing at it.
func TestGuessedMap(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":         `<script src="/a.js"></script><script src="/b.js"></script>`,
		"/a.js":     "var a=1;",
		"/a.js.map": `{"version":3,"sources":["src/a.ts"],"sourcesContent":["x"]}`,
		"/b.js":     "var b=1;",
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || len(r.SourceMaps) != 1 || !r.SourceMaps[0].Guessed || r.SourceMaps[0].Status != model.MapExposed {
		t.Fatalf("guessed map: complete=%v maps=%+v", r.Complete, r.SourceMaps)
	}
	r = runWith(t, srv.URL+"/", Options{NoGuessMaps: true})
	if len(r.SourceMaps) != 0 {
		t.Errorf("--no-guess-maps still probed: %+v", r.SourceMaps)
	}
}

// A map that answers 200 with an error document or a too-deep index is
// "could not check", kept apart from script gaps.
func TestBadMapsAreMapGaps(t *testing.T) {
	deep := `{"version":3,"sources":["s.js"],"sourcesContent":["x"]}`
	for i := 0; i < 40; i++ {
		deep = `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":` + deep + `}]}`
	}
	for name, body := range map[string]string{
		"json-error": `{"error":"AccessDenied"}`,
		"xml-error":  `<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>`,
		"too-deep":   deep,
	} {
		srv := site{pages: map[string]string{
			"/":         `<script src="/a.js"></script>`,
			"/a.js":     "1\n//# sourceMappingURL=a.js.map",
			"/a.js.map": body,
		}}.start(t)
		r := run(t, srv.URL+"/", "")
		if r.Complete || !r.OnlyMapGaps() || len(r.SourceMaps) != 1 || r.SourceMaps[0].Status != model.MapInvalid {
			t.Errorf("%s: complete=%v kinds=%v maps=%+v", name, r.Complete, r.IncompleteKinds, r.SourceMaps)
		}
	}
}

func TestInlineScriptMapURLIsFetched(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":              "<script>var a=1;\n//# sourceMappingURL=/inline.js.map</script>",
		"/inline.js.map": `{"version":3,"sources":["src/i.ts"],"sourcesContent":["x"]}`,
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if len(r.ExposedMaps()) != 1 {
		t.Fatalf("inline script's map not fetched: %+v", r.SourceMaps)
	}
}

// The page itself can carry keys outside any script.
func TestSecretsInPageHTML(t *testing.T) {
	srv := site{pages: map[string]string{"/": `<html><head><meta name="stripe-key" content="` + stripeKey + `">` +
		`<script>var a=1;</script></head><body><input type="hidden" name="api_key" value="Zq3kV9xR2mT7wY1bN5cL8dF4"></body></html>`}}.start(t)
	r := run(t, srv.URL+"/", "")
	types := map[string]bool{}
	for _, s := range r.Secrets {
		types[s.Type] = true
	}
	if !types["Stripe Secret Key"] || !types["Hardcoded credential"] {
		t.Fatalf("HTML secrets missing: %+v", r.Secrets)
	}
}

// Two maps whose names differ only in case, or only by .map, get their own
// dump directories on a case-insensitive filesystem.
func TestDumpDirsAreDistinct(t *testing.T) {
	pairs := [][2]string{
		{"http://h/coll/Bundle.js.map", "http://h/coll/bundle.js.map"},
		{"http://h/coll2/m.js.map", "http://h/coll2/m.js"},
	}
	for _, p := range pairs {
		a, b := dumpDir(p[0], "x"), dumpDir(p[1], "x")
		if strings.EqualFold(a, b) {
			t.Errorf("%s and %s share dump dir %s", p[0], p[1], a)
		}
	}
}
