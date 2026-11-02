package scan

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NotChaosuu/bundlexray/pkg/fetch"
	"github.com/NotChaosuu/bundlexray/pkg/model"
)

// site serves a fixed set of paths; anything listed in deny gets 403.
type site struct {
	pages map[string]string
	types map[string]string
	deny  map[string]bool
}

func (s site) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.deny[r.URL.Path] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		body, ok := s.pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if ct := s.types[r.URL.Path]; ct != "" {
			w.Header().Set("Content-Type", ct)
		} else {
			w.Header().Set("Content-Type", typeFor(r.URL.Path))
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// typeFor labels a fixture the way a real server would.
func typeFor(path string) string {
	switch {
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".mjs"):
		return "application/javascript"
	case strings.HasSuffix(path, ".map"), strings.HasSuffix(path, ".json"):
		return "application/json"
	}
	return "text/html"
}

func run(t *testing.T, target string, dump string) *model.Report {
	t.Helper()
	r, err := Run(target, Options{Fetch: fetch.Options{Timeout: 5 * time.Second}, Concurrency: 4, DumpDir: dump})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const page4 = `<script src="/s1.js"></script><script src="/s2.js"></script><script src="/s3.js"></script><script src="/s4.js"></script>`

var ghToken = "gh" + "p_" + "Zq3kV9xR2mT7wY1bN5cL8dF4gH6jK0pQ" + "s9Te"

// Nothing was read, so nothing may be reported as clean.
func TestAllScriptsFailIsIncomplete(t *testing.T) {
	srv := site{
		pages: map[string]string{"/": page4},
		deny:  map[string]bool{"/s1.js": true, "/s2.js": true, "/s3.js": true, "/s4.js": true},
	}.start(t)
	r := run(t, srv.URL+"/", "")
	if r.Complete || r.ScriptsScanned != 0 || len(r.Errors) != 4 || r.Errors[0].Status != 403 {
		t.Fatalf("want incomplete with 4 HTTP 403 errors, got complete=%v scanned=%d errors=%+v", r.Complete, r.ScriptsScanned, r.Errors)
	}
}

func TestPartialFailureIsIncomplete(t *testing.T) {
	srv := site{
		pages: map[string]string{"/": page4, "/s4.js": `var t="` + ghToken + `"`},
		deny:  map[string]bool{"/s1.js": true, "/s2.js": true, "/s3.js": true},
	}.start(t)
	r := run(t, srv.URL+"/", "")
	if r.Complete || r.ScriptsScanned != 1 || len(r.Secrets) != 1 {
		t.Fatalf("got complete=%v scanned=%d secrets=%d", r.Complete, r.ScriptsScanned, len(r.Secrets))
	}
	if !strings.Contains(strings.Join(r.Incomplete, ";"), "3 of 4") {
		t.Errorf("reason should say 3 of 4 failed: %v", r.Incomplete)
	}
}

// A 200 that serves HTML (WAF challenge, soft 404, SPA fallback) is a failed
// read, not a bundle with nothing in it.
func TestHTMLInsteadOfScriptIsAFailure(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":       `<script src="/app.js"></script>`,
		"/app.js": "<!DOCTYPE html><html><body>blocked</body></html>",
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if r.Complete || len(r.Errors) != 1 {
		t.Fatalf("HTML in place of JS must be an error: complete=%v errors=%+v", r.Complete, r.Errors)
	}
}

// A 404 looks exactly like a CDN that filters by user agent or region, so it
// cannot be read as "nothing there".
func TestMissingScriptIsIncomplete(t *testing.T) {
	srv := site{pages: map[string]string{"/": `<script src="/gone.js"></script><script src="/a.js"></script>`, "/a.js": "1"}}.start(t)
	r := run(t, srv.URL+"/", "")
	if r.Complete || len(r.Errors) != 1 || r.Errors[0].Status != 404 {
		t.Fatalf("404 script: complete=%v errors=%+v", r.Complete, r.Errors)
	}
}

func TestCleanSiteIsComplete(t *testing.T) {
	srv := site{pages: map[string]string{"/": `<script src="/a.js"></script>`, "/a.js": "console.log(1)"}}.start(t)
	r := run(t, srv.URL+"/", "")
	if !r.Complete || r.ScriptsScanned != 1 || len(r.Incomplete) != 0 {
		t.Fatalf("clean site should be complete: %+v", r)
	}
}

// A referenced map that 403s is "could not check", not "no map".
func TestSourceMapOutcomes(t *testing.T) {
	srv := site{
		pages: map[string]string{
			"/":     `<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script><script src="/d.js"></script>`,
			"/a.js": "1\n//# sourceMappingURL=a.js.map", "/b.js": "2\n//# sourceMappingURL=b.js.map",
			"/c.js": "3\n//# sourceMappingURL=c.js.map", "/d.js": "4\n//# sourceMappingURL=d.js.map",
			"/b.js.map": "<!doctype html><html>app shell</html>",
			"/d.js.map": `{"version":3,"sources":["src/x.js"],"sourcesContent":["x"]}`,
		},
		deny: map[string]bool{"/a.js.map": true},
	}.start(t)
	r := run(t, srv.URL+"/", "")
	got := map[string]string{}
	for _, m := range r.SourceMaps {
		got[filepath.Base(m.MapURL)] = m.Status
	}
	want := map[string]string{"a.js.map": model.MapUnreadable, "b.js.map": model.MapNotFound, "c.js.map": model.MapNotFound, "d.js.map": model.MapExposed}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: status %q, want %q", k, got[k], v)
		}
	}
	if r.Complete {
		t.Error("an unreadable map makes the scan incomplete")
	}
	if len(r.ExposedMaps()) != 1 {
		t.Errorf("exactly one map is exposed: %+v", r.ExposedMaps())
	}
}

// One map shared by four chunks is one finding, fetched once, written
// once; a key repeated in every chunk is one secret.
func TestSharedMapAndRepeatedSecretDeduped(t *testing.T) {
	var mapHits int
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(page4)) })
	for _, s := range []string{"/s1.js", "/s2.js", "/s3.js", "/s4.js"} {
		body := "var t=\"" + ghToken + "\";" + s + "\n//# sourceMappingURL=/app.js.map"
		mux.HandleFunc(s, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
	}
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		mapHits++
		w.Write([]byte(`{"version":3,"sources":["a.js","b.js"],"sourcesContent":["A","B"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	dump := t.TempDir()
	r := run(t, srv.URL+"/", dump)
	if len(r.SourceMaps) != 1 || len(r.SourceMaps[0].AlsoReferencedBy) != 3 || mapHits != 1 {
		t.Fatalf("want one map referenced by 4 bundles and fetched once; maps=%+v fetches=%d", r.SourceMaps, mapHits)
	}
	if r.SourceMaps[0].Reconstructed != 2 {
		t.Errorf("reconstructed %d, want 2", r.SourceMaps[0].Reconstructed)
	}
	if len(r.Secrets) != 1 || len(r.Secrets[0].AlsoIn) != 3 {
		t.Errorf("want one secret seen in 4 files, got %+v", r.Secrets)
	}
}

// data: script bodies are scanned, not counted and dropped.
func TestDataScriptIsScanned(t *testing.T) {
	srv := site{pages: map[string]string{"/": `<script src="data:text/javascript,var%20t%3D%22` + ghToken + `%22"></script>`}}.start(t)
	r := run(t, srv.URL+"/", "")
	if len(r.Secrets) != 1 || r.InlineScanned != 1 || len(r.Scripts) != 0 {
		t.Fatalf("data: script not scanned inline: secrets=%+v inline=%d scripts=%v", r.Secrets, r.InlineScanned, r.Scripts)
	}
}

func TestIdenticalBundlesScannedOnce(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":     `<script src="/a.js?v=1"></script><script src="/a.js?v=2"></script>`,
		"/a.js": "var t=\"" + ghToken + "\"",
	}}.start(t)
	r := run(t, srv.URL+"/", "")
	if r.ScriptsScanned != 2 || len(r.Skipped) != 1 || len(r.Secrets) != 1 || len(r.Secrets[0].AlsoIn) != 0 {
		t.Fatalf("duplicate content should be read but scanned once: %+v", r)
	}
}

// A map URL is relative to where the script was actually served from.
func TestMapResolvedAgainstRedirectedScript(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`<script src="/latest.js"></script>`)) })
	mux.HandleFunc("/latest.js", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/v9/app.js", http.StatusFound) })
	mux.HandleFunc("/v9/app.js", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x\n//# sourceMappingURL=app.js.map")) })
	mux.HandleFunc("/v9/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":3,"sources":["a.js"],"sourcesContent":["A"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	r := run(t, srv.URL+"/", "")
	if len(r.ExposedMaps()) != 1 {
		t.Fatalf("map next to the redirected script not found: %+v", r.SourceMaps)
	}
}

func TestDumpWritesUnderOneDirPerMap(t *testing.T) {
	srv := site{pages: map[string]string{
		"/":         `<script src="/a.js"></script>`,
		"/a.js":     "1\n//# sourceMappingURL=a.js.map",
		"/a.js.map": `{"version":3,"sources":["../../../x.js","nul"],"sourcesContent":["X","N"]}`,
	}}.start(t)
	dump := t.TempDir()
	r := run(t, srv.URL+"/", dump)
	m := r.ExposedMaps()
	if len(m) != 1 || m[0].Reconstructed != 2 || m[0].ReconstructFailed != 0 {
		t.Fatalf("dump result wrong: %+v", m)
	}
	// Reported with forward slashes on every OS.
	if !strings.HasPrefix(m[0].DumpDir, filepath.ToSlash(dump)) || strings.Contains(m[0].DumpDir, `\`) {
		t.Errorf("dump dir %s outside %s", m[0].DumpDir, dump)
	}
	if _, err := os.Stat(filepath.Join(filepath.FromSlash(m[0].DumpDir), "_nul")); err != nil {
		t.Errorf("reserved name not renamed: %v", err)
	}
}

func TestBadTarget(t *testing.T) {
	for _, target := range []string{"httpfoo://x", "ftp://x/", "http://", "example.com"} {
		if _, err := Run(target, Options{}); err == nil {
			t.Errorf("%q should be rejected", target)
		}
	}
}
