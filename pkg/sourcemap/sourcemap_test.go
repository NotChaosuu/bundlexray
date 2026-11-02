package sourcemap

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `{
  "version": 3,
  "file": "app.min.js",
  "sourceRoot": "",
  "sources": ["webpack://myapp/./src/index.js", "webpack://myapp/./src/api/client.js"],
  "sourcesContent": ["export const secret = 42\n", "export function call(){ return fetch('/api/me') }\n"],
  "names": [],
  "mappings": "AAAA"
}`

func TestParseAndRecoverableCount(t *testing.T) {
	sm, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if !sm.HasContent() || sm.RecoverableCount() != 2 {
		t.Errorf("recoverable = %d, want 2", sm.RecoverableCount())
	}
}

func TestParseRejectsNonSourceMap(t *testing.T) {
	for _, in := range []string{`{"foo":"bar"}`, `{"version":2,"sources":["a.js"]}`, `<!doctype html><html></html>`} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrNotSourceMap) {
			t.Errorf("Parse(%s) should fail with ErrNotSourceMap, got %v", in, err)
		}
	}
}

// The spec lets a map start with )]}' to defeat XSSI.
func TestParseSkipsXSSIPrefix(t *testing.T) {
	if _, err := Parse([]byte(")]}'\n" + sample)); err != nil {
		t.Errorf("XSSI-prefixed map rejected: %v", err)
	}
}

func TestParseFlattensIndexMaps(t *testing.T) {
	idx := `{"version":3,"sections":[
	  {"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a.js"],"sourcesContent":["A"]}},
	  {"offset":{"line":9,"column":0},"map":{"version":3,"sourceRoot":"lib","sources":["b.js","c.js"],"sourcesContent":["B",null]}}]}`
	sm, err := Parse([]byte(idx))
	if err != nil {
		t.Fatal(err)
	}
	if len(sm.Sources) != 3 || sm.RecoverableCount() != 2 || sm.Sources[1] != "lib/b.js" {
		t.Errorf("index map not flattened: %+v", sm)
	}
}

func TestReconstructWritesSanitizedTree(t *testing.T) {
	sm, _ := Parse([]byte(sample))
	dir := t.TempDir()
	res, err := sm.Reconstruct(dir)
	if err != nil || res.Written != 2 || res.Failed != 0 {
		t.Fatalf("got %+v, %v", res, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "myapp", "src", "index.js"))
	if err != nil || !strings.Contains(string(data), "secret = 42") {
		t.Errorf("reconstructed content wrong: %q %v", data, err)
	}
}

func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

func TestReconstructIsTraversalSafe(t *testing.T) {
	evil := `{
      "version": 3,
      "sources": ["../../../../../../etc/passwd", "/etc/shadow", "C:\\Windows\\System32\\evil.js", "file:///C:/Users/me/x.js"],
      "sourcesContent": ["pwned1", "pwned2", "pwned3", "pwned4"]
    }`
	sm, err := Parse([]byte(evil))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := sm.Reconstruct(dir); err != nil {
		t.Fatal(err)
	}
	for _, escape := range []string{filepath.Join(dir, "..", "..", "etc", "passwd"), "/etc/passwd", "/etc/shadow"} {
		if _, err := os.Stat(escape); err == nil {
			t.Fatalf("traversal escaped the output dir: %s exists", escape)
		}
	}
	if got := filesUnder(t, dir); len(got) != 4 {
		t.Errorf("expected 4 files safely inside outDir, got %v", got)
	}
}

// Names Windows cannot store as written. Each one must land as its own
// file, and the count must match what is on disk.
func TestReconstructSurvivesHostileFilenames(t *testing.T) {
	sources := []string{
		"CON", "nul", "src/nul.txt", "COM1.js", "lpt¹", "AUX/x.js",
		"...", "a.", "a", "b /c.js", "f:g.js", "src/App.js", "src/app.js", "lib/util.js", "lib/Util.js",
		"q/r", "q/r/s.js", "ctl\x01char.js", strings.Repeat("long", 80) + ".js",
	}
	content := make([]string, len(sources))
	for i := range content {
		content[i] = "content-" + string(rune('A'+i))
	}
	raw, _ := json.Marshal(map[string]any{"version": 3, "sources": sources, "sourcesContent": content})
	sm, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	res, err := sm.Reconstruct(dir)
	if err != nil {
		t.Fatal(err)
	}
	on := filesUnder(t, dir)
	if res.Failed != 0 || res.Written != len(sources) || len(on) != len(sources) {
		t.Fatalf("written=%d failed=%d on disk=%d want %d each\nerrors: %v\nfiles: %v",
			res.Written, res.Failed, len(on), len(sources), res.Errors, on)
	}
	seen := map[string]bool{}
	for _, f := range on {
		b, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f)))
		if seen[string(b)] {
			t.Errorf("content %q written twice (a collision overwrote a file)", b)
		}
		seen[string(b)] = true
	}
}

func TestSanitizeSourcePath(t *testing.T) {
	cases := map[string]string{
		"webpack://app/./src/x.js":      "app/src/x.js",
		"../../a/b.js":                  "a/b.js",
		"/etc/passwd":                   "etc/passwd",
		"C:\\Users\\me\\x.js":           "Users/me/x.js",
		"webpack-internal:///./util.js": "util.js",
		"src/index.js?v=2":              "src/index.js",
		"src/nul.js":                    "src/_nul.js",
		"src/f:g.js":                    "src/f_g.js",
		"a./b../c.js":                   "a/b/c.js",
	}
	for in, want := range cases {
		if got := SanitizeSourcePath(in); got != want {
			t.Errorf("SanitizeSourcePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeNeutralisesDisplayAndAliasTricks(t *testing.T) {
	for in, want := range map[string]string{
		"\u202egnp.js":      "gnp.js",
		"a\u2066b\u2069.js": "ab.js",
		"VERYLO~1/one.js":   "VERYLO_1/one.js",
		"src/PROGRA~2.js":   "src/PROGRA_2.js",
		"keep~tilde.js":     "keep~tilde.js",
	} {
		if got := SanitizeSourcePath(in); got != want {
			t.Errorf("SanitizeSourcePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseVersionAndDepth(t *testing.T) {
	if _, err := Parse([]byte(`{"version":"3","sources":["a.js"],"sourcesContent":["x"]}`)); err != nil {
		t.Errorf(`"version":"3" rejected: %v`, err)
	}
	deep := `{"version":3,"sources":["s.js"],"sourcesContent":["x"]}`
	for i := 0; i < 10; i++ {
		deep = `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":` + deep + `}]}`
	}
	sm, err := Parse([]byte(deep))
	if err != nil || sm.RecoverableCount() != 1 {
		t.Errorf("depth-10 index map: %v %+v", err, sm)
	}
	for i := 0; i < 30; i++ {
		deep = `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":` + deep + `}]}`
	}
	if _, err := Parse([]byte(deep)); !errors.Is(err, ErrNotSourceMap) {
		t.Errorf("depth-40 index map should be reported, got %v", err)
	}
}
