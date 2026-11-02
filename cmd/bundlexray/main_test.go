package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var ghToken = "gh" + "p_" + "Zq3kV9xR2mT7wY1bN5cL8dF4gH6jK0pQ" + "s9Te"

func server(t *testing.T, pages map[string]string, deny ...string) string {
	t.Helper()
	denied := map[string]bool{}
	for _, d := range deny {
		denied[d] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if denied[r.URL.Path] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		body, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "application/javascript")
		case strings.HasSuffix(r.URL.Path, ".map"):
			w.Header().Set("Content-Type", "application/json")
		default:
			w.Header().Set("Content-Type", "text/html")
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func cli(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// The gate fails closed on an incomplete scan; --allow-incomplete opts out.
func TestExitCodeOnIncompleteScan(t *testing.T) {
	url := server(t, map[string]string{"/": `<script src="/a.js"></script>`}, "/a.js")
	code, out, _ := cli("-q", "--exit-code", url+"/")
	if code != exitIncomplete {
		t.Errorf("all-403 scan with --exit-code: exit %d, want %d", code, exitIncomplete)
	}
	if strings.Contains(out, "nothing exposed") || !strings.Contains(out, "INCOMPLETE") {
		t.Errorf("output must not read as clean:\n%s", out)
	}
	if code, _, _ := cli("-q", "--exit-code", "--allow-incomplete", url+"/"); code != exitOK {
		t.Errorf("--allow-incomplete: exit %d, want 0", code)
	}
	if code, _, _ := cli("-q", url+"/"); code != exitOK {
		t.Errorf("without --exit-code a scan exits 0, got %d", code)
	}
}

func TestJSONCarriesCompletenessAndEmptyArrays(t *testing.T) {
	url := server(t, map[string]string{"/": `<script src="/a.js"></script>`}, "/a.js")
	_, out, _ := cli("--json", url+"/")
	var doc struct {
		Report map[string]json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc.Report["complete"]) != "false" {
		t.Errorf("complete = %s", doc.Report["complete"])
	}
	for _, k := range []string{"secrets", "endpoints", "source_maps", "skipped", "warnings"} {
		if string(doc.Report[k]) != "[]" {
			t.Errorf("%s = %s, want []", k, doc.Report[k])
		}
	}
	if !strings.Contains(string(doc.Report["errors"]), `"status": 403`) {
		t.Errorf("errors should carry the 403: %s", doc.Report["errors"])
	}
}

// The README's own CI example puts the flags after the URL, which the
// standard flag package would silently ignore.
func TestFlagsAfterTarget(t *testing.T) {
	url := server(t, map[string]string{"/": `<script src="/a.js"></script>`, "/a.js": `var t="` + ghToken + `"`})
	if code, _, _ := cli(url+"/", "--exit-code", "--min-severity", "high", "-q"); code != exitFindings {
		t.Errorf("trailing --exit-code ignored: exit %d", code)
	}
}

func TestPublicKeysDoNotTripGate(t *testing.T) {
	gkey := "AI" + "za" + "SyB4kZ9xR2mT7wY1bN5cL8dF4gH6jK0pQs9"
	pk := "pk_" + "live_" + "51H8xZq3kV9xR2mT7wY1bN5cL8dF4gH6jK0pQ"
	url := server(t, map[string]string{"/": `<script src="/a.js"></script>`, "/a.js": `m("` + gkey + `");s("` + pk + `")`})
	code, out, _ := cli("--exit-code", url+"/")
	if code != exitOK {
		t.Errorf("a Maps key and a Stripe publishable key failed the gate: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "+2 public-by-design keys") {
		t.Errorf("info keys should be summarized, not listed:\n%s", out)
	}
}

func TestExposedMapTripsGate(t *testing.T) {
	url := server(t, map[string]string{
		"/":         `<script src="/a.js"></script>`,
		"/a.js":     "1\n//# sourceMappingURL=a.js.map",
		"/a.js.map": `{"version":3,"sources":["src/a.ts"],"sourcesContent":["export {}"]}`,
	})
	if code, _, _ := cli("-q", "--exit-code", url+"/"); code != exitFindings {
		t.Errorf("exposed source map with code: exit %d, want %d", code, exitFindings)
	}
}

func TestUsageAndErrors(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{nil, exitError},
		{[]string{"httpfoo://x"}, exitError},
		{[]string{"--min-severity", "critical", "https://x.example"}, exitError},
		{[]string{"https://a.example", "https://b.example"}, exitError},
		{[]string{"--secrets-only", "--endpoints-only", "https://a.example"}, exitError},
		{[]string{"--bogus"}, exitError},
		{[]string{"--version"}, exitOK},
		{[]string{"-h"}, exitOK},
	}
	for _, c := range cases {
		if code, _, _ := cli(c.args...); code != c.want {
			t.Errorf("%v: exit %d, want %d", c.args, code, c.want)
		}
	}
}

// An unreachable target is a broken run (2), never "findings" (1).
func TestUnreachableTargetIsError(t *testing.T) {
	if code, _, _ := cli("-q", "--exit-code", "--allow-private", "--timeout", "2s", "http://127.0.0.1:1/"); code != exitError {
		t.Errorf("connection refused: exit %d, want %d", code, exitError)
	}
}

func TestFlagValidation(t *testing.T) {
	url := server(t, map[string]string{"/": `<script src="/a.js"></script>`, "/a.js": "1"})
	for _, args := range [][]string{
		{"--timeout", "0", url + "/"},
		{"--timeout", "-1s", url + "/"},
		{"--max-scripts", "0", url + "/"},
	} {
		if code, _, _ := cli(args...); code != exitError {
			t.Errorf("%v: exit %d, want %d", args, code, exitError)
		}
	}
}

// --secrets-only and --endpoints-only do not fail CI on what they hide.
func TestGateFollowsWhatIsShown(t *testing.T) {
	url := server(t, map[string]string{
		"/":         `<script src="/a.js"></script>`,
		"/a.js":     "1\n//# sourceMappingURL=a.js.map",
		"/a.js.map": `{"version":3,"sources":["src/a.ts"],"sourcesContent":["export {}"]}`,
	})
	if code, _, _ := cli("-q", "--exit-code", "--secrets-only", url+"/"); code != exitOK {
		t.Errorf("--secrets-only failed on a hidden source map: exit %d", code)
	}
	url2 := server(t, map[string]string{"/": `<script src="/a.js"></script>`, "/a.js": `var t="` + ghToken + `"`})
	if code, _, _ := cli("-q", "--exit-code", "--endpoints-only", url2+"/"); code != exitOK {
		t.Errorf("--endpoints-only failed on a hidden secret: exit %d", code)
	}
}

// Hosts that refuse every .map (Vercel) would otherwise force everyone onto
// --allow-incomplete, which also hides real script failures.
func TestAllowUnreadableMaps(t *testing.T) {
	url := server(t, map[string]string{"/": `<script src="/a.js"></script>`, "/a.js": "1\n//# sourceMappingURL=a.js.map"}, "/a.js.map")
	if code, _, _ := cli("-q", "--exit-code", url+"/"); code != exitIncomplete {
		t.Errorf("unreadable map: exit %d, want %d", code, exitIncomplete)
	}
	if code, _, _ := cli("-q", "--exit-code", "--allow-unreadable-maps", url+"/"); code != exitOK {
		t.Errorf("--allow-unreadable-maps: exit %d, want 0", code)
	}
	url2 := server(t, map[string]string{"/": `<script src="/a.js"></script>`}, "/a.js")
	if code, _, _ := cli("-q", "--exit-code", "--allow-unreadable-maps", url2+"/"); code != exitIncomplete {
		t.Errorf("--allow-unreadable-maps hid a script failure: exit %d", code)
	}
}

func TestConcurrencyAndTimeBounds(t *testing.T) {
	url := server(t, map[string]string{"/": `<script src="/a.js"></script>`, "/a.js": "var a=1;"})
	for _, args := range [][]string{
		{"--concurrency", "0", url + "/"},
		{"--concurrency", "65", url + "/"},
		{"--concurrency", "2000000", url + "/"},
		{"--max-time", "0", url + "/"},
	} {
		if code, _, _ := cli(args...); code != exitError {
			t.Errorf("%v: exit %d, want %d", args, code, exitError)
		}
	}
	if code, _, _ := cli("-q", "--concurrency", "64", url+"/"); code != exitOK {
		t.Errorf("--concurrency 64 rejected: exit %d", code)
	}
}

// "Scanned: X of Y" counts the scripts the limit left unread.
func TestScannedCountsUnfetched(t *testing.T) {
	u := server(t, map[string]string{
		"/":     `<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>`,
		"/a.js": "var a=1;", "/b.js": "var b=1;", "/c.js": "var c=1;",
	})
	_, out, _ := cli(u+"/", "--max-scripts", "1", "--no-guess-maps", "--allow-private")
	if !strings.Contains(out, "1 of 3 scripts") {
		t.Fatalf("output: %s", out)
	}
}

// Failed script URLs go under their own heading, not under whichever
// incompleteness reason was printed last.
func TestFailedRequestsListedUnderOwnHeading(t *testing.T) {
	u := server(t, map[string]string{
		"/":     `<script src="/gone.js"></script><script src="/b.js"></script>`,
		"/b.js": "var b=1;\n//# sourceMappingURL=/b.js.map\n",
	}, "/b.js.map")
	_, out, _ := cli(u+"/", "--allow-private")
	head := strings.Index(out, "failed requests:")
	gone := strings.Index(out, "/gone.js")
	if head < 0 || gone < head || strings.LastIndex(out[:head], "source map") < 0 {
		t.Fatalf("output: %s", out)
	}
}

// A guessed chunk that does not exist is not counted as a script the scan
// missed: a complete scan reads "N of N" and lists the guess apart.
func TestScannedLeavesOutMissingGuesses(t *testing.T) {
	u := server(t, map[string]string{
		"/":          `<script src="/rt.js"></script>`,
		"/rt.js":     `var r={};r.p="/";r.u=e=>"c/"+e+"."+{1:"a1",2:"b2"}[e]+".js";`,
		"/c/1.a1.js": "var a=1;",
	})
	_, out, _ := cli(u+"/", "--no-guess-maps", "--allow-private")
	if !strings.Contains(out, "2 of 2 scripts (1 found by following imports), 1 guessed chunk not found") || strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("output: %s", out)
	}
}

// Dump paths are printed with forward slashes on every OS.
func TestDumpPathsUseForwardSlashes(t *testing.T) {
	u := server(t, map[string]string{
		"/":         `<script src="/a.js"></script>`,
		"/a.js":     "var a=1;\n//# sourceMappingURL=a.js.map",
		"/a.js.map": `{"version":3,"sources":["src/x.js"],"sourcesContent":["var x=1"],"mappings":"AAAA"}`,
	})
	dir := t.TempDir()
	_, out, _ := cli(u+"/", "--allow-private", "--dump", dir+"/rec", "--json")
	var doc struct {
		Report struct {
			SourceMaps []struct {
				DumpDir string `json:"dump_dir"`
			} `json:"source_maps"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Report.SourceMaps) != 1 {
		t.Fatalf("json: %v %s", err, out)
	}
	if d := doc.Report.SourceMaps[0].DumpDir; d == "" || strings.Contains(d, `\`) {
		t.Errorf("dump_dir %q", d)
	}
	_, _, errs := cli(u+"/", "--allow-private", "--dump", dir+"/rec2")
	if i := strings.Index(errs, "-> "); i < 0 || strings.Contains(errs[i:], `\`) {
		t.Errorf("progress: %s", errs)
	}
}
