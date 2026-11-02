package scan

import (
	"sort"
	"strings"
	"testing"
	"time"
)

// nonCode must separate code from strings, template text, comments and
// regex literals, including code inside ${...} in a template.
func TestNonCode(t *testing.T) {
	code := "a(); // import x\n" +
		"/* import y */ b = 'import z'; c = \"im\\\"port\";\n" +
		"d = `text ${ import('./real.js') } more import`;\n" +
		"e = /import\\/[a-z]+/g; f = 4 / 2; import('./code.js');"
	nc := nonCode(code)
	in := func(sub string, nth int) bool {
		p := -1
		for i := 0; i <= nth; i++ {
			p = strings.Index(code[p+1:], sub) + p + 1
		}
		return !nc.contains(p)
	}
	cases := []struct {
		sub  string
		nth  int
		code bool
	}{
		{"import x", 0, false},
		{"import y", 0, false},
		{"import z", 0, false},
		{"import('./real.js')", 0, true},
		{"more import", 0, false},
		{"import\\/", 0, false},
		{"import('./code.js')", 0, true},
		{"f = 4", 0, true},
	}
	for _, c := range cases {
		if got := in(c.sub, c.nth); got != c.code {
			t.Errorf("%q in code = %v, want %v", c.sub, got, c.code)
		}
	}
}

func TestFindRefsStrength(t *testing.T) {
	refs := findRefs(`import "./a.js";var s="import './b.js'";/* import('./c.js') */import("./d.js");`)
	got := map[string]bool{}
	for _, r := range refs {
		got[r.spec] = r.strong
	}
	want := map[string]bool{"./a.js": true, "./b.js": false, "./c.js": false, "./d.js": true}
	for k, v := range want {
		if s, ok := got[k]; !ok || s != v {
			t.Errorf("%s: strong=%v present=%v, want strong=%v", k, s, ok, v)
		}
	}
}

// One pass per chunk map: a bundle full of ]+".js" sites must not rescan a
// 200 KB window per site, which would take minutes.
func TestWebpackChunksLinear(t *testing.T) {
	var b strings.Builder
	b.WriteString(`n.p="/s/";n.u=function(e){return"c/"+{`)
	for i := 0; i < 2000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`1` + strings.Repeat("0", 0) + string(rune('0'+i%10)) + `:"x` + string(rune('a'+i%26)) + `"`)
	}
	b.WriteString(`}[e]+".js"};`)
	b.WriteString(strings.Repeat(`a[e]+".js";`, 40000))
	start := time.Now()
	ls := chunkLoaders(b.String(), nonCode(b.String()))
	pub, _, _ := publicPath(b.String(), "n")
	if pub != "/s/" || len(ls.loaders) != 1 || len(ls.loaders[0].files) == 0 || ls.loaders[0].rt != "n" {
		t.Fatalf("pub=%q loaders=%d", pub, len(ls.loaders))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("chunk maps took %s", d)
	}
}

// Three real chunk-map shapes, and one that is only partly understood and
// must produce no guesses rather than wrong ones.
func TestWebpackChunkShapes(t *testing.T) {
	cases := map[string][]string{
		`e.u=e=>"c/"+{12:"aa11",34:"bb22"}[e]+".js"`:                                                     {"c/aa11.js", "c/bb22.js"},
		`e.u=e=>"static/chunks/"+e+"."+{12:"aa11"}[e]+".js"`:                                             {"static/chunks/12.aa11.js"},
		`t.u=e=>"js/"+({75:"debug0",411:"settings"}[e]||e)+"-"+{75:"ec9c",411:"d879",3:"aaaa"}[e]+".js"`: {"js/debug0-ec9c.js", "js/settings-d879.js", "js/3-aaaa.js"},
		`t.u=e=>x(e)+"-"+{3:"d879e57f"}[e]+".js"`:                                                        nil,
	}
	for code, want := range cases {
		got, unparsed := loaderFiles(code)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s\n  got  %v\n  want %v", code, got, want)
		}
		if want == nil && len(unparsed) == 0 {
			t.Errorf("%s: a loader it cannot read must be reported", code)
		}
	}
}

// loaderFiles returns every chunk file the loaders in code name, sorted, and
// the loaders it recognised but could not read.
func loaderFiles(code string) ([]string, []string) {
	ls := chunkLoaders(code, nonCode(code))
	var files []string
	for _, l := range ls.loaders {
		files = append(files, l.files...)
	}
	sort.Strings(files)
	return files, ls.unparsed
}
