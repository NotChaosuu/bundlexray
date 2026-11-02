package scan

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Where a reference resolves from.
const (
	fromScript = iota // the importing script (import, import(), importScripts)
	fromPage          // the document (new Worker, serviceWorker.register)
	fromRoot          // the build base (Vite's preload list)
	fromNext          // Next.js's /_next/ folder (static/chunks/x.js)
)

// ref is a script that another script loads.
type ref struct {
	spec string
	// strong refs are certain to be loaded (static import, import(),
	// workers in code); failing to fetch one leaves the scan incomplete.
	strong bool
	// exact refs come from a list the bundler wrote (Vite's preload list,
	// Next.js chunk lists, a Parcel manifest): real files, so a 404 is a
	// gap too. Refs that are neither are import text inside strings or
	// comments, where a 404 is only noted.
	exact bool
	base  int
	// json marks import ... with {type:"json"}: a JSON body is expected.
	json bool
	// bare is a specifier like "app" that only an import map can resolve.
	bare bool
	// module marks an import specifier, which goes through the import map.
	module bool
}

var (
	// Each runs on a short window after a literal needle; see findRefs.
	importFromRe = regexp.MustCompile(`^import\s*(?:[\w$*\s{},]+?\s*from\s*)?["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `](\s*(?:with|assert)\s*\{\s*type\s*:\s*["'](\w+)["']\s*\})?`)
	exportFromRe = regexp.MustCompile(`^export\s*(?:\*(?:\s*as\s+[\w$]+)?|\{[^}]*\})\s*from\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]`)
	dynImportRe  = regexp.MustCompile(`^import\s*\(\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]\s*(,\s*\{\s*(?:with|assert)\s*:\s*\{\s*type\s*:\s*["'](\w+)["'])?`)
	workerRe     = regexp.MustCompile(`^(?:new\s+(?:Shared)?Worker|serviceWorker\.register|importScripts)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]`)
	viteDepRe    = regexp.MustCompile(`["']((?:\./|/)?[\w\-./@~]+\.m?js)["']`)
	viteDefRe    = regexp.MustCompile(`__vite__mapDeps\s*=|__vite__fileDeps\s*=|viteFileDeps\s*=`)
	jsPathRe     = regexp.MustCompile(`\.(?:m|c)?js$`)
	// A Next.js chunk path, relative to /_next/ or absolute.
	nextChunkRe = regexp.MustCompile(`^(?:(?:https?://[^/"'\s]+)?/(?:[\w\-.]+/)*_next/)?static/(?:[\w\-.~]+/)*chunks/[\w\-./@~%]+\.m?js$`)
	listStrRe   = regexp.MustCompile(`^\s*["']([^"'\s]+)["']\s*([,\]])`)
)

// findRefs lists the scripts a script would load. It finds literal needles
// and runs anchored patterns on a short window after each, and it knows
// which parts of the code are strings and comments: an import written inside
// a string (sample code, a docs snippet) is at most a weak reference.
func findRefs(code string) []ref {
	refs, _ := findRefsIn(code, nonCode(code))
	return refs
}

// findRefsIn is findRefs on code whose strings and comments are already
// known. It also returns each loader list it recognised but could not read.
func findRefsIn(code string, nc spans) (out []ref, unparsed []string) {
	seen := map[string]int{}
	add := func(spec string, strong bool, base int, typ string) *ref {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			return nil
		}
		if i, dup := seen[spec]; dup {
			// The same path as a real import and as list text: keep the
			// stronger reading.
			out[i].strong = out[i].strong || strong
			return nil
		}
		r, ok := classifySpec(spec, typ)
		if !ok {
			return nil
		}
		r.strong = strong
		if base == fromRoot || base == fromNext {
			// Lists hold base-relative paths (assets/x.js), not bare module
			// names.
			if !jsPathRe.MatchString(strings.SplitN(spec, "?", 2)[0]) {
				return nil
			}
			if r.bare {
				r.bare = false
				r.base = base
			}
		} else if base == fromPage && r.base == fromScript {
			r.base = fromPage
		}
		seen[spec] = len(out)
		out = append(out, r)
		return &out[len(out)-1]
	}
	scanNeedle(code, "import", true, func(p int, w string) {
		inCode := !nc.contains(p)
		m := dynImportRe.FindStringSubmatch(w)
		if m == nil {
			m = importFromRe.FindStringSubmatch(w)
		}
		if m != nil {
			if r := add(m[1], inCode, fromScript, m[3]); r != nil {
				r.module = true
			}
		}
	})
	scanNeedle(code, "export", true, func(p int, w string) {
		if m := exportFromRe.FindStringSubmatch(w); m != nil {
			if r := add(m[1], !nc.contains(p), fromScript, ""); r != nil {
				r.module = true
			}
		}
	})
	for _, n := range []string{"new ", "serviceWorker.register", "importScripts"} {
		scanNeedle(code, n, n != "serviceWorker.register", func(p int, w string) {
			if m := workerRe.FindStringSubmatch(w); m != nil {
				base := fromPage
				if strings.HasPrefix(w, "importScripts") {
					base = fromScript
				}
				add(m[1], !nc.contains(p), base, "")
			}
		})
	}
	exact := func(spec string, base int) {
		if r := add(spec, false, base, ""); r != nil {
			r.exact = true
		}
	}
	// Vite lists every preloadable chunk in one array, relative to the base.
	vite := 0
	for _, n := range []string{"__vite__mapDeps", "__vite__fileDeps", "viteFileDeps"} {
		scanNeedle(code, n, false, func(p int, w string) {
			// The list can run to many KB: read it from the code, not the
			// window.
			if i := strings.Index(w, "["); i >= 0 {
				list := code[p+i : min(len(code), p+i+4<<20)]
				if j := strings.Index(list, "]"); j >= 0 {
					for _, m := range viteDepRe.FindAllStringSubmatch(list[:j], -1) {
						vite++
						base := fromScript
						if !strings.HasPrefix(m[1], "./") && !strings.HasPrefix(m[1], "../") && !strings.HasPrefix(m[1], "/") {
							base = fromRoot
						}
						exact(m[1], base)
					}
				}
			}
		})
	}
	if vite == 0 && viteDefRe.MatchString(code) {
		unparsed = append(unparsed, "Vite preload list (__vite__mapDeps) in a form the scan does not read")
	}
	// Next.js lists chunks as plain strings: Turbopack's
	// ["static/chunks/x.js",...].map(t=>s.l(t)), App Router flight data
	// (self.__next_f, where the quotes are escaped), and the
	// static/immutable/chunks/ folder of newer builds.
	scanNeedle(code, "chunks/", false, func(p int, w string) {
		if spec, ok := quotedAt(code, p, nc); ok && nextChunkRe.MatchString(strings.SplitN(spec, "?", 2)[0]) {
			switch {
			case strings.HasPrefix(spec, "static/"):
				exact(spec, fromNext)
			case strings.HasPrefix(spec, "/"):
				exact(spec, fromPage)
			default:
				// A full URL is often another site's, as in a consent
				// tool's table of the scripts a page loads: a guess.
				add(spec, false, fromPage, "")
			}
		}
	})
	// React Router and Remix list every route module in a JSON manifest:
	// window.__reactRouterManifest={"routes":{"root":{"module":"/assets/root-x.js","imports":[...]}}}
	for _, n := range []string{"__reactRouterManifest=", "__remixManifest="} {
		scanNeedle(code, n, false, func(p int, w string) {
			rest := strings.TrimLeft(code[p+len(n):min(len(code), p+len(n)+64)], " ")
			if !strings.HasPrefix(rest, "{") {
				// window.__reactRouterManifest=e: the code that sets it,
				// not the manifest.
				return
			}
			var m any
			if json.NewDecoder(strings.NewReader(code[p+len(n):])).Decode(&m) != nil {
				unparsed = append(unparsed, "route manifest ("+strings.TrimSuffix(n, "=")+") in a form the scan does not read")
				return
			}
			for _, f := range manifestModules(m) {
				exact(f, fromPage)
			}
		})
	}
	// VitePress maps each page to its chunk: assets/<page>.md.<hash>.js.
	scanNeedle(code, "__VP_HASH_MAP__=JSON.parse(", false, func(p int, w string) {
		lit, _, ok := jsString(w[len("__VP_HASH_MAP__=JSON.parse("):])
		var m map[string]string
		if !ok || json.Unmarshal([]byte(lit), &m) != nil {
			if lit, ok = jsStringAt(code, p+len("__VP_HASH_MAP__=JSON.parse(")); !ok || json.Unmarshal([]byte(lit), &m) != nil {
				unparsed = append(unparsed, "VitePress page map (__VP_HASH_MAP__) in a form the scan does not read")
				return
			}
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			exact("assets/"+k+"."+m[k]+".js", fromRoot)
		}
	})
	// Parcel: require("./bundle-manifest").register(..., JSON.parse('{...}'))
	scanNeedle(code, "bundle-manifest", false, func(p int, w string) {
		i := strings.Index(w, "JSON.parse(")
		if i < 0 {
			return
		}
		lit, _, ok := jsString(w[i+len("JSON.parse("):])
		var files []string
		var obj map[string]string
		var arr []string
		if ok && json.Unmarshal([]byte(lit), &obj) == nil {
			for _, v := range obj {
				files = append(files, v)
			}
		} else if ok && json.Unmarshal([]byte(lit), &arr) == nil {
			files = arr
		} else {
			unparsed = append(unparsed, "Parcel bundle manifest in a form the scan does not read")
			return
		}
		sort.Strings(files)
		for _, f := range files {
			if jsPathRe.MatchString(f) {
				if !strings.HasPrefix(f, "/") && !strings.Contains(f, "://") && !strings.HasPrefix(f, ".") {
					f = "./" + f
				}
				exact(f, fromScript)
			}
		}
	})
	// SystemJS: System.register(["./dep.js", ...], function ...)
	scanNeedle(code, "System.register(", false, func(p int, w string) {
		rest := w[len("System.register("):]
		if _, n, ok := jsString(rest); ok {
			// System.register("name", [...])
			rest = rest[n:]
		}
		rest = strings.TrimLeft(rest, " ,\n\t")
		if !strings.HasPrefix(rest, "[") {
			return
		}
		rest = rest[1:]
		for {
			m := listStrRe.FindStringSubmatchIndex(rest)
			if m == nil {
				return
			}
			add(rest[m[2]:m[3]], !nc.contains(p), fromScript, "")
			if rest[m[4]] == ']' {
				return
			}
			rest = rest[m[1]:]
		}
	})
	// Module federation remotes: "app1@https://cdn.example.com/remoteEntry.js".
	// Documentation compiled to JSX quotes such paths as whole literals too,
	// so a remote is only exact where the federation runtime loads it
	// (__webpack_require__.l("...") or an entry: field); elsewhere it is
	// followed as a guess.
	scanNeedle(code, "remoteEntry", false, func(p int, w string) {
		spec, ok := quotedAt(code, p, nc)
		if !ok {
			return
		}
		if at := strings.IndexByte(spec, '@'); at > 0 && !strings.Contains(spec[:at], "/") {
			spec = spec[at+1:]
		}
		lo, before := max(0, p-300), ""
		if q := strings.LastIndexAny(code[lo:p], "\"'`"); q >= 0 {
			before = strings.TrimRight(code[lo:lo+q], " ")
		}
		if strings.HasSuffix(before, ".l(") || strings.HasSuffix(before, "entry:") || strings.HasSuffix(before, `entry":`) {
			exact(spec, fromPage)
		} else {
			add(spec, false, fromPage, "")
		}
	})
	return out, unparsed
}

// manifestModules collects the "module" and "imports" paths of a route
// manifest.
func manifestModules(v any) []string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				switch s := x.(type) {
				case string:
					if k == "module" && jsPathRe.MatchString(strings.SplitN(s, "?", 2)[0]) {
						out = append(out, s)
					}
				case []any:
					if k == "imports" {
						for _, i := range s {
							if s, ok := i.(string); ok && jsPathRe.MatchString(strings.SplitN(s, "?", 2)[0]) {
								out = append(out, s)
							}
						}
						continue
					}
				}
				walk(x)
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	walk(v)
	sort.Strings(out)
	return out
}

// jsStringAt reads a long quoted string from the code itself, for literals
// longer than a needle window.
func jsStringAt(code string, p int) (string, bool) {
	lit, _, ok := jsString(code[p:min(len(code), p+8<<20)])
	return lit, ok
}

// quotedAt returns the string literal around code[p], when p is inside a
// short one that is a whole literal in the code, or JSON with escaped quotes
// held in a JS string (Next.js flight data). A path quoted inside a longer
// string is documentation text, not a list the bundler wrote.
func quotedAt(code string, p int, nc spans) (string, bool) {
	isQuote := func(c byte) bool { return c == '"' || c == 0x27 || c == '`' }
	s := p
	for s > 0 && p-s < 300 && !isQuote(code[s-1]) && code[s-1] != '\n' && code[s-1] != ' ' {
		s--
	}
	if s == 0 || !isQuote(code[s-1]) {
		return "", false
	}
	q := code[s-1]
	e := p
	for e < len(code) && e-p < 300 && code[e] != q && code[e] != '\n' && code[e] != ' ' {
		e++
	}
	if e >= len(code) || code[e] != q {
		return "", false
	}
	spec := code[s:e]
	if s >= 2 && code[s-2] == 0x5c {
		// \"static/chunks/x.js\" in flight data: the closing quote is
		// escaped too.
		if !inFlightData(code, s, nc) {
			return "", false
		}
		spec = strings.TrimSuffix(spec, string(rune(0x5c)))
	} else if !nc.whole(s-1, e+1) {
		return "", false
	}
	if strings.IndexByte(spec, 0x5c) >= 0 {
		return "", false
	}
	return spec, true
}

// inFlightData reports whether code[p] is inside the string argument of a
// Next.js App Router self.__next_f.push([1,"..."]).
func inFlightData(code string, p int, nc spans) bool {
	i := sort.Search(len(nc), func(i int) bool { return nc[i][1] > p })
	if i == len(nc) || nc[i][0] > p {
		return false
	}
	return strings.Contains(code[max(0, nc[i][0]-24):nc[i][0]], "__next_f.push(")
}

// jsString reads the quoted JavaScript string at the start of s (after
// spaces) and returns its value with simple escapes undone, and how many
// bytes of s it used.
func jsString(s string) (string, int, bool) {
	i := 0
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	if i >= len(s) || (s[i] != '"' && s[i] != 0x27) {
		return "", 0, false
	}
	q := s[i]
	var b strings.Builder
	for i++; i < len(s); i++ {
		switch c := s[i]; {
		case c == q:
			return b.String(), i + 1, true
		case c == 0x5c && i+1 < len(s):
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
		case c == '\n':
			return "", 0, false
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, false
}

// classifySpec keeps what a browser would actually fetch as a script: a
// relative or absolute URL ending in .js/.mjs/.cjs (a JSON module may end in
// .json), or a bare specifier for the import map. Template pieces (${...}),
// JSON-escaped paths, stylesheets, components and extensionless example
// paths are dropped.
func classifySpec(spec, typ string) (ref, bool) {
	if strings.ContainsAny(spec, "`\\") || strings.Contains(spec, "${") || typ == "css" {
		return ref{}, false
	}
	r := ref{spec: spec, json: typ == "json"}
	path := spec
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	relative := strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") ||
		strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://")
	switch {
	case r.json:
		return r, strings.HasSuffix(path, ".json") || !relative
	case relative:
		return r, jsPathRe.MatchString(path)
	case strings.Contains(spec, ":"):
		return ref{}, false
	case jsPathRe.MatchString(path) && !strings.Contains(path, "/"):
		// sw.js, worker.js: a plain filename, relative to its base.
		return r, true
	}
	// Bare specifier ("app", "lib/util.js"): only an import map resolves it.
	r.bare = true
	return r, true
}

// chunkID writes a minified numeric key the way webpack names the file:
// 5e3 is chunk 5000.
func chunkID(k string) string {
	if m, e, ok := strings.Cut(k, "e"); ok && m != "" && e != "" && isDigits(m) && isDigits(e) && len(e) < 3 {
		n, _ := strconv.Atoi(m)
		p, _ := strconv.Atoi(e)
		for ; p > 0; p-- {
			n *= 10
		}
		return strconv.Itoa(n)
	}
	return k
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// scanNeedle calls f with the position and a window starting at each
// occurrence of needle. With word set, an occurrence inside a longer
// identifier (reimport) is skipped.
func scanNeedle(code, needle string, word bool, f func(pos int, window string)) {
	for i := 0; ; {
		j := strings.Index(code[i:], needle)
		if j < 0 {
			return
		}
		p := i + j
		i = p + len(needle)
		if word && p > 0 && isIdent(code[p-1]) {
			continue
		}
		f(p, window(code, p, 600))
	}
}

func isIdent(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func window(s string, from, n int) string {
	to := from + n
	if to > len(s) {
		to = len(s)
	}
	return s[from:to]
}

// spans is a sorted list of [start, end) ranges.
type spans [][2]int

// whole reports whether [a, b) is exactly one of the spans.
func (s spans) whole(a, b int) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i][0] >= a })
	return i < len(s) && s[i][0] == a && s[i][1] == b
}

func (s spans) contains(p int) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i][1] > p })
	return i < len(s) && s[i][0] <= p
}

// nonCode returns the strings, template text, comments and regex literals in
// JavaScript source. It is a lexer only in the sense needed here: it tracks
// quotes, escapes, ${} nesting in templates, and tells a regex from a
// division by the previous significant character.
func nonCode(code string) spans {
	var out spans
	var tmpl []int // brace depth at each open ${ in a template
	depth := 0
	prev := byte(0)
	n := len(code)
	for i := 0; i < n; {
		c := code[i]
		switch {
		case c == '/' && i+1 < n && code[i+1] == '/':
			e := strings.IndexByte(code[i:], '\n')
			if e < 0 {
				e = n - i
			}
			out = append(out, [2]int{i, i + e})
			i += e
			continue
		case c == '/' && i+1 < n && code[i+1] == '*':
			e := strings.Index(code[i+2:], "*/")
			if e < 0 {
				out = append(out, [2]int{i, n})
				return out
			}
			out = append(out, [2]int{i, i + 2 + e + 2})
			i += e + 4
			continue
		case c == '"' || c == '\'':
			j := i + 1
			for j < n && code[j] != c && code[j] != '\n' {
				if code[j] == '\\' {
					j++
				}
				j++
			}
			out = append(out, [2]int{i, min(j+1, n)})
			i = j + 1
			prev = '"'
			continue
		case c == '`' || c == '}' && len(tmpl) > 0 && depth == tmpl[len(tmpl)-1]+1:
			if c == '}' {
				// The } that closes a ${...}: back to template text.
				depth--
				tmpl = tmpl[:len(tmpl)-1]
			}
			j := i + 1
			for j < n && code[j] != '`' {
				if code[j] == '\\' {
					j += 2
					continue
				}
				if code[j] == '$' && j+1 < n && code[j+1] == '{' {
					break
				}
				j++
			}
			out = append(out, [2]int{i, min(j+1, n)})
			if j+1 < n && code[j] == '$' {
				tmpl = append(tmpl, depth)
				depth++
				i = j + 2
				prev = '{'
				continue
			}
			i = j + 1
			prev = '"'
			continue
		case c == '/' && (prev == 0 || strings.IndexByte("(,=:[!&|?{};+-*%<>~^", prev) >= 0 || isIdent(prev) && keywordBefore(code, i)):
			j := i + 1
			class := false
			for j < n && code[j] != '\n' && (code[j] != '/' || class) {
				switch code[j] {
				case '\\':
					j++
				case '[':
					class = true
				case ']':
					class = false
				}
				j++
			}
			out = append(out, [2]int{i, min(j+1, n)})
			i = j + 1
			prev = '"'
			continue
		case c == '{':
			depth++
		case c == '}':
			depth--
		}
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			prev = c
		}
		i++
	}
	return out
}

// keywordBefore reports whether the word ending just before code[i] (spaces
// skipped) is a keyword after which a / starts a regex, as in return/x/.test(s).
func keywordBefore(code string, i int) bool {
	e := i
	for e > 0 && isSpace(code[e-1]) {
		e--
	}
	s := e
	for s > 0 && e-s < 12 && isIdent(code[s-1]) {
		s--
	}
	if s > 0 && code[s-1] == '.' {
		return false
	}
	switch code[s:e] {
	case "return", "typeof", "case", "do", "else", "in", "of", "instanceof", "new", "delete", "void", "throw", "yield", "await":
		return true
	}
	return false
}
