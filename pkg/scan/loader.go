package scan

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A chunk loader is the expression a bundler runtime uses to turn a chunk id
// into a file name, as in webpack's
//
//	r.u=e=>"static/js/"+e+"."+{12:"a1b2",34:"c3d4"}[e]+".js"
//
// chunkLoaders finds each one from the ".js" string it ends with, reads the
// whole expression with a small parser (string and template literals, the
// id, object maps indexed by it, ||, ===, ?: and +) and evaluates it for every
// chunk id the expression names. A loader that is recognised but cannot be
// evaluated is reported rather than skipped: its chunks are code the scan
// never read.
type loader struct {
	files []string
	// rt is the runtime object the loader hangs off (r in r.u and r.p).
	rt string
	// expr and param are kept so that chunk ids found elsewhere (the
	// r.e(123) calls that load chunks) can be evaluated later.
	expr  *node
	param string
	// pass is set when some branch puts the id into the name unmapped
	// (({12:"about"}[e]||e)+".js"): the ids the maps name are then not all
	// the chunks there are.
	pass bool
	// at is the start of the expression, for messages.
	at string
}

type loaderScan struct {
	loaders []loader
	// unparsed describes each recognised loader that could not be evaluated.
	unparsed []string
	// computed counts other computed script URLs ("x/"+name+".js").
	computed int
}

// maxLoaderBack bounds how far back a loader expression may start from its
// ".js" end; a chunk map with thousands of entries is a few hundred KB.
const maxLoaderBack = 1 << 20

// loaderBudget bounds the bytes walked and parsed, and the evaluation work,
// for one script. Real bundles use a small fraction of it; a crafted one
// that would take longer is reported as not fully checked.
const loaderBudget = 32 << 20

var (
	// What sits right before a webpack chunk-filename function body.
	uAssignRe = regexp.MustCompile(`([\w$]+)\.u\s*=\s*(?:function\b[^{]{0,40}\{(?:\s|//[^\n]*\n|/\*[^*]*\*/)*(?:return\b)?|(?:\([^()]{0,40}\)|[\w$]+)\s*=>\s*(?:\{(?:\s|//[^\n]*\n|/\*[^*]*\*/)*(?:return\b)?)?)\s*$`)
	// webpack 4 names the function; its body reads the public path itself.
	jsonpSrcRe = regexp.MustCompile(`function\s+jsonpScriptSrc\s*\([^)]*\)\s*\{\s*return\s*$`)
	// An object map indexed by a variable: {...}[e] or ({...})[e].
	indexedMapRe = regexp.MustCompile(`\}\s*\)?\s*\[\s*[\w$]+\s*\]`)
)

func chunkLoaders(code string, nc spans) loaderScan {
	var out loaderScan
	seen := map[string]bool{}
	done := map[int]bool{}
	budget := loaderBudget
	vars := map[string]*node{}
	keep := func(l loader) {
		var fresh []string
		for _, f := range l.files {
			if !seen[f] {
				seen[f] = true
				fresh = append(fresh, f)
			}
		}
		l.files = fresh
		out.loaders = append(out.loaders, l)
	}
	// webpack's X.u = function, read whole: it may hold if/return statements
	// and need not end in a ".js" string at all.
	var covered spans
	for _, m := range uFuncRe.FindAllStringSubmatchIndex(code, 64) {
		if nc.contains(m[0]) || !webpackRuntime(code, code[m[2]:m[3]]) {
			continue
		}
		l, end, why, cost := uFunction(code, m[0], m[1], code[m[2]:m[3]], budget, vars)
		budget -= cost
		if why == notFunction {
			// t.u=n: an assignment, not a chunk-name function.
			continue
		}
		covered = append(covered, [2]int{m[0], max(end, m[1])})
		if why != "" {
			out.unparsed = append(out.unparsed, snippet(code[m[0]:min(len(code), max(end, m[1]+40))])+": "+why)
			continue
		}
		keep(l)
	}
	long := false
	for si, sp := range nc {
		end, ok := loaderEnd(code, sp)
		if !ok || covered.contains(sp[0]) {
			continue
		}
		if budget <= 0 {
			out.unparsed = append(out.unparsed, "too many computed script names to check them all")
			break
		}
		start, steps, ok := exprStart(code, nc, si, min(maxLoaderBack, budget))
		// Each candidate also costs a parse and two pattern checks.
		budget -= steps + 512
		if !ok && steps > maxLoaderBack && !long {
			long = true
			out.unparsed = append(out.unparsed, "a computed script name longer than 1 MB was not read")
		}
		if !ok || done[start] {
			continue
		}
		done[start] = true
		before := code[max(0, start-300):start]
		rt := ""
		uFn := false
		if m := uAssignRe.FindStringSubmatch(before); m != nil {
			rt, uFn = m[1], true
		} else if jsonpSrcRe.MatchString(before) {
			uFn = true
		}
		text := code[start:end]
		signal := uFn || indexedMapRe.MatchString(text) || strings.Contains(text, ".chunk.")
		l, why, cost := evalLoader(code, start, end, budget, vars)
		budget -= cost
		if rt != "" {
			l.rt = rt
		}
		switch {
		case why == "" && (len(l.files) > 0 || l.pass && signal):
			keep(l)
		case signal:
			if why == "" {
				why = "it names no chunk ids"
			}
			out.unparsed = append(out.unparsed, snippet(text)+": "+why)
		default:
			out.computed++
		}
	}
	return out
}

// loaderEnd reports whether a string span is the ".js" end of a computed
// file name: a string ending in .js preceded by +, or the closing piece of a
// template that interpolates something.
func loaderEnd(code string, sp [2]int) (int, bool) {
	a, b := sp[0], sp[1]
	if b-a < 4 {
		return 0, false
	}
	q := code[b-1]
	switch code[a] {
	case '"', '\'':
		if q != code[a] {
			return 0, false
		}
		p := a - 1
		for p >= 0 && isSpace(code[p]) {
			p--
		}
		if p < 0 || code[p] != '+' {
			return 0, false
		}
	case '}':
		if q != '`' {
			return 0, false
		}
	default:
		return 0, false
	}
	body := code[a+1 : b-1]
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	if !strings.HasSuffix(body, ".js") && !strings.HasSuffix(body, ".mjs") && !strings.HasSuffix(body, ".cjs") {
		return 0, false
	}
	return b, true
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// exprStart walks back from the string span nc[si] to the start of the
// expression it ends: past balanced brackets, strings, + || ?: and
// comparisons, up to an assignment, =>, return, a comma or semicolon, or an
// unmatched opening bracket.
func exprStart(code string, nc spans, si, limit int) (int, int, bool) {
	k := si - 1
	depth, colons, lastColon := 0, 0, -1
	from := nc[si][0]
	stop := func(at int) (int, int, bool) {
		if colons > 0 && lastColon >= 0 {
			return lastColon + 1, from - at, true
		}
		return at, from - at, true
	}
	for p := from - 1; p >= 0; p-- {
		if from-p > limit {
			return 0, from - p, false
		}
		for k >= 0 && nc[k][0] > p {
			k--
		}
		if k >= 0 && p < nc[k][1] {
			// A string, template piece, comment or regex: skip it whole.
			if code[nc[k][0]] == '/' && depth == 0 && nc[k][1]-nc[k][0] > 1 && code[nc[k][0]+1] != '/' && code[nc[k][0]+1] != '*' {
				// A regex literal cannot be part of a file-name expression.
				return stop(nc[k][1])
			}
			p = nc[k][0]
			k--
			continue
		}
		c := code[p]
		switch {
		case isSpace(c):
		case c == ')' || c == ']' || c == '}':
			depth++
		case c == '{' && p > 0 && code[p-1] == '$' && k >= 0 && nc[k][1] == p:
			// The ${ of a template: its } was skipped with the template text.
		case c == '(' || c == '[' || c == '{':
			if depth == 0 {
				return stop(p + 1)
			}
			depth--
		case depth > 0:
		case c == ';' || c == ',':
			return stop(p + 1)
		case c == ':':
			colons++
			lastColon = p
		case c == '?':
			if p+1 < len(code) && (code[p+1] == '.' || code[p+1] == '?') || p > 0 && code[p-1] == '?' {
				continue
			}
			if colons > 0 {
				colons--
			}
		case c == '&' && p > 0 && code[p-1] == '&':
			return stop(p + 1)
		case c == '>' && p > 0 && code[p-1] == '=':
			return stop(p + 1)
		case c == '=':
			next := byte(0)
			if p+1 < len(code) {
				next = code[p+1]
			}
			if next == '=' || p > 0 && strings.IndexByte("=!<>", code[p-1]) >= 0 {
				continue
			}
			return stop(p + 1)
		case isIdent(c):
			e := p + 1
			for p > 0 && isIdent(code[p-1]) {
				p--
			}
			switch code[p:e] {
			case "return", "case", "throw", "yield", "else", "do":
				if p == 0 || code[p-1] != '.' {
					return stop(e)
				}
			}
		}
	}
	return stop(0)
}

func snippet(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		s = s[:60] + "..." + s[len(s)-17:]
	}
	return s
}

// evalLoader parses code[start:] as one expression, which must reach end,
// and compiles it. The loader's rt is the runtime object read through .p
// (webpack 4's a.p+"...").
func evalLoader(code string, start, end, budget int, vars map[string]*node) (loader, string, int) {
	ps := &parser{lx: lexer{src: code, p: start}, vars: vars}
	ps.advance()
	n := ps.expr(0)
	cost := ps.last - start + ps.spent
	if ps.err != "" {
		return loader{}, ps.err, cost
	}
	if ps.last < end {
		return loader{}, "the expression continues in a form the parser does not read", cost
	}
	l, why, c := compile(n, budget-cost)
	l.at = snippet(code[start:end])
	return l, why, cost + c
}

// probeID is a chunk id no real map uses. If evaluating it still yields a
// file name, some branch passes unknown ids through.
const probeID = "9070001"

// compile evaluates a parsed loader for every chunk id it names (map keys
// and the values it compares the id with) and checks whether a branch passes
// other ids through.
func compile(n *node, budget int) (loader, string, int) {
	param, rt, why := freeVars(n)
	if why != "" {
		return loader{}, why, 0
	}
	l := loader{rt: rt, expr: n, param: param}
	if param == "" {
		return l, "it names no chunk ids", 0
	}
	if v, err := n.eval(param, probeID); err == "" && v.ok && strings.Contains(v.s, probeID) && fileName(v.s) {
		l.pass = true
	}
	ids := map[string]bool{}
	chunkIDs(n, param, ids)
	if len(ids) == 0 && !l.pass {
		return l, "it names no chunk ids", 0
	}
	work := len(ids) * size(n)
	if work > budget {
		return l, "too many chunk ids to evaluate", work
	}
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		v, err := n.eval(param, id)
		if err != "" {
			return l, err, work
		}
		if v.ok && fileName(v.s) {
			l.files = append(l.files, v.s)
		}
	}
	if len(l.files) == 0 && !l.pass {
		return l, "no chunk id gives a file name", work
	}
	return l, "", work
}

// fileName reports whether an evaluated name is a script file name.
func fileName(s string) bool {
	return !strings.Contains(s, "undefined") && jsPathRe.MatchString(strings.SplitN(s, "?", 2)[0])
}

// more evaluates the loader for chunk ids found later, in r.e(123) calls;
// the ids its own maps name were evaluated already.
func (l loader) more(ids []string) []string {
	var out []string
	for _, id := range ids {
		if v, err := l.expr.eval(l.param, id); err == "" && v.ok && fileName(v.s) {
			out = append(out, v.s)
		}
	}
	return out
}

var (
	// X.u = (e) => ..., X.u = function(e){...}: webpack's chunk-file name.
	uFuncRe = regexp.MustCompile(`([\w$]+)\.u\s*=\s*`)
	// The calls that load a chunk by id: r.e(123), n.e("src_pages_a").
	chunkCallRe = regexp.MustCompile(`[\w$]\.e\(\s*(?:/\*[^*]*\*/\s*)?(\d+(?:e\d+)?|"[\w\-./~]+")\s*\)`)
)

// chunkCalls lists the chunk ids code loads with X.e(id).
func chunkCalls(code string) []string {
	var ids []string
	for _, m := range chunkCallRe.FindAllStringSubmatch(code, -1) {
		ids = append(ids, chunkID(strings.Trim(m[1], `"`)))
	}
	return ids
}

// webpackRuntime reports whether rt is a webpack runtime object here, so
// that an unrelated t.u = function in a library is not taken for a loader.
func webpackRuntime(code, rt string) bool {
	if rt == "__webpack_require__" {
		return true
	}
	re := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(rt) + `\.(?:p|e|l|f)\s*=`)
	return re.MatchString(code)
}

const notFunction = "it is not a function"

// uFunction reads the function assigned at code[at:] (X.u = ...): an arrow
// with an expression body, or a body of if (cond) return x; statements and
// a final return, which it turns into one ?: expression.
func uFunction(code string, from, at int, rt string, budget int, vars map[string]*node) (loader, int, string, int) {
	ps := &parser{lx: lexer{src: code, p: at}, vars: vars}
	ps.advance()
	fail := func(why string) (loader, int, string, int) {
		return loader{}, ps.last, why, ps.last - at + ps.spent
	}
	switch {
	case ps.tok.kind == 'i' && ps.tok.s == "function":
		ps.advance()
		if ps.tok.kind == 'i' {
			ps.advance()
		}
		ps.expect("(")
		ps.advance()
		ps.expect(")")
	case ps.punct("("):
		ps.advance()
		ps.advance()
		ps.expect(")")
		ps.expect("=>")
	case ps.tok.kind == 'i':
		ps.advance()
		ps.expect("=>")
	default:
		return fail(notFunction)
	}
	if ps.err != "" {
		return fail(notFunction)
	}
	var n *node
	if ps.punct("{") {
		ps.advance()
		n = ps.body()
	} else {
		n = ps.expr(0)
	}
	if ps.err != "" {
		return fail(ps.err)
	}
	l, why, c := compile(n, budget-(ps.last-at)-ps.spent)
	if why != "" {
		return fail(why)
	}
	l.rt = rt
	l.at = snippet(code[from:min(len(code), ps.last)])
	return l, ps.last, "", ps.last - at + ps.spent + c
}

// size counts the nodes of an expression.
func size(n *node) int {
	c := 1
	for _, k := range n.kids {
		c += size(k)
	}
	return c
}

// node is one piece of a loader expression.
type node struct {
	op   byte // s literal, i identifier, m member, o object, x index, | or, = eq, ! ne, ? ternary, + concat, n not, l slice
	s    string
	kids []*node
	obj  map[string]string
	bad  map[string]bool // object entries whose value is not a constant
}

type value struct {
	s  string
	ok bool // false for a lookup that missed (undefined)
}

func truthy(v value) bool { return v.ok && v.s != "" && v.s != "false" && v.s != "0" }

func (n *node) eval(param, id string) (value, string) {
	switch n.op {
	case 's':
		return value{n.s, true}, ""
	case 'i':
		if n.s == param {
			return value{id, true}, ""
		}
		return value{}, "it reads " + n.s
	case 'm':
		// The public path (r.p) is added by the caller.
		return value{"", true}, ""
	case 'x':
		k, err := n.kids[1].eval(param, id)
		if err != "" {
			return k, err
		}
		o := n.kids[0]
		if o.bad[k.s] {
			return value{}, "a chunk map entry is not a constant"
		}
		v, ok := o.obj[k.s]
		return value{v, ok}, ""
	case '|':
		l, err := n.kids[0].eval(param, id)
		if err != "" || truthy(l) {
			return l, err
		}
		return n.kids[1].eval(param, id)
	case '=', '!':
		l, err := n.kids[0].eval(param, id)
		if err != "" {
			return l, err
		}
		r, err := n.kids[1].eval(param, id)
		if err != "" {
			return r, err
		}
		if (l.ok && r.ok && l.s == r.s) == (n.op == '=') {
			return value{"true", true}, ""
		}
		return value{"false", true}, ""
	case 'n':
		v, err := n.kids[0].eval(param, id)
		if truthy(v) {
			return value{"false", true}, err
		}
		return value{"true", true}, err
	case '?':
		c, err := n.kids[0].eval(param, id)
		if err != "" {
			return c, err
		}
		if truthy(c) {
			return n.kids[1].eval(param, id)
		}
		return n.kids[2].eval(param, id)
	case 'l':
		v, err := n.kids[0].eval(param, id)
		if err != "" || !v.ok {
			return v, err
		}
		a, b, _ := strings.Cut(n.s, ",")
		from, _ := strconv.Atoi(a)
		to := len(v.s)
		if b != "" {
			to, _ = strconv.Atoi(b)
		}
		from, to = max(0, min(from, len(v.s))), max(0, min(to, len(v.s)))
		if from > to {
			return value{"", true}, ""
		}
		return value{v.s[from:to], true}, ""
	case '+':
		var b strings.Builder
		ok := true
		for _, k := range n.kids {
			v, err := k.eval(param, id)
			if err != "" {
				return v, err
			}
			ok = ok && v.ok
			b.WriteString(v.s)
		}
		return value{b.String(), ok}, ""
	}
	return value{}, "it holds an object where a name is expected"
}

// freeVars finds the chunk id parameter (the one free identifier) and the
// runtime object read through .p, if any.
func freeVars(n *node) (param, rt, why string) {
	var walk func(n *node)
	walk = func(n *node) {
		switch n.op {
		case 'i':
			if param == "" {
				param = n.s
			} else if param != n.s && why == "" {
				why = "it reads " + param + " and " + n.s
			}
		case 'm':
			if !strings.HasSuffix(n.s, ".p") {
				if why == "" {
					why = "it reads " + n.s
				}
				return
			}
			rt = strings.TrimSuffix(n.s, ".p")
		}
		for _, k := range n.kids {
			walk(k)
		}
	}
	walk(n)
	return
}

// chunkIDs collects the ids an expression knows: the keys of the maps it
// indexes with the parameter, and the values it compares the parameter with.
func chunkIDs(n *node, param string, ids map[string]bool) {
	switch n.op {
	case 'x':
		if k := n.kids[1]; k.op == 'i' && k.s == param {
			for id := range n.kids[0].obj {
				ids[id] = true
			}
			for id := range n.kids[0].bad {
				ids[id] = true
			}
		}
	case '=', '!':
		a, b := n.kids[0], n.kids[1]
		if a.op == 'i' && a.s == param && b.op == 's' {
			ids[b.s] = true
		} else if b.op == 'i' && b.s == param && a.op == 's' {
			ids[a.s] = true
		}
	}
	for _, k := range n.kids {
		chunkIDs(k, param, ids)
	}
}

// parser is a precedence parser over the few operators a loader uses.
type parser struct {
	lx  lexer
	tok ltok
	err string
	// vars caches map variables looked up by name (shared by the parsers
	// of one script); spent is what those lookups cost.
	vars  map[string]*node
	spent int
	// last is the offset just past the last token consumed.
	last int
}

func (ps *parser) advance() {
	ps.last = ps.tok.at
	ps.tok = ps.lx.next()
}

func (ps *parser) fail(why string) *node {
	if ps.err == "" {
		ps.err = why
	}
	return &node{op: 's'}
}

func (ps *parser) punct(s string) bool { return ps.tok.kind == 'p' && ps.tok.s == s }

func (ps *parser) expect(s string) {
	if !ps.punct(s) {
		ps.fail("expected " + s)
		return
	}
	ps.advance()
}

// Binding power of each binary operator.
var binary = map[string]int{"||": 1, "??": 1, "===": 3, "==": 3, "!==": 3, "!=": 3, "+": 4}

func (ps *parser) expr(minBP int) *node {
	left := ps.unary()
	for ps.err == "" {
		if ps.punct("?") && minBP == 0 {
			ps.advance()
			a := ps.expr(0)
			ps.expect(":")
			b := ps.expr(0)
			left = &node{op: '?', kids: []*node{left, a, b}}
			continue
		}
		bp, ok := binary[ps.tok.s]
		if ps.tok.kind != 'p' || !ok || bp <= minBP {
			return left
		}
		op := ps.tok.s
		ps.advance()
		right := ps.expr(bp)
		switch op {
		case "+":
			if left.op == '+' {
				left.kids = append(left.kids, right)
			} else {
				left = &node{op: '+', kids: []*node{left, right}}
			}
		case "||", "??":
			left = &node{op: '|', kids: []*node{left, right}}
		case "===", "==":
			left = &node{op: '=', kids: []*node{left, right}}
		default:
			left = &node{op: '!', kids: []*node{left, right}}
		}
	}
	return left
}

// body reads if (c) return x; ... return y; } into c ? x : y.
func (ps *parser) body() *node {
	var conds, vals []*node
	for ps.err == "" {
		switch {
		case ps.punct(";"):
			ps.advance()
		case ps.tok.kind == 'i' && ps.tok.s == "if":
			ps.advance()
			ps.expect("(")
			c := ps.expr(0)
			ps.expect(")")
			braced := ps.punct("{")
			if braced {
				ps.advance()
			}
			if ps.tok.kind != 'i' || ps.tok.s != "return" {
				return ps.fail("an if without a return")
			}
			ps.advance()
			v := ps.expr(0)
			if ps.punct(";") {
				ps.advance()
			}
			if braced {
				ps.expect("}")
			}
			conds, vals = append(conds, c), append(vals, v)
		case ps.tok.kind == 'i' && ps.tok.s == "return":
			ps.advance()
			n := ps.expr(0)
			if ps.punct(";") {
				ps.advance()
			}
			ps.expect("}")
			for i := len(conds) - 1; i >= 0; i-- {
				n = &node{op: '?', kids: []*node{conds[i], vals[i], n}}
			}
			return n
		default:
			return ps.fail("a statement the scan does not read")
		}
	}
	return &node{op: 's'}
}

func (ps *parser) unary() *node {
	if ps.punct("!") {
		ps.advance()
		return &node{op: 'n', kids: []*node{ps.unary()}}
	}
	n := ps.primary()
	for ps.err == "" {
		switch {
		case ps.punct("["):
			if n.op == 'i' {
				// H[e] with var H={...} in the same script.
				if o := ps.mapVar(n.s); o != nil {
					n = o
				}
			}
			if n.op != 'o' {
				return ps.fail("it indexes something other than a map")
			}
			ps.advance()
			k := ps.expr(0)
			ps.expect("]")
			n = &node{op: 'x', kids: []*node{n, k}}
		case ps.punct("."):
			ps.advance()
			if ps.tok.kind == 'i' && ps.tok.s == "concat" {
				// "static/js/".concat(e, ".js"), as Babel writes +.
				ps.advance()
				ps.expect("(")
				c := &node{op: '+', kids: []*node{n}}
				for ps.err == "" && !ps.punct(")") {
					c.kids = append(c.kids, ps.expr(0))
					if ps.punct(",") {
						ps.advance()
					}
				}
				ps.expect(")")
				n = c
				continue
			}
			if ps.tok.kind == 'i' && ps.tok.s == "slice" {
				// hash.slice(0,6): a fixed-length prefix.
				ps.advance()
				ps.expect("(")
				var args []string
				for ps.err == "" && ps.tok.kind == 'n' {
					args = append(args, ps.tok.s)
					ps.advance()
					if ps.punct(",") {
						ps.advance()
					}
				}
				ps.expect(")")
				if len(args) == 0 || len(args) > 2 {
					return ps.fail("it slices a name")
				}
				n = &node{op: 'l', s: strings.Join(args, ","), kids: []*node{n}}
				continue
			}
			if ps.tok.kind != 'i' || n.op != 'i' {
				return ps.fail("it reads a property")
			}
			n = &node{op: 'm', s: n.s + "." + ps.tok.s}
			ps.advance()
		case ps.punct("(") && n.op == 'm' && strings.HasSuffix(n.s, ".h"):
			// webpack's r.h() returns the build hash, set in the same
			// runtime as r.h=()=>"6f67...".
			h, ok := ps.hashFn(strings.TrimSuffix(n.s, ".h"))
			if !ok {
				return ps.fail("it calls a function")
			}
			ps.advance()
			ps.expect(")")
			n = &node{op: 's', s: h}
		case ps.punct("("):
			return ps.fail("it calls a function")
		default:
			return n
		}
	}
	return n
}

// mapVar finds an object literal assigned to name elsewhere in the script
// (var H={7:"c0ffee"}) and parses it. It looks only in the 64 KB before the
// expression, which is where a runtime keeps its maps.
func (ps *parser) mapVar(name string) *node {
	if o, ok := ps.vars[name]; ok {
		return o
	}
	lo := max(0, ps.lx.p-64<<10)
	ps.spent += ps.lx.p - lo
	re := regexp.MustCompile(`(?:^|[\s,;{(])` + regexp.QuoteMeta(name) + `\s*=\s*\{`)
	var o *node
	if m := re.FindStringIndex(ps.lx.src[lo:ps.lx.p]); m != nil {
		sub := &parser{lx: lexer{src: ps.lx.src, p: lo + m[1] - 1}}
		sub.advance()
		if n := sub.object(); sub.err == "" {
			o = n
		}
		ps.spent += sub.last - (lo + m[1])
	}
	if ps.vars != nil {
		ps.vars[name] = o
	}
	return o
}

// hashFn finds the literal webpack's rt.h returns: rt.h=()=>"..." or
// rt.h=function(){return"..."}.
func (ps *parser) hashFn(rt string) (string, bool) {
	re := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(rt) + `\.h\s*=\s*(?:\(\)\s*=>\s*|function\s*\(\)\s*\{\s*return\s*)["']([\w]+)["']`)
	lo, hi := max(0, ps.lx.p-64<<10), min(len(ps.lx.src), ps.lx.p+64<<10)
	ps.spent += hi - lo
	m := re.FindStringSubmatch(ps.lx.src[lo:hi])
	if m == nil {
		return "", false
	}
	return m[1], true
}

func (ps *parser) primary() *node {
	t := ps.tok
	switch {
	case t.kind == 's':
		ps.advance()
		return &node{op: 's', s: t.s}
	case t.kind == 'n':
		ps.advance()
		return &node{op: 's', s: chunkID(t.s)}
	case t.kind == 'i':
		ps.advance()
		switch t.s {
		case "void":
			ps.unary()
			return &node{op: 'x', kids: []*node{{op: 'o'}, {op: 's'}}}
		case "undefined":
			return &node{op: 'x', kids: []*node{{op: 'o'}, {op: 's'}}}
		case "function", "new", "typeof", "this", "return":
			return ps.fail("it holds " + t.s)
		}
		return &node{op: 'i', s: t.s}
	case t.kind == 't':
		return ps.template()
	case ps.punct("("):
		ps.advance()
		n := ps.expr(0)
		ps.expect(")")
		return n
	case ps.punct("{"):
		return ps.object()
	}
	return ps.fail("unexpected " + strings.TrimSpace(t.s))
}

func (ps *parser) template() *node {
	n := &node{op: '+'}
	for {
		t := ps.tok
		if t.kind != 't' {
			return ps.fail("unfinished template")
		}
		n.kids = append(n.kids, &node{op: 's', s: t.s})
		ps.advance()
		if !t.more {
			return n
		}
		n.kids = append(n.kids, ps.expr(0))
		if ps.err != "" {
			return n
		}
	}
}

func (ps *parser) object() *node {
	n := &node{op: 'o', obj: map[string]string{}, bad: map[string]bool{}}
	ps.advance()
	for ps.err == "" && !ps.punct("}") {
		var key string
		switch ps.tok.kind {
		case 's', 'i':
			key = ps.tok.s
		case 'n':
			key = chunkID(ps.tok.s)
		default:
			return ps.fail("unexpected map key")
		}
		ps.advance()
		ps.expect(":")
		v := ps.expr(0)
		switch {
		case v.op == 's':
			n.obj[key] = v.s
		case v.op == 'n' && len(v.kids) == 1 && v.kids[0].op == 's':
			// !0 and !1, as in CSS chunk maps.
			n.obj[key] = map[bool]string{true: "true", false: "false"}[!truthy(value{v.kids[0].s, true})]
		default:
			n.bad[key] = true
		}
		if ps.punct(",") {
			ps.advance()
		} else if !ps.punct("}") {
			return ps.fail("unexpected map entry")
		}
	}
	ps.advance()
	return n
}

// lexer reads JavaScript tokens from a position known to be in code.
type lexer struct {
	src   string
	p     int
	tmpl  []int // brace depth at each open ${
	depth int
}

type ltok struct {
	kind byte // s string, n number, i identifier, p punctuation, t template piece, 0 end
	s    string
	at   int  // offset just past the token
	more bool // a template piece followed by ${
}

var puncts = []string{"===", "!==", "...", "==", "!=", "||", "??", "&&", "=>", "?.", "<=", ">="}

func (l *lexer) next() ltok {
	src := l.src
	for l.p < len(src) {
		c := src[l.p]
		switch {
		case isSpace(c):
			l.p++
			continue
		case c == '/' && l.p+1 < len(src) && src[l.p+1] == '/':
			e := strings.IndexByte(src[l.p:], '\n')
			if e < 0 {
				l.p = len(src)
			} else {
				l.p += e
			}
			continue
		case c == '/' && l.p+1 < len(src) && src[l.p+1] == '*':
			e := strings.Index(src[l.p+2:], "*/")
			if e < 0 {
				l.p = len(src)
			} else {
				l.p += e + 4
			}
			continue
		}
		break
	}
	if l.p >= len(src) {
		return ltok{at: l.p}
	}
	c := src[l.p]
	switch {
	case c == '"' || c == '\'':
		var b strings.Builder
		j := l.p + 1
		for j < len(src) && src[j] != c && src[j] != '\n' {
			if src[j] == '\\' && j+1 < len(src) {
				j++
			}
			b.WriteByte(src[j])
			j++
		}
		l.p = min(j+1, len(src))
		return ltok{kind: 's', s: b.String(), at: l.p}
	case c == '`' || c == '}' && len(l.tmpl) > 0 && l.depth == l.tmpl[len(l.tmpl)-1]:
		if c == '}' {
			l.tmpl = l.tmpl[:len(l.tmpl)-1]
		}
		var b strings.Builder
		j := l.p + 1
		for j < len(src) && src[j] != '`' {
			if src[j] == '\\' && j+1 < len(src) {
				j++
			} else if src[j] == '$' && j+1 < len(src) && src[j+1] == '{' {
				l.tmpl = append(l.tmpl, l.depth)
				l.p = j + 2
				return ltok{kind: 't', s: b.String(), at: l.p, more: true}
			}
			b.WriteByte(src[j])
			j++
		}
		l.p = min(j+1, len(src))
		return ltok{kind: 't', s: b.String(), at: l.p}
	case c >= '0' && c <= '9':
		j := l.p
		for j < len(src) && (isIdent(src[j]) || src[j] == '.') {
			j++
		}
		t := ltok{kind: 'n', s: src[l.p:j], at: j}
		l.p = j
		return t
	case isIdent(c):
		j := l.p
		for j < len(src) && isIdent(src[j]) {
			j++
		}
		t := ltok{kind: 'i', s: src[l.p:j], at: j}
		l.p = j
		return t
	}
	for _, p := range puncts {
		if strings.HasPrefix(src[l.p:], p) {
			l.p += len(p)
			return ltok{kind: 'p', s: p, at: l.p}
		}
	}
	switch c {
	case '{':
		l.depth++
	case '}':
		l.depth--
	}
	l.p++
	return ltok{kind: 'p', s: string(c), at: l.p}
}

// publicPath finds the literal webpack assigns to rt.p. auto is set for
// webpack 5's automatic public path (the folder of the running script plus
// suffix); literal is false when the value is computed at run time, and pub
// is then the best fallback literal, if any.
func publicPath(code, rt string) (pub string, auto, literal bool) {
	if rt == "" {
		return "", false, false
	}
	re := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(rt) + `\.p\s*=([^=>][^\n]{0,300})`)
	var fallback string
	for _, m := range re.FindAllStringSubmatchIndex(code, 8) {
		v := strings.TrimSpace(code[m[2]:m[3]])
		if v == "" {
			continue
		}
		if q := v[0]; q == '"' || q == '\'' {
			if e := strings.IndexByte(v[1:], q); e >= 0 {
				rest := strings.TrimSpace(v[e+2:])
				if rest == "" || strings.IndexByte(",;})", rest[0]) >= 0 {
					return v[1 : e+1], false, true
				}
			}
		}
		// webpack writes the currentScript lookup just above the assignment.
		near := code[max(0, m[0]-2000):m[0]]
		if am := autoPathRe.FindStringSubmatch(v); am != nil && strings.Contains(near, "currentScript") {
			return am[2], true, true
		}
		if strings.Contains(near, "Automatic publicPath") && autoChainRe.MatchString(v) {
			// s.p=c=c.replace(...).replace(/\/[^\/]+$/,"/"): the folder of the
			// running script, written as a chain.
			if sm := autoSuffixRe.FindStringSubmatch(cutExpr(v)); sm != nil {
				return sm[1], true, true
			}
			return "", true, true
		}
		if fl := lastLiteralRe.FindStringSubmatch(cutExpr(v)); fl != nil && fallback == "" {
			fallback = fl[2]
		}
	}
	return fallback, false, false
}

var (
	autoChainRe   = regexp.MustCompile(`^[\w$]+\s*(?:=\s*[\w$]+\s*)?(?:\.replace\(|\+|[,;})]|$)`)
	autoSuffixRe  = regexp.MustCompile(`\)\s*\+\s*["']([^"']*)["']\s*$`)
	autoPathRe    = regexp.MustCompile(`^[\w$]+\s*(?:\+\s*(["'])([^"']*)["'])?\s*(?:[,;})]|$)`)
	lastLiteralRe = regexp.MustCompile(`(["'])([^"'\s]*)["']\s*\)?\s*$`)
)

// cutExpr trims a right-hand side at the end of its statement.
func cutExpr(v string) string {
	depth := 0
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return v[:i]
			}
			depth--
		case ',', ';':
			if depth == 0 {
				return v[:i]
			}
		}
	}
	return v
}
