package detect

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/NotChaosuu/bundlexray/pkg/model"
)

const (
	notePublic = "public by design; nothing to rotate"
	noteGoogle = "Google API keys ship in front ends for Maps/Firebase. Check its API restrictions: " +
		"an unrestricted key can call billable APIs, including Gemini"
	noteAWSID = "access key ID only; it is the paired 40-char secret that grants access"
)

type secretRule struct {
	name string
	sev  model.Severity
	re   *regexp.Regexp
	note string
	// skip is how many leading bytes are a fixed prefix, excluded from the
	// randomness check on the rest.
	skip int
	// twoClasses requires the random part to mix at least two of upper,
	// lower and digit, for shapes that also fit ordinary identifiers.
	twoClasses bool
	// noBoundary is for rules whose pattern is self-delimiting (URLs, PEM).
	noBoundary bool
	// prefixOK lists text that may sit directly before a match even though
	// it ends in a letter (the /bot of a Telegram API URL).
	prefixOK []string
	// check can veto a match or re-grade it.
	check func(v string) (model.Severity, string, bool)
	// needles are literals every match contains, for patterns that do not
	// start with one. The regex then runs only in a window around each
	// needle: Go's regexp has no fast path for a leading class or
	// alternation and would otherwise simulate the NFA at every byte.
	needles []string
	back    int
	window  int
}

// Ordered most specific first: a span claimed by an earlier rule is not
// reported again by a later, looser one (sk-ant- before sk-).
var secretRules = []secretRule{
	{name: "Database URL with credentials", sev: model.High, re: dbURLRe, needles: []string{"postgres", "mysql", "mariadb", "mongodb", "redis", "amqp", "mssql", "sqlserver"}, window: 400, noBoundary: true, check: gradeDBURL},
	{name: "AWS Access Key", sev: model.High, re: regexp.MustCompile(`(?:AKIA|ASIA)[A-Z2-7]{16}`), needles: []string{"AKIA", "ASIA"}, window: 20, skip: 4, note: noteAWSID},
	{name: "GitHub Fine-Grained PAT", sev: model.High, re: regexp.MustCompile(`github_pat_[0-9A-Za-z_]{80,}`), skip: 11},
	{name: "GitHub Token", sev: model.High, re: regexp.MustCompile(`gh[pour]_[0-9A-Za-z]{36}`), skip: 4},
	// GitHub App installation tokens became variable-length in 2026.
	{name: "GitHub App Token", sev: model.High, re: regexp.MustCompile(`ghs_[0-9A-Za-z._]{36,}`), skip: 4},
	{name: "GitLab Token", sev: model.High, re: regexp.MustCompile(`glpat-[0-9A-Za-z_\-]{20,}(?:\.[0-9a-z]{2}\.[0-9a-z]{7})?`), skip: 6},
	{name: "npm Token", sev: model.High, re: regexp.MustCompile(`npm_[0-9A-Za-z]{36}`), skip: 4},
	{name: "Slack Webhook", sev: model.High, re: regexp.MustCompile(`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/\-]{20,}`), noBoundary: true},
	{name: "Discord Webhook", sev: model.High, re: regexp.MustCompile(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{15,22}/[A-Za-z0-9_\-]{60,}`), noBoundary: true},
	{name: "Slack Token", sev: model.High, re: regexp.MustCompile(`(?:xoxe\.)?xox[abeoprs]-[0-9]+-[0-9A-Za-z\-]{8,}`), needles: []string{"xox"}, back: 5, window: 400, skip: 5},
	{name: "Slack App Token", sev: model.High, re: regexp.MustCompile(`xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+`), skip: 5},
	{name: "SendGrid API Key", sev: model.High, re: regexp.MustCompile(`SG\.[0-9A-Za-z_\-]{20,24}\.[0-9A-Za-z_\-]{39,50}`), skip: 3},
	{name: "Mailgun API Key", sev: model.High, re: regexp.MustCompile(`key-[0-9a-f]{32}`), skip: 4},
	{name: "Anthropic API Key", sev: model.High, re: regexp.MustCompile(`sk-ant-[0-9A-Za-z_\-]{32,}`), skip: 7},
	// T3BlbkFJ is base64 for "OpenAI" and sits in the middle of every
	// documented OpenAI key format, legacy and project-scoped.
	{name: "OpenAI API Key", sev: model.High, re: regexp.MustCompile(`sk-(?:proj-|svcacct-|admin-|None-)?[0-9A-Za-z_\-]{16,}T3BlbkFJ[0-9A-Za-z_\-]{16,}`), skip: 3},
	{name: "OpenAI API Key", sev: model.High, re: regexp.MustCompile(`sk-(?:proj|svcacct|admin)-[0-9A-Za-z_\-]{40,}`), skip: 8, twoClasses: true},
	{name: "sk- API Key", sev: model.Medium, re: regexp.MustCompile(`sk-[0-9A-Za-z]{48}`), skip: 3, twoClasses: true,
		note: "OpenAI-style key shape; confirm the provider"},
	{name: "Stripe Secret Key", sev: model.High, re: regexp.MustCompile(`[sr]k_live_[0-9A-Za-z]{10,128}`), needles: []string{"k_live_"}, back: 1, window: 140, skip: 8},
	{name: "Stripe Webhook Secret", sev: model.High, re: regexp.MustCompile(`whsec_[0-9A-Za-z+/=]{24,}`), skip: 6},
	{name: "Stripe Test Secret Key", sev: model.Low, re: regexp.MustCompile(`[sr]k_test_[0-9A-Za-z]{10,128}`), needles: []string{"k_test_"}, back: 1, window: 140, skip: 8,
		note: "test mode only; no live charges, but it reads and writes the test account"},
	{name: "Stripe Publishable Key", sev: model.Info, re: regexp.MustCompile(`pk_(?:live|test)_[0-9A-Za-z]{10,128}`), skip: 8, note: notePublic},
	{name: "Mapbox Secret Token", sev: model.High, re: regexp.MustCompile(`sk\.eyJ[0-9A-Za-z_\-]{15,}\.[0-9A-Za-z_\-]{15,}`), skip: 3},
	{name: "Mapbox Temporary Token", sev: model.Low, re: regexp.MustCompile(`tk\.eyJ[0-9A-Za-z_\-]{15,}\.[0-9A-Za-z_\-]{15,}`), skip: 3,
		note: "expires within an hour of issue"},
	{name: "Mapbox Public Token", sev: model.Info, re: regexp.MustCompile(`pk\.eyJ[0-9A-Za-z_\-]{15,}\.[0-9A-Za-z_\-]{15,}`), skip: 3, note: notePublic},
	{name: "Supabase Secret Key", sev: model.High, re: regexp.MustCompile(`sb_secret_[0-9A-Za-z_\-]{20,}`), skip: 10},
	{name: "Supabase Publishable Key", sev: model.Info, re: regexp.MustCompile(`sb_publishable_[0-9A-Za-z_\-]{20,}`), skip: 15, note: notePublic},
	{name: "Hugging Face Token", sev: model.High, re: regexp.MustCompile(`hf_[A-Za-z]{34}`), skip: 3, check: hasUpperLower},
	{name: "Shopify Token", sev: model.High, re: regexp.MustCompile(`shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}`), needles: []string{"shp"}, window: 40, skip: 6},
	{name: "Telegram Bot Token", sev: model.High, re: regexp.MustCompile(`[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}`), needles: []string{":AA"}, back: 10, window: 40, prefixOK: []string{"/bot"}},
	{name: "Google OAuth Client Secret", sev: model.High, re: regexp.MustCompile(`GOCSPX-[0-9A-Za-z_\-]{28}`), skip: 7},
	{name: "Azure Storage Key", sev: model.High, re: regexp.MustCompile(`AccountKey=[0-9A-Za-z+/]{40,}={0,2}`), skip: 11, noBoundary: true},
	{name: "Azure Shared Access Key", sev: model.High, re: regexp.MustCompile(`SharedAccessKey=[0-9A-Za-z+/]{30,}={0,2}`), skip: 16, noBoundary: true},
	{name: "DigitalOcean Token", sev: model.High, re: regexp.MustCompile(`do[opr]_v1_[0-9a-f]{64}`), skip: 7},
	{name: "Postman API Key", sev: model.High, re: regexp.MustCompile(`PMAK-[0-9a-f]{24}-[0-9a-f]{34}`), skip: 5},
	{name: "Braintree Access Token", sev: model.High, re: regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`), skip: 24},
	{name: "Sentry Auth Token", sev: model.High, re: regexp.MustCompile(`sntry[su]_[0-9A-Za-z+/=_\-]{40,}`), skip: 7},
	{name: "PostHog Personal API Key", sev: model.High, re: regexp.MustCompile(`phx_[0-9A-Za-z]{39,}`), skip: 4},
	{name: "PostHog Project Key", sev: model.Info, re: regexp.MustCompile(`phc_[0-9A-Za-z]{39,}`), skip: 4, note: notePublic},
	{name: "Google API Key", sev: model.Info, re: regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), skip: 4, note: noteGoogle},
	{name: "JWT", sev: model.Low, re: regexp.MustCompile(`eyJ[0-9A-Za-z_\-]{8,}\.eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{10,}`), check: gradeJWT},
}

var privateKeyRe = regexp.MustCompile(`-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----`)

var dbURLRe = regexp.MustCompile(`(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://([^\s:@/"'` + "`" + `]{1,64}):([^\s@/"'` + "`" + `]{3,128})@[0-9A-Za-z.\-_]+`)

// gradeDBURL keeps connection strings whose password looks real.
func gradeDBURL(v string) (model.Severity, string, bool) {
	m := dbURLRe.FindStringSubmatch(v)
	if m == nil {
		return "", "", false
	}
	user, pass := m[1], m[2]
	if pass == user || isTypedPlaceholder(pass) || strings.ContainsAny(pass, "${}<>*") || sequential(pass) || stockPasswords[strings.ToLower(pass)] ||
		genericPlaceholder.MatchString(pass) && (hardPlaceholder.MatchString(pass) || fillerOnly(pass)) {
		// Documentation connection strings: postgres://user:your_password@...
		return "", "", false
	}
	if weakPassword(pass) || strings.Contains(lettersOnly(deLeet(pass)), "password") || genericPlaceholder.MatchString(pass) {
		// postgres:mysecretpassword and sa:YourStrong!Passw0rd are the
		// usual documentation examples, but a real database with a weak
		// password is a finding too.
		return model.Low, "a common or weak password: a documentation example, or guessable if real", true
	}
	return model.High, "", true
}

var twilioPairs = []struct {
	name string
	re   *regexp.Regexp
}{
	{"Twilio Auth Token", regexp.MustCompile(`AC[0-9a-f]{32}["'` + "`" + `]?\s*[,:]\s*["'` + "`" + `]?([0-9a-f]{32})`)},
	{"Twilio API Key Secret", regexp.MustCompile(`SK[0-9a-f]{32}["'` + "`" + `]?\s*[,:]\s*["'` + "`" + `]?([0-9A-Za-z]{32})`)},
}

// find returns the rule's matches in ascending order.
func (r *secretRule) find(text string) [][]int {
	if len(r.needles) == 0 {
		if lit, _ := r.re.LiteralPrefix(); lit != "" && !strings.Contains(text, lit) {
			return nil
		}
		return r.re.FindAllStringIndex(text, -1)
	}
	var pos []int
	for _, n := range r.needles {
		for i := 0; ; {
			j := strings.Index(text[i:], n)
			if j < 0 {
				break
			}
			pos = append(pos, i+j)
			i += j + 1
		}
	}
	sort.Ints(pos)
	var out [][]int
	next := 0
	for _, p := range pos {
		ws := p - r.back
		if ws < next {
			ws = next
		}
		if ws > p {
			continue
		}
		we := p + r.window
		if we > len(text) {
			we = len(text)
		}
		loc := r.re.FindStringIndex(text[ws:we])
		if loc == nil || ws+loc[0] > p {
			continue
		}
		out = append(out, []int{ws + loc[0], ws + loc[1]})
		next = ws + loc[1]
	}
	return out
}

type span struct{ start, end int }

// claimed tracks accepted spans per rule. Each rule's matches arrive in
// ascending order, so its slice stays sorted and overlap is a binary search
// per earlier rule rather than a scan over every accepted span.
type claimed [][]span

func (c claimed) overlaps(s span) bool {
	for _, list := range c {
		i := sort.Search(len(list), func(i int) bool { return list[i].end > s.start })
		if i < len(list) && list[i].start < s.end {
			return true
		}
	}
	return false
}

// lines maps byte offsets to line and column without rescanning the text.
type lines []int

func newLines(text string) lines {
	l := lines{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			l = append(l, i+1)
		}
	}
	return l
}

func (l lines) at(off int) (line, col int) {
	i := sort.Search(len(l), func(i int) bool { return l[i] > off }) - 1
	if i < 0 {
		i = 0
	}
	return i + 1, off - l[i] + 1
}

// hit is a finding before it is placed in the source.
type hit struct {
	typ  string
	sev  model.Severity
	val  string
	note string
	at   int
}

// Secrets scans one script. A value repeated in the same file is reported once.
func Secrets(source string, content []byte) []model.Secret {
	text := string(content)
	ln := newLines(text)
	var out []model.Secret
	seen := map[string]bool{}
	emit := func(h hit, at int) {
		key := h.typ + "\x00" + h.val
		if seen[key] {
			return
		}
		seen[key] = true
		line, col := ln.at(at)
		out = append(out, model.Secret{Type: h.typ, Value: h.val, Severity: h.sev, Source: source, Line: line, Column: col, Note: h.note})
	}
	for _, h := range scanText(text) {
		emit(h, h.at)
	}
	// Code can hide a key behind escapes the minifier had no reason to
	// write ("\x73k_live_...") or split it with +. Scan the decoded view, but
	// only around the places that changed: rescanning the whole file would
	// double the cost and find nothing new.
	if dec, offs, changes := decodeEscapes(text); dec != "" {
		for _, w := range windows(changes, len(dec), 300, 600) {
			for _, h := range scanText(dec[w.start:w.end]) {
				h.at += w.start
				if !strings.Contains(text, h.val) {
					h.note = strings.TrimPrefix(h.note+"; split or escaped in the source", "; ")
				}
				emit(h, offs.original(h.at))
			}
		}
	}
	// atob("...") configs: decode and scan the payload.
	for _, b := range atobPayloads(text) {
		for _, h := range scanText(b.text) {
			h.note = strings.TrimPrefix(h.note+"; base64-encoded in the source", "; ")
			emit(h, b.at)
		}
	}
	out = dropFragments(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() < out[j].Severity.Rank()
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Column < out[j].Column
	})
	return out
}

// windows merges [p-before, p+after) around each point into disjoint spans.
func windows(points []int, n, before, after int) []span {
	var out []span
	for _, p := range points {
		s, e := max(0, p-before), min(n, p+after)
		if len(out) > 0 && s <= out[len(out)-1].end {
			out[len(out)-1].end = max(out[len(out)-1].end, e)
			continue
		}
		out = append(out, span{s, e})
	}
	return out
}

type payload struct {
	text string
	at   int
}

var atobRe = regexp.MustCompile(`^atob\(\s*["'` + "`" + `]([A-Za-z0-9+/=]{16,})["'` + "`" + `]\s*\)`)

func atobPayloads(text string) []payload {
	var out []payload
	for i := 0; ; {
		j := strings.Index(text[i:], "atob(")
		if j < 0 {
			return out
		}
		p := i + j
		i = p + 5
		// A config blob is well under 64 KB; the cap bounds the regex.
		end := min(len(text), p+64<<10)
		m := atobRe.FindStringSubmatch(text[p:end])
		if m == nil {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(m[1]); err == nil {
			out = append(out, payload{string(b), p})
		}
	}
}

// dropFragments removes a finding whose value is only the start of a longer
// finding of the same type: the first half of a key split with +. After
// sorting, every extension of a value sits right behind it.
func dropFragments(in []model.Secret) []model.Secret {
	idx := make([]int, len(in))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(x, y int) bool {
		a, b := in[idx[x]], in[idx[y]]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Value < b.Value
	})
	frag := make([]bool, len(in))
	for k := 0; k+1 < len(idx); k++ {
		a, b := in[idx[k]], in[idx[k+1]]
		if a.Type == b.Type && len(b.Value) > len(a.Value) && strings.HasPrefix(b.Value, a.Value) {
			frag[idx[k]] = true
		}
	}
	var out []model.Secret
	for i, s := range in {
		if !frag[i] {
			out = append(out, s)
		}
	}
	return out
}

func scanText(text string) []hit {
	var out []hit
	var taken claimed

	var pk []span
	for _, loc := range privateKeyRe.FindAllStringSubmatchIndex(text, -1) {
		end, ok := privateKeyBody(text, loc[1])
		if !ok {
			continue
		}
		sev, typ := model.High, "Private Key"
		if strings.HasPrefix(text[loc[2]:loc[3]], "ENCRYPTED") {
			sev, typ = model.Medium, "Encrypted Private Key"
		}
		pk = append(pk, span{loc[0], end})
		out = append(out, hit{typ: typ, sev: sev, val: text[loc[0]:loc[1]], at: loc[0]})
	}
	taken = append(taken, pk)

	// A Twilio auth token is 32 bare hex digits; it is only recognisable by
	// where it sits, right after the account SID it belongs to:
	// twilio("AC...", "<token>") or "AC...:<token>@api.twilio.com".
	var tw []span
	for _, t := range twilioPairs {
		for _, loc := range t.re.FindAllStringSubmatchIndex(text, -1) {
			if loc[0] > 0 && isAlnum(text[loc[0]-1]) {
				continue
			}
			sp := span{loc[2], loc[3]}
			if end := sp.end; end < len(text) && isAlnum(text[end]) {
				continue
			}
			val := text[sp.start:sp.end]
			if !randomEnough(val) || isTypedPlaceholder(val) || sequential(val) {
				continue
			}
			tw = append(tw, sp)
			out = append(out, hit{typ: t.name, sev: model.High, val: val, at: sp.start})
		}
	}
	taken = append(taken, tw)

	for ri := range secretRules {
		rule := &secretRules[ri]
		var mine []span
		for _, loc := range rule.find(text) {
			sp := span{loc[0], loc[1]}
			if !rule.noBoundary && !(rule.boundaryOK(text, sp.start) && boundaryAfter(text, sp.end)) {
				continue
			}
			val := text[sp.start:sp.end]
			body := val
			if rule.skip < len(body) {
				body = body[rule.skip:]
			}
			// A rule with its own check judges placeholders itself (a DB URL
			// on an example.net host can still carry a real password).
			if !randomEnough(body) || rule.check == nil && isTypedPlaceholder(val) {
				continue
			}
			if rule.twoClasses && classes(body) < 2 {
				continue
			}
			sev, note := rule.sev, rule.note
			if rule.check != nil {
				s, n, ok := rule.check(val)
				if !ok {
					continue
				}
				sev = s
				if n != "" {
					note = n
				}
			}
			if taken.overlaps(sp) {
				continue
			}
			mine = append(mine, sp)
			out = append(out, hit{typ: rule.name, sev: sev, val: val, note: note, at: sp.start})
		}
		taken = append(taken, mine)
	}

	for _, a := range assignments(text) {
		if taken.overlaps(a.val) {
			continue
		}
		val := text[a.val.start:a.val.end]
		sev, note, ok := gradeGeneric(text[a.name.start:a.name.end], val)
		if a.bearer && randomEnough(val) && !isTypedPlaceholder(val) {
			sev, note, ok = model.Medium, "hardcoded Authorization header", true
		}
		if !ok {
			continue
		}
		out = append(out, hit{typ: "Hardcoded credential", sev: sev, val: val, note: note, at: a.val.start})
	}
	return out
}

// randomEnough rejects filler (AAAA..., 0000..., xxxx...) without dropping
// real random tokens. The entropy floor scales with what a random string of
// this length over this alphabet can reach, so short hex and long base62 are
// judged on the same footing. A fixed floor would drop about one random
// 32-hex token in 56.
func randomEnough(s string) bool {
	if len(s) < 8 {
		return true
	}
	k := alphabetSize(s)
	n := len(s)
	if n < k {
		k = n
	}
	if shannonEntropy(s) < 0.55*math.Log2(float64(k)) {
		return false
	}
	// A random string has runs of 3-4 now and then; 8 is filler.
	return !hasLongRun(s, 8)
}

func alphabetSize(s string) int {
	var lower, upper, digit, hexOnly, other = false, false, false, true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
			hexOnly = hexOnly && c <= 'f'
		case c >= 'A' && c <= 'Z':
			upper = true
			hexOnly = hexOnly && c <= 'F'
		case c >= '0' && c <= '9':
			digit = true
		default:
			other = true
			hexOnly = false
		}
	}
	if hexOnly && !(lower && upper) {
		if !lower && !upper {
			return 10
		}
		return 16
	}
	k := 0
	for _, f := range []struct {
		on bool
		n  int
	}{{lower, 26}, {upper, 26}, {digit, 10}, {other, 4}} {
		if f.on {
			k += f.n
		}
	}
	return k
}

func classes(s string) int {
	var u, l, d int
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			u = 1
		case c >= 'a' && c <= 'z':
			l = 1
		case c >= '0' && c <= '9':
			d = 1
		}
	}
	return u + l + d
}

var pemEscapes = regexp.MustCompile(`\\+[nrt]`)

// privateKeyBody accepts a PEM header only when real key material follows: at
// least 64 base64 characters before the matching END line. A bare header
// string (crypto libraries ship these as constants) is not a leak. Newlines
// may be literal, escaped once (\n) or twice (\\n, JSON inside a JS string).
func privateKeyBody(text string, from int) (int, bool) {
	// 16 KB holds any PEM key seen in practice; RSA-8192 is about 6.5 KB.
	limit := from + 16<<10
	if limit > len(text) {
		limit = len(text)
	}
	end := strings.Index(text[from:limit], "-----END ")
	if end < 0 {
		return 0, false
	}
	body := pemEscapes.ReplaceAllString(text[from:from+end], "")
	n := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case isAlnum(c) || c == '+' || c == '/' || c == '=':
			n++
		case strings.IndexByte(" \n\r\t:,-\"'`\\", c) >= 0:
		default:
			return 0, false
		}
	}
	return from + end, n >= 64
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func (r *secretRule) boundaryOK(text string, i int) bool {
	for _, p := range r.prefixOK {
		if i >= len(p) && text[i-len(p):i] == p {
			return true
		}
	}
	return boundaryBefore(text, i)
}

// boundaryBefore rejects a match that continues a longer token: a CSS class
// (mask-image-… for sk-), an identifier, or a base64 run. An escape sequence
// (\n, \t), a percent-escape (%3D) or a URL path separator directly before
// the match still counts as a boundary.
func boundaryBefore(text string, i int) bool {
	if i == 0 {
		return true
	}
	c := text[i-1]
	if c == '/' {
		return !inBase64Run(text, i-1)
	}
	if !(isAlnum(c) || c == '_' || c == '-' || c == '+' || c == '.') {
		return true
	}
	if i >= 2 && text[i-2] == '\\' && strings.IndexByte("nrtfvbu0", c) >= 0 {
		return true
	}
	if i >= 3 && text[i-3] == '%' && isHex(text[i-2]) && isHex(c) {
		return true
	}
	return false
}

// inBase64Run reports whether the '/' at i sits inside a long base64 run
// (a WASM or image blob) rather than in a URL path like /v1/ or https://.
func inBase64Run(text string, i int) bool {
	n, slashes := 0, 0
	for j := i - 1; j >= 0 && n < 64; j-- {
		c := text[j]
		if !(isAlnum(c) || c == '+' || c == '/' || c == '=') {
			break
		}
		if c == '/' {
			slashes++
		}
		n++
	}
	// In base64 a slash is one character in 64; in a path it is one in a
	// handful. A long run with few slashes is a blob.
	return n >= 24 && slashes*12 < n
}

func boundaryAfter(text string, i int) bool {
	if i >= len(text) {
		return true
	}
	c := text[i]
	return !(isAlnum(c) || c == '_')
}

func hasUpperLower(v string) (model.Severity, string, bool) {
	var u, l bool
	for i := 3; i < len(v); i++ {
		u = u || v[i] >= 'A' && v[i] <= 'Z'
		l = l || v[i] >= 'a' && v[i] <= 'z'
	}
	return model.High, "", u && l
}

func hasLongRun(s string, n int) bool {
	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

func gradeJWT(v string) (model.Severity, string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", "", false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if !decodeJSONPart(parts[0], &hdr) || hdr.Alg == "" {
		return "", "", false
	}
	var claims map[string]any
	if !decodeJSONPart(parts[1], &claims) {
		return "", "", false
	}
	role, _ := claims["role"].(string)
	iss, _ := claims["iss"].(string)
	switch {
	case role == "service_role":
		return model.High, "Supabase service_role key: bypasses row-level security", true
	case role == "anon" || (strings.Contains(iss, "supabase") && role == ""):
		return model.Info, "Supabase anon key; " + notePublic + " if row-level security is on", true
	case role == "admin" || role == "service" || role == "superuser":
		return model.Medium, "token carries role " + role, true
	}
	if exp, ok := claims["exp"].(float64); ok && exp > 0 && time.Unix(int64(exp), 0).Before(time.Now()) {
		return model.Info, "expired " + time.Unix(int64(exp), 0).UTC().Format("2006-01-02"), true
	}
	return model.Low, "", true
}

func decodeJSONPart(p string, v any) bool {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(p, "="))
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

// Typed keys have random bodies, so filler words are matched only as words
// of five or more letters in one case: "your" turns up by chance in about
// one random 40-char token in eight thousand, and "dUmMy" in one in a
// hundred thousand.
var typedPlaceholderWords = []string{"example", "placeholder", "changeme", "xxxxx", "dummy", "redacted", "insert", "replace"}

func isTypedPlaceholder(v string) bool {
	if docExamples[v] || docExamples[v[strings.IndexByte(v, '=')+1:]] || sequential(v) {
		return true
	}
	for _, ph := range typedPlaceholderWords {
		if strings.Contains(v, ph) || strings.Contains(v, strings.ToUpper(ph)) {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range freq {
		if c > 0 {
			p := c / n
			e -= p * math.Log2(p)
		}
	}
	return e
}
