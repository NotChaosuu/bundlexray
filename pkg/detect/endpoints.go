package detect

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/NotChaosuu/bundlexray/pkg/model"
)

var (
	// Both are anchored and run on a short window after a literal hit; see
	// Endpoints.
	urlRe     = regexp.MustCompile(`^((?:https?|wss?)://[^"'` + "`" + `\s]{5,200})["'` + "`" + `]`)
	pathRe    = regexp.MustCompile(`^(/[a-zA-Z0-9_\-][a-zA-Z0-9_\-./]{2,180}(?:\?[^"'` + "`" + `]{0,80})?)["'` + "`" + `]`)
	assetExt  = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|otf|eot|map|mp4|webp|avif|webm|mp3|pdf|wasm|js|mjs)($|\?|#)`)
	hasLetter = regexp.MustCompile(`[a-zA-Z]`)
	versionRe = regexp.MustCompile(`^v[0-9]{1,2}$`)
)

// Endpoints extracts quoted URLs and absolute paths from one script, skipping
// static assets, and classifies each by its path segments.
func Endpoints(source string, content []byte) []model.Endpoint {
	text := string(content)
	var out []model.Endpoint

	at := map[string]int{}
	add := func(v string, quote int) {
		v = strings.TrimSpace(v)
		if v == "" || !looksLikeEndpoint(v) {
			return
		}
		e := endpointAt(text, quote, v, source)
		if i, ok := at[v]; ok {
			out[i] = Merge(out[i], e)
			return
		}
		at[v] = len(out)
		out = append(out, e)
	}

	// Find literal anchors first (a quote then "/", or "://") and only run
	// the regexes there. A pattern that starts with a character class makes
	// Go's regexp simulate its NFA at every byte of a multi-megabyte bundle.
	for i := 0; ; {
		j := strings.Index(text[i:], "://")
		if j < 0 {
			break
		}
		p := i + j
		i = p + 3
		// Walk back over the scheme (|0x20 folds HTTPS to https) to the quote.
		s := p
		for s > 0 && p-s < 5 && isLowerAlpha(text[s-1]|0x20) {
			s--
		}
		if s == 0 || !isQuote(text[s-1]) {
			continue
		}
		if m := urlRe.FindStringSubmatch(window(text, s, 220)); m != nil {
			add(m[1], s-1)
		}
	}
	for i := 0; i+1 < len(text); i++ {
		if text[i+1] != '/' || !isQuote(text[i]) {
			continue
		}
		if m := pathRe.FindStringSubmatch(window(text, i+1, 270)); m != nil {
			add(m[1], i)
			i += len(m[0])
		}
	}
	return out
}

func window(text string, from, n int) string {
	to := from + n
	if to > len(text) {
		to = len(text)
	}
	return text[from:to]
}

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

func isLowerAlpha(c byte) bool { return c >= 'a' && c <= 'z' }

func looksLikeEndpoint(p string) bool {
	if !hasLetter.MatchString(p) {
		return false
	}
	// Pieces of template literals and string concatenation, not endpoints.
	if strings.Contains(p, "${") || strings.Contains(p, "{{") || strings.HasSuffix(p, ".") {
		return false
	}
	if i := strings.Index(p, "://"); i > 0 {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" {
			return false
		}
		host := u.Hostname()
		if strings.HasSuffix(host, ".") || strings.HasPrefix(host, ".") || strings.ContainsAny(host, "{}$+*") ||
			(!strings.Contains(host, ".") && host != "localhost") {
			return false
		}
		return !assetExt.MatchString(u.Path)
	}
	if assetExt.MatchString(p) {
		return false
	}
	if strings.Contains(p, "//") && !strings.HasPrefix(p, "//") {
		return false
	}
	return len(p) >= 4
}

// Categories match whole path segments, so /manage hits /manage/users but not
// /pagead/managed/, and /charge does not hit /charge-up-collaboration.
var segmentCats = []struct {
	cat  string
	segs []string
}{
	{"auth", []string{"auth", "oauth", "oauth2", "login", "logout", "accounts", "passport", "signin", "sign-in", "signout", "signup", "sign-up",
		"register", "token", "tokens", "session", "sessions", "password", "sso", "saml", "openid", "authorize", "mfa", "2fa"}},
	{"admin", []string{"admin", "administrator", "internal", "private", "manage", "management", "staff", "superuser", "backoffice", "debug"}},
	{"graphql", []string{"graphql", "gql"}},
	// Not "hooks": /reference/react/hooks is documentation, and app routes
	// use it for anything.
	{"webhook", []string{"webhook", "webhooks", "callback", "callbacks"}},
	{"upload", []string{"upload", "uploads", "attachment", "attachments"}},
	{"payment", []string{"payment", "payments", "pay", "charge", "charges", "checkout", "billing", "invoice", "invoices", "subscription", "subscriptions"}},
}

// requestBefore and routeBefore match the code just before a value's opening
// quote, which is enough to tell how it is used: fetch("/x"),
// axios.post("/x"), url:"/x" and api+"/x" are requests; {path:"/x"},
// {to:"/x"}, navigate("/x") and router.push("/x") are app routes.
var (
	requestBefore = regexp.MustCompile(`(?:\bfetch|\baxios(?:\.[a-z]+)?|\.(?:get|post|put|patch|delete|head|request|ajax|getjson|sendbeacon)|\bnew\s+(?:url|request|eventsource|websocket|worker)|\.open\(\s*["'][a-z]+["']\s*,)\s*\(?\s*$|\b(?:url|baseurl|endpoint|uri|apiurl|api_url|action)\s*[:=]\s*$|[\w$]*(?:api|base|url|host|endpoint|server|origin)[\w$]*\s*\+\s*$`)
	routeBefore   = regexp.MustCompile(`\b(?:path|to|href|pathname|redirect|redirectto|from|as)\s*[:=]\s*\{?\s*$|\b(?:navigate|push|replace|redirect|navigateto|navigatebyurl)\s*\(\s*$`)
	// First path segments of documentation and content pages.
	docRoots = map[string]bool{"docs": true, "doc": true, "reference": true, "guide": true, "guides": true, "learn": true,
		"blog": true, "tutorial": true, "tutorials": true, "examples": true, "handbook": true, "manual": true, "changelog": true}
)

// endpointAt classifies v, whose opening quote is at text[quote].
func endpointAt(text string, quote int, v, source string) model.Endpoint {
	before := strings.ToLower(text[max(0, quote-64):quote])
	e := model.Endpoint{Value: v, Source: source}
	if t := strings.TrimRight(before, " \t\n"); strings.HasSuffix(t, "+") {
		e.Partial = true
	}
	switch {
	case requestBefore.MatchString(before):
		e.Context = "request"
	case routeBefore.MatchString(before):
		e.Context = "route"
	}
	e.Category = categoryIn(v, e.Context)
	return e
}

// categoryIn is classify with the code's context: a path the app routes to
// is a page, not an API call, and a documentation page is just a path.
func categoryIn(v, context string) string {
	c := classify(v)
	if context == "route" && strings.HasPrefix(v, "/") && !apiPath(v) {
		// An app page. A full URL in href: is a link to another site, and
		// path:"/v1/upload" in a request config is still an API call.
		return "route"
	}
	if context == "" && strings.HasPrefix(v, "/") {
		if seg, _, _ := strings.Cut(strings.TrimPrefix(strings.ToLower(v), "/"), "/"); docRoots[seg] {
			return "path"
		}
	}
	return c
}

// apiPath reports whether v has an API segment: api, rest, graphql, gql or a
// version such as v2.
func apiPath(v string) bool {
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	for _, s := range strings.Split(strings.ToLower(v), "/") {
		switch {
		case s == "api" || s == "rest" || s == "graphql" || s == "gql" || versionRe.MatchString(s):
			return true
		}
	}
	return false
}

// Merge combines two sightings of the same value: a request beats a route,
// and either beats a value whose use is unknown; a full value beats a
// concatenation tail.
func Merge(a, b model.Endpoint) model.Endpoint {
	rank := map[string]int{"": 0, "route": 1, "request": 2}
	if rank[b.Context] > rank[a.Context] {
		b.Partial = a.Partial && b.Partial
		return b
	}
	a.Partial = a.Partial && b.Partial
	return a
}

func classify(p string) string {
	l := strings.ToLower(p)
	if strings.HasPrefix(l, "ws://") || strings.HasPrefix(l, "wss://") {
		return "websocket"
	}
	path := l
	if i := strings.Index(path, "://"); i >= 0 {
		path = path[i+3:]
		if j := strings.IndexByte(path, '/'); j >= 0 {
			path = path[j:]
		} else {
			path = "/"
		}
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	segs := strings.Split(path, "/")
	if strings.HasPrefix(l, "http") {
		// login.example.com, admin.example.com: the first host label counts as a segment.
		if h := hostOf(l); strings.Count(h, ".") >= 2 {
			segs = append(segs, h[:strings.IndexByte(h, '.')])
		}
	}
	for _, sc := range segmentCats {
		for _, s := range segs {
			for _, want := range sc.segs {
				if s == want {
					return sc.cat
				}
			}
		}
	}
	for _, s := range segs {
		if s == "api" || s == "rest" || s == "graph" || versionRe.MatchString(s) {
			return "api"
		}
	}
	if strings.HasPrefix(l, "http") && strings.HasPrefix(hostOf(l), "api.") {
		return "api"
	}
	return "path"
}

func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if j := strings.IndexAny(u, "/?#"); j >= 0 {
		u = u[:j]
	}
	return u
}
