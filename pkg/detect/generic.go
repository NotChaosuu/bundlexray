package detect

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/NotChaosuu/bundlexray/pkg/model"
)

// credentialNeedles find candidate names. A needle can sit anywhere in the
// name (JWT_SECRET_PROD, clientSecretValue, GITHUBTOKEN); gradeGeneric then
// decides from the whole name whether it really names a credential.
var credentialNeedles = []string{"secret", "password", "passwd", "pwd", "pass", "token", "key", "credential", "authorization", "pat"}

// valueChars is one character of a quoted value: no quote, whitespace or
// backslash, except the \/ that JSON encoders write for a slash.
const valueChars = `(?:[^"'` + "`" + `\s\\]|\\/)`

var (
	// The value after the name: optional closing quote, ':' or '=', an
	// optional fallback (a.key||"..."), then the quoted value. Quotes may be
	// escaped, for JSON held inside a JS string ({\"secret\":\"...\"}).
	assignedValue = regexp.MustCompile(`^(?:\\?["'])?\s*[:=]\s*(?:[\w$.]+\s*(?:\|\||\?\?)\s*)?\\?["'` + "`" + `](` + valueChars + `{10,200})\\?["'` + "`" + `]`)
	// Authorization: "Bearer <token>"
	authValue = regexp.MustCompile(`^(?:\\?["'])?\s*[:=]\s*\\?["'` + "`" + `](?:Bearer|Basic|Token)\s+([0-9A-Za-z._~+/=\-]{16,400})\\?["'` + "`" + `]`)
	// <meta name="api-key" content="..."> and <input name="api_key" value="...">
	attrValue = regexp.MustCompile(`^["']\s[^<>]{0,100}?\b(?:value|content)\s*=\s*["']([^"'\s<>]{10,200})["']`)
)

type assignment struct {
	name, val span
	bearer    bool
}

func isNameChar(c byte) bool { return isAlnum(c) || c == '_' || c == '$' || c == '-' }

// nameAround returns the full name containing text[kw:end]: identifier
// characters on both sides, or, for a quoted name ("Secret Key"), the whole
// quoted string.
func nameAround(text string, kw, end int) (int, int) {
	s, e := kw, end
	for s > 0 && kw-s < 64 && isNameChar(text[s-1]) {
		s--
	}
	for e < len(text) && e-end < 64 && isNameChar(text[e]) {
		e++
	}
	if (s > 0 && text[s-1] == ' ') || (e < len(text) && text[e] == ' ') {
		qs, qe := s, e
		for qs > 0 && kw-qs < 64 && (isNameChar(text[qs-1]) || text[qs-1] == ' ') {
			qs--
		}
		for qe < len(text) && qe-end < 64 && (isNameChar(text[qe]) || text[qe] == ' ') {
			qe++
		}
		if qs > 0 && qe < len(text) && (text[qs-1] == '"' || text[qs-1] == '\'') && text[qe] == text[qs-1] {
			return qs, qe
		}
	}
	return s, e
}

// assignments finds name = "value" pairs whose name contains a credential
// needle, in ascending order of value position.
func assignments(text string) []assignment {
	low := asciiLower(text)
	var out []assignment
	seen := map[int]bool{}
	for _, w := range credentialNeedles {
		for i := 0; ; {
			j := strings.Index(low[i:], w)
			if j < 0 {
				break
			}
			kw := i + j
			i = kw + len(w)
			start, end := nameAround(text, kw, kw+len(w))
			if seen[start] {
				continue
			}
			seen[start] = true
			lim := min(len(text), end+460)
			rest := text[end:lim]
			m := authValue.FindStringSubmatchIndex(rest)
			bearer := m != nil
			if m == nil {
				m = assignedValue.FindStringSubmatchIndex(rest)
			}
			if m == nil && start >= 6 {
				before := strings.ToLower(text[max(0, start-6):start])
				if before == `name="` || before == `name='` {
					m = attrValue.FindStringSubmatchIndex(rest)
				}
			}
			if m == nil {
				continue
			}
			out = append(out, assignment{name: span{start, end}, val: span{end + m[2], end + m[3]}, bearer: bearer})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].val.start < out[j].val.start })
	return out
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// nameWords splits STRIPE_SECRET_KEY, clientSecret, api-key and password2
// into lower-case words.
func nameWords(name string) []string {
	var words []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case !isAlnum(c):
			flush()
		case len(cur) > 0 && isDigit(c) != isDigit(cur[len(cur)-1]):
			flush()
			cur = append(cur, c)
		case isUpper(c) && len(cur) > 0 && !isUpper(cur[len(cur)-1]):
			flush()
			cur = append(cur, c)
		case isUpper(c) && len(cur) > 1 && isUpper(cur[len(cur)-1]) && i+1 < len(name) && name[i+1] >= 'a' && name[i+1] <= 'z':
			// APIKey -> API, Key
			flush()
			cur = append(cur, c)
		default:
			cur = append(cur, c)
		}
	}
	flush()
	return words
}

var (
	// heads are the words that make a name a credential name.
	heads = set("secret", "secrets", "password", "passwd", "pwd", "pass", "token", "key", "credential", "credentials", "authorization", "pat", "passphrase")
	// Only these may follow the head: JWT_SECRET_PROD, API_KEY_V2,
	// SECRET_KEY_BASE, clientSecretValue. passwordPolicy and secretHash name
	// something about a credential, not the credential.
	nameSuffixes = set("prod", "production", "prd", "dev", "develop", "development", "staging", "stage", "stg", "live",
		"test", "testing", "qa", "uat", "local", "value", "val", "base", "env", "string", "str", "b64", "base64", "hex",
		"raw", "enc", "encoded", "new", "old", "default", "primary", "secondary", "main", "current", "override", "plain",
		"text", "v", "b", "pem", "der", "jwk", "json", "key", "secret", "site", "server", "backend",
		"backup", "bak", "previous", "prev", "rotated", "alt", "alternate", "legacy", "sandbox", "internal", "private",
		"readonly", "ro", "rw", "temp", "tmp", "replica", "fallback", "fallbacks", "original", "orig", "admin", "write")
	// Secret words that make any name a credential name, wherever they sit:
	// JWT_SECRET_BACKUP, DB_PASSWORD_REPLICA, SECRET_KEY_FALLBACKS.
	anywhereWords = set("secret", "secrets", "password", "passwd", "pwd", "privatekey", "passphrase")
	// What follows a secret word when the name is about the secret rather
	// than the secret itself: passwordPolicy, secretHash, passwordMinLength.
	metaWords = set("policy", "policies", "strength", "length", "len", "min", "max", "minlength", "maxlength", "rule", "rules",
		"regex", "regexp", "pattern", "hint", "help", "placeholder", "label", "field", "input", "error", "errors", "message",
		"msg", "prompt", "title", "required", "confirm", "confirmation", "confirmed", "reset", "forgot", "change", "changed",
		"update", "updated", "expiry", "expires", "expiration", "expired", "age", "ttl", "timeout", "attempts", "count",
		"retries", "visible", "visibility", "show", "shown", "hide", "hidden", "toggle", "icon", "button", "btn", "form", "page",
		"url", "uri", "link", "route", "dialog", "modal", "enabled", "disabled", "enable", "disable", "mode", "valid",
		"validator", "validation", "validate", "invalid", "strong", "weak", "meter", "score", "mask", "masked", "format",
		"template", "schema", "hash", "hashed", "name", "names", "id", "ids", "arn", "ref", "path", "version", "versions",
		"manager", "store", "provider", "type", "kind", "status", "state", "view", "screen", "step", "flow", "less",
		"login", "sent", "set", "rotation", "storage", "header", "param", "selector", "fingerprint", "proof", "question",
		"santa", "group", "region", "visible", "tab", "menu")
	// Words before a secret word that make the name UI state.
	verbWords   = set("show", "hide", "toggle", "forgot", "reveal", "mask", "unmask")
	versionWord = regexp.MustCompile(`^(?:v?[0-9]+)$`)
	// Strict secret words: whatever else the name says, the value is secret.
	strictWords = set("secret", "secrets", "password", "passwd", "pwd", "pass", "private", "privatekey", "credential", "credentials")
	// Other words that put a value on the server side.
	hardWords = set("admin", "personal", "rest", "master", "root", "service", "servicerole", "signing", "webhook",
		"hmac", "jwt", "encryption", "management", "runner")
	softWords   = set("token", "auth", "authorization", "write", "access", "bearer", "apitoken")
	sessionWord = set("csrf", "xsrf", "nonce")
	// A token named for one of these is pagination, theming or UI state.
	tokenNoise = set("page", "next", "cursor", "continuation", "resume", "i18n", "design", "color", "colour", "css", "cache",
		"sort", "id", "worker", "path", "reset", "push", "fcm", "device", "notification", "registration", "theme", "style",
		"font", "size", "spacing", "parse", "parser", "lexer", "syntax", "eof", "regex", "cancel", "cancellation", "abort",
		"sync", "change", "etag", "version", "query", "search", "filter", "invite", "verification", "confirm", "confirmation",
		// On-chain tokens are currencies, not credentials.
		"usdc", "usdt", "native", "governance", "wrapped", "reward", "staking", "lp", "erc20", "nft", "gas")
	// Words that make NAME_KEY a credential name (ALGOLIA_ADMIN_KEY, HMAC_KEY).
	keyQualifiers = set("api", "app", "sdk", "admin", "write", "master", "signing", "encryption", "license", "client",
		"server", "service", "secret", "access", "private", "hmac", "jwt", "session", "cookie", "aes", "crypto", "auth",
		"rest", "personal", "management", "webhook", "consumer", "integration", "insert", "ingestion", "ingest",
		"account", "application", "deploy")
	publicWords = set("public", "publishable", "anon", "sitekey", "vapid")
	// Words that make a token an account or service credential.
	accessWords = set("access", "auth", "api", "bearer", "refresh", "admin", "bot", "app", "client", "user")
	// Framework prefixes that expose an env var to the browser on purpose.
	// Naming a secret this way is how secrets leak, so it never demotes.
	publicEnvPrefixes = []string{"NEXT_PUBLIC_", "NUXT_PUBLIC_", "EXPO_PUBLIC_", "VITE_", "REACT_APP_", "GATSBY_", "PUBLIC_", "VUE_APP_"}
	// Services whose credentials only ever belong on a server.
	serverVendors = set("twilio", "stripe", "sendgrid", "mailgun", "aws", "openai", "anthropic", "github", "gitlab",
		"slack", "discord", "telegram", "shopify", "database", "db", "postgres", "mysql", "mongo", "mongodb", "redis", "smtp", "ses")
	// Prefixes run together with a head in one word: GITHUBTOKEN, DBPASS.
	runPrefixes = set("api", "app", "access", "auth", "secret", "private", "client", "admin", "root", "user", "db", "smtp",
		"master", "signing", "encryption", "hmac", "jwt", "session", "refresh", "bearer", "bot", "service", "sdk", "server")
)

// clientKeys lists browser SDKs whose keys ship in the page by design, with
// the name words that identify that public key. A vendor word alone is not
// enough: DATADOG_API_KEY and LAUNCHDARKLY_API_KEY are secret, while the
// Datadog client token and LaunchDarkly client-side ID are not.
var clientKeys = map[string]struct{ need, allow map[string]bool }{
	"amplitude":    {nil, set("api", "key")},
	"mixpanel":     {nil, set("token", "project", "api", "key")},
	"segment":      {set("write"), set("write", "key")},
	"mparticle":    {nil, set("api", "key")},
	"onetrust":     {nil, set("api", "key", "id", "domain")},
	"gigya":        {nil, set("api", "key")},
	"heap":         {nil, set("app", "id", "api", "key")},
	"hotjar":       {nil, set("id", "site", "key")},
	"fullstory":    {nil, set("org", "id", "key")},
	"posthog":      {nil, set("project", "api", "key", "write")},
	"algolia":      {set("search"), set("search", "only", "api", "key")},
	"sentry":       {set("dsn"), set("dsn")},
	"launchdarkly": {set("client"), set("client", "side", "id", "key")},
	"datadog":      {set("client", "rum"), set("client", "token", "rum", "application", "app", "id")},
	"recaptcha":    {nil, set("site", "key", "enterprise", "invisible", "v2", "v3", "public")},
	"hcaptcha":     {nil, set("site", "key", "public")},
	"turnstile":    {nil, set("site", "key", "public")},
	"pusher":       {set("key"), set("app", "key")},
	"onesignal":    {set("app"), set("app", "id")},
	"intercom":     {set("app"), set("app", "id")},
	"braze":        {set("sdk"), set("sdk", "api", "key")},
	"optimizely":   {nil, set("sdk", "key", "project", "id")},
	"appsflyer":    {nil, set("dev", "key", "app", "id")},
	"branch":       {nil, set("key", "live", "test")},
	"tinymce":      {nil, set("api", "key")},
	"bugsnag":      {nil, set("api", "key", "notifier")},
	"growthbook":   {nil, set("client", "key", "sdk")},
	"statsig":      {nil, set("client", "key", "sdk")},
	"rollbar":      {nil, set("access", "token", "client", "post")},
	"contentful":   {nil, set("access", "token", "delivery", "preview", "space", "id")},
	"logrocket":    {nil, set("app", "id", "key")},
	"mapbox":       {nil, set("access", "token", "public")},
	"firebase":     {nil, set("api", "key", "app", "id", "web")},
	"stripe":       {set("publishable"), set("publishable", "key")},
	"google":       {set("maps"), set("maps", "api", "key", "browser")},
	"alchemy":      {nil, set("api", "key")},
	"paddle":       {set("client"), set("client", "token", "side")},
}

func set(ws ...string) map[string]bool {
	m := map[string]bool{}
	for _, w := range ws {
		m[w] = true
	}
	return m
}

// splitWord breaks run-together words: mparticleapikey, GITHUBTOKEN, DBPASS,
// MAILCHIMPAPIKEY, TWILIOAUTHTOKEN. A compound tail (apikey, authtoken,
// signingkey) or a long secret word (password, secret) is split off
// whatever precedes it. A short head (pass, pwd, token, key, pat) is split
// off only when a known word is left, so compass, bypass, monkey and hotkey
// stay whole.
func splitWord(w string) []string {
	if heads[w] || len(w) <= 3 {
		return []string{w}
	}
	for v := range clientKeys {
		if strings.HasPrefix(w, v) && len(w) > len(v) {
			if rest := splitKnown(w[len(v):]); rest != nil {
				return append([]string{v}, rest...)
			}
		}
	}
	for _, t := range compoundTails {
		if !strings.HasSuffix(w, t.suffix) || len(w) == len(t.suffix) {
			continue
		}
		pre := w[:len(w)-len(t.suffix)]
		if len(pre) < 2 {
			continue
		}
		return append(splitWord(pre), t.parts...)
	}
	for _, h := range []string{"pass", "pwd", "token", "key", "pat"} {
		if !strings.HasSuffix(w, h) || len(w) == len(h) {
			continue
		}
		pre := w[:len(w)-len(h)]
		if runPrefixes[pre] || serverVendors[pre] || knownVendors[pre] {
			return []string{pre, h}
		}
		if sub := splitWord(pre); len(sub) > 1 {
			return append(sub, h)
		}
	}
	return []string{w}
}

// compoundTails are word pairs that end a run-together name, longest first.
var compoundTails = []struct {
	suffix string
	parts  []string
}{
	{"servicerolekey", []string{"servicerole", "key"}},
	{"webhooksecret", []string{"webhook", "secret"}},
	{"clientsecret", []string{"client", "secret"}},
	{"accesstoken", []string{"access", "token"}},
	{"signingkey", []string{"signing", "key"}},
	{"privatekey", []string{"private", "key"}},
	{"servicekey", []string{"service", "key"}},
	{"authtoken", []string{"auth", "token"}},
	{"accesskey", []string{"access", "key"}},
	{"secretkey", []string{"secret", "key"}},
	{"masterkey", []string{"master", "key"}},
	{"apisecret", []string{"api", "secret"}},
	{"appsecret", []string{"app", "secret"}},
	{"apitoken", []string{"api", "token"}},
	{"adminkey", []string{"admin", "key"}},
	{"password", []string{"password"}},
	{"apikey", []string{"api", "key"}},
	{"passwd", []string{"passwd"}},
	{"secret", []string{"secret"}},
}

// knownVendors are service names that run together with a head
// (MAILCHIMPKEY, SUPABASEKEY) besides the server vendors.
var knownVendors = set("mailchimp", "supabase", "algolia", "vercel", "netlify", "heroku", "cloudflare", "datadog",
	"npm", "pypi", "docker", "sentry", "okta", "auth0", "firebase", "azure", "gcp", "google", "postmark", "resend",
	"paypal", "plaid", "square", "linear", "notion", "airtable", "hubspot", "zendesk", "jira", "atlassian")

func splitKnown(rest string) []string {
	var parts []string
	for rest != "" {
		matched := false
		for _, k := range []string{"apikey", "api", "key", "id", "app", "token", "write", "client", "site", "sdk", "project", "access"} {
			if strings.HasPrefix(rest, k) {
				if k == "apikey" {
					parts = append(parts, "api", "key")
				} else {
					parts = append(parts, k)
				}
				rest, matched = rest[len(k):], true
				break
			}
		}
		if !matched {
			return nil
		}
	}
	return parts
}

func clientKey(words []string) (string, bool) {
	for _, w := range words {
		ck, ok := clientKeys[w]
		if !ok {
			continue
		}
		needOK := ck.need == nil
		for _, o := range words {
			if o == w {
				continue
			}
			if !ck.allow[o] {
				return "", false
			}
			if ck.need[o] {
				needOK = true
			}
		}
		return w, needOK
	}
	return "", false
}

var (
	envName      = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	allCaps      = regexp.MustCompile(`^[A-Z][A-Z0-9]{5,}$`)
	identifierRe = regexp.MustCompile(`^[A-Za-z][A-Za-z_\-.:/]*$`)
	caseShape    = regexp.MustCompile(`^(?:[a-z]+(?:[A-Z][a-z]+)*|[A-Z][a-z]+(?:[A-Z][a-z]+)*|[A-Z]+)[0-9]*$`)
	wordPath     = regexp.MustCompile(`^(?:[a-z]+[0-9]{0,2}|v?[0-9]{1,2})$`)
	hexRe        = regexp.MustCompile(`^[0-9a-f]+$`)
	// Datadog browser client tokens: pub + 32 hex.
	datadogClient = regexp.MustCompile(`^pub[0-9a-f]{32}$`)
)

// credentialName splits a name into words and checks it names a credential:
// a head word (secret, password, token, a qualified key...) followed only by
// qualifiers. It returns the words with any public-env prefix removed, and
// the prefix.
func credentialName(name string) (words []string, prefix string, ok bool) {
	bare := strings.Trim(name, "_$- ")
	upper := strings.ToUpper(bare)
	for _, p := range publicEnvPrefixes {
		if strings.HasPrefix(upper, p) && len(upper) > len(p) {
			prefix = p
			bare = bare[len(p):]
			break
		}
	}
	for _, w := range nameWords(bare) {
		words = append(words, splitWord(w)...)
	}
	for i := 0; i+1 < len(words); i++ {
		switch {
		case words[i] == "master" && words[i+1] == "card":
			// MasterCard is a card brand, not a master key.
			words[i], words[i+1] = "mastercard", "brand"
		case words[i] == "pass" && words[i+1] == "through":
			// passThrough is a mode, not a password.
			words[i], words[i+1] = "passthrough", "mode"
		case words[i] == "service" && words[i+1] == "worker":
			// A service worker is a browser script, not a service account.
			words[i], words[i+1] = "serviceworker", "worker"
		case words[i] == "pass" && words[i+1] == "key":
			// passKey is a WebAuthn passkey, not a credential value.
			return nil, "", false
		}
	}
	if l := strings.ToLower(bare); strings.Contains(l, "i18n") || strings.Contains(l, "l10n") {
		return nil, "", false
	}
	// A secret word decides the name wherever it sits, unless the words
	// after it say the name is about the secret (passwordPolicy). Even then
	// a later key or token can still name a credential
	// (PASSWORD_RESET_HMAC_KEY, SECRET_MANAGER_TOKEN), so fall through.
strict:
	for i := len(words) - 1; i >= 0; i-- {
		if !anywhereWords[words[i]] && (words[i] != "key" || i == 0 || words[i-1] != "private") {
			continue
		}
		if i > 0 && verbWords[words[i-1]] {
			// showPassword, toggleSecret: UI state about the field, unless a
			// key or token follows (FORGOT_PASSWORD_JWT_KEY).
			for _, w := range words[i+1:] {
				if w == "key" || w == "token" {
					break strict
				}
			}
			return nil, "", false
		}
		for _, w := range words[i+1:] {
			if metaWords[w] {
				break strict
			}
		}
		return words, prefix, true
	}
	h := -1
	for i, w := range words {
		if heads[w] {
			h = i
		}
	}
	if h < 0 {
		return nil, "", false
	}
	for _, w := range words[h+1:] {
		if !nameSuffixes[w] && !versionWord.MatchString(w) {
			return nil, "", false
		}
	}
	// When a suffix word is itself a head (SECRET_KEY_BASE: key), judge the
	// first head of the trailing run.
	for h > 0 && heads[words[h-1]] {
		h--
	}
	pre := words[:h]
	in := func(m map[string]bool, ws []string) bool {
		for _, w := range ws {
			if m[w] {
				return true
			}
		}
		return false
	}
	switch words[h] {
	case "key":
		// passKey is a WebAuthn passkey; cacheKey and sortKey are not credentials.
		if len(pre) > 0 && pre[len(pre)-1] == "pass" {
			return nil, "", false
		}
		_, vendor := clientKey(words)
		if _, isVendor := clientKeys[firstVendor(words)]; !in(keyQualifiers, pre) && !in(strictWords, pre) &&
			!in(serverVendors, pre) && !in(publicWords, pre) && !vendor && !isVendor {
			return nil, "", false
		}
	case "token":
		// nextPageToken and pushToken name UI or device state; a token
		// for an account or a service (PAGE_ACCESS_TOKEN,
		// RUNNER_REGISTRATION_TOKEN) is still a credential.
		if n := len(pre); n > 0 && tokenNoise[pre[n-1]] && (n < 2 || !hardWords[pre[n-2]] && !accessWords[pre[n-2]]) {
			return nil, "", false
		}
	case "pat":
		// A personal access token: GITHUB_PAT, GITLAB_PAT.
		if len(pre) == 0 || !serverVendors[pre[len(pre)-1]] && !knownVendors[pre[len(pre)-1]] {
			return nil, "", false
		}
	}
	return words, prefix, true
}

func firstVendor(words []string) string {
	for _, w := range words {
		if _, ok := clientKeys[w]; ok {
			return w
		}
	}
	return ""
}

// gradeGeneric decides whether a name = "value" assignment is a credential
// and how much it matters. The value must look random (not an identifier,
// path, selector or template); the name's words decide the severity.
func gradeGeneric(name, val string) (model.Severity, string, bool) {
	ok, demote := valueCheck(name, val)
	if !ok {
		// The randomness checks reject dictionary passphrases and long
		// digit strings, but under a password or secret name they are
		// still real secrets.
		if note := plainSecret(name, val); note != "" {
			if _, _, named := credentialName(name); named {
				return model.Low, note, true
			}
		}
		return "", "", false
	}
	words, prefix, ok := credentialName(name)
	if !ok {
		return "", "", false
	}
	sev, note, ok := gradeWords(name, val, words, prefix)
	if ok && demote != "" && sev.Rank() < model.Low.Rank() {
		return model.Low, demote, true
	}
	return sev, note, ok
}

func gradeWords(name, val string, words []string, prefix string) (model.Severity, string, bool) {
	has := func(m map[string]bool) bool {
		for _, w := range words {
			if m[w] {
				return true
			}
		}
		return false
	}
	bare := strings.Trim(name, "_$- ")
	envLike := envName.MatchString(bare) || allCaps.MatchString(bare)
	switch {
	case has(strictWords) && !has(publicWords):
		if prefix != "" {
			return model.Medium, prefix + " exposes this to every visitor by design; a secret should never carry it", true
		}
		return model.Medium, "", true
	case has(sessionWord):
		// csrfToken, nonce: per-session values, not credentials.
		return "", "", false
	case has(set("license")) && !has(set("relic", "newrelic")):
		return model.Low, "a licence key for a UI library; these ship in the bundle by design", true
	case has(set("storefront")):
		return model.Info, "Shopify Storefront API token: public by design (an Admin API token, shpat_, is not)", true
	case has(publicWords) || strings.Join(words, "") == "applicationserverkey":
		return model.Info, "named as public (a public key or client token)", true
	case hasAnyPrefix(val, "sdk-", "client-", "public-") || datadogClient.MatchString(val):
		return model.Info, "client-side key format; " + notePublic, true
	}
	if v, ok := clientKey(words); ok {
		return model.Info, v + " browser SDK key; " + notePublic, true
	}
	switch {
	case has(hardWords):
		return model.Medium, "", true
	case firstVendor(words) == "algolia" && !has(softWords):
		return model.Low, "Algolia search and admin keys share one format; check this one is search-only", true
	case prefix != "":
		return model.Low, prefix + " variables are shipped to the browser on purpose; check it is meant to be public", true
	case has(softWords) && envLike:
		return model.Medium, "build-time environment variable inlined into the bundle", true
	case has(serverVendors):
		return model.Medium, "credential for a server-side service", true
	case envLike:
		return model.Medium, "build-time environment variable inlined into the bundle", true
	case hexRe.MatchString(val) && len(val) == 32:
		return model.Low, "32-hex client key; often public (Algolia search, analytics write keys)", true
	}
	return model.Low, "", true
}

func hasAnyPrefix(s string, ps ...string) bool {
	for _, p := range ps {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// genericPlaceholder matches filler words standing on their own
// (your-api-key, YOUR_TOKEN, xxxx) but not inside random text (x9Yourq7...).
// A plain substring test throws away roughly one random value in a few
// hundred.
var genericPlaceholder = regexp.MustCompile(`(?i)(?:^|[^a-z])(?:your|todo|xxxx|test|sample|demo)(?:[^a-z]|$)|example|placeholder|changeme|dummy|redacted|insert|replace|<`)

// valueCheck decides whether a value can be a credential. It returns a
// note when the value is kept but should be reported at LOW: a common weak
// password (Welcome2024!), or a value with a placeholder word next to
// something that is not filler. A weak real password is still a finding.
func valueCheck(name, val string) (bool, string) {
	if !genericValueOK(name, val) {
		return false, ""
	}
	if genericPlaceholder.MatchString(val) {
		if hardPlaceholder.MatchString(val) || fillerOnly(val) {
			return false, ""
		}
		return true, "contains a placeholder word (example, dummy, test...); may be sample data"
	}
	if stockPasswords[strings.ToLower(val)] {
		// The bare default itself (mysecretpassword): documentation.
		return false, ""
	}
	if weakPassword(val) {
		return true, "a common weak password: guessable if it is real, or a demo value"
	}
	return true, ""
}

// hardPlaceholder marks values that are never real: <your-key> and
// [REDACTED].
var hardPlaceholder = regexp.MustCompile(`(?i)<|redacted`)

// fillerOnly reports whether a value is nothing but placeholder words,
// separators and digits: your-api-key-here, example123, insert_token_here.
func fillerOnly(v string) bool {
	l := lettersOnly(v)
	for _, w := range fillerWords {
		l = strings.ReplaceAll(l, w, "")
	}
	return len(l) < 4
}

var fillerWords = []string{"placeholder", "password", "generated", "changeme", "example", "replace", "testing", "actual",
	"secret", "sample", "insert", "string", "random", "client", "access", "public", "private", "change", "dummy", "token",
	"value", "enter", "goes", "here", "your", "todo", "test", "demo", "with", "real", "fake", "mock", "this", "pass",
	"live", "prod", "auth", "key", "api", "app", "the", "own", "put", "foo", "bar", "baz", "abc", "xyz", "pwd", "my",
	"our", "me", "id", "to", "an", "a", "x"}

func genericValueOK(name, val string) bool {
	if hasLongRun(val, 8) || sequential(val) || docExamples[val] {
		return false
	}
	// Subresource-integrity and CSP hashes, and regular expressions.
	if hasAnyPrefix(val, "sha256-", "sha384-", "sha512-", "(?") || regexLike(val) || strings.Contains(val, "(?=") || strings.Contains(val, ".{") {
		return false
	}
	// A value that is only its own name is a label, not a leak.
	for _, w := range nameWords(name) {
		// P@ssw0rd2024! is a weak password, not a label: valueCheck
		// reports it.
		if len(w) >= 4 && lettersOnly(val) == w && !weakPassword(val) {
			return false
		}
	}
	if strings.ContainsAny(val[:1], "[.#:(") && selectorLike.MatchString(val) || strings.Contains(val, "=>") || strings.Contains(val, "()") {
		// CSS selectors and code, e.g. password:"[type=password]"
		return false
	}
	b64 := base64Secret(val)
	if strings.Contains(val, "://") || strings.HasPrefix(val, "/") && !b64 || strings.HasPrefix(val, `\/`) ||
		strings.Contains(val, "${") || strings.Contains(val, "{{") || strings.Contains(val, "%s") {
		return false
	}
	if identifierRe.MatchString(val) && wordLike(val) {
		return false
	}
	if codeLike(val) && !b64 {
		return false
	}
	// %filtered%, [REDACTED], **secret**: a word in punctuation is a
	// placeholder the SDK writes, not a value.
	if letters := strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf && isAlnum(byte(r)) {
			return r
		}
		return -1
	}, val); letters != "" && !strings.ContainsAny(letters, "0123456789") && wordLike(letters) {
		return false
	}
	// Kebab, snake and path-shaped words: www-account-pages/login-methods-v2-password
	parts := strings.FieldsFunc(val, func(r rune) bool { return strings.ContainsRune("-_/.:", r) })
	if len(parts) >= 2 {
		wordy := true
		for _, p := range parts {
			if !wordPath.MatchString(p) {
				wordy = false
				break
			}
		}
		if wordy {
			return false
		}
	}
	// A value that repeats its own name's words is a label, not a secret.
	lv := strings.ToLower(val)
	shared := 0
	rest := lv
	for _, w := range nameWords(name) {
		if len(w) >= 4 && strings.Contains(lv, w) {
			shared++
			rest = strings.ReplaceAll(rest, w, "")
		}
	}
	if shared >= 2 || shared == 1 && identifierRe.MatchString(val) && (len(rest) <= 6 || wordLike(labelRest(val, rest))) {
		// SPOPassword:"SPOPassword" is an enum, not a credential; random
		// letters that happen to contain the word are not.
		return false
	}
	if strings.Count(val, ".") >= 2 && !strings.ContainsAny(val, "!#$%&*+=@^~") && classes(strings.ReplaceAll(val, ".", "")) < 3 {
		// dotted.i18n.keys, hostnames and version strings
		return false
	}
	// Short hex is a colour, a hash prefix or an ID; 16 hex is 64 bits, the
	// least a key needs.
	if hexRe.MatchString(strings.ToLower(val)) && len(val) < 16 {
		return false
	}
	letters := 0
	for i := 0; i < len(val); i++ {
		if c := val[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			letters++
		}
	}
	if letters == 0 {
		return false
	}
	// At least 2 bits per character and 55% of what the value's alphabet
	// allows, so hex and base64 are judged on the same scale.
	k := alphabetSize(val)
	if k > len(val) {
		k = len(val)
	}
	return shannonEntropy(val) >= math.Max(2.0, 0.55*math.Log2(float64(k)))
}

// labelRest returns val with the shared name word removed, keeping val's
// case so wordLike can read its camelCase parts.
func labelRest(val, restLower string) string {
	lv := strings.ToLower(val)
	var b strings.Builder
	for i, j := 0, 0; i < len(val) && j <= len(restLower); i++ {
		if j < len(restLower) && lv[i] == restLower[j] {
			b.WriteByte(val[i])
			j++
		}
	}
	return b.String()
}

var pathWord = regexp.MustCompile(`^(?:[a-z]{3,}|[A-Z][a-z]{2,})(?:[-_][a-z]+)*$`)

// base64Secret spots a base64 secret that happens to start with / or + or
// end with + (an AWS secret access key does about 1 time in 20): 40 or
// more characters of the base64 alphabet with all three character classes
// and no path-like run of words.
func base64Secret(v string) bool {
	if len(v) < 40 || strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != "" || classes(v) < 3 {
		return false
	}
	for _, part := range strings.Split(v, "/") {
		if pathWord.MatchString(part) {
			return false
		}
	}
	return true
}

// selectorLike matches CSS selectors and call fragments
// ([type=password], #password-input, .field:focus) but not a password that
// happens to start with # or [.
var selectorLike = regexp.MustCompile(`^(?:[#.:][a-z][a-z0-9_-]*|\[[a-z][^\]]*\]|\()(?:[#.:][a-z][a-z0-9_-]*|\[[^\]]*\]|[ >~+*,()"'=])*$`)

// regexLike reports whether a value starting with ^ is a regular expression
// rather than a password: it ends with $ or holds a class, escape or group.
func regexLike(v string) bool {
	return strings.HasPrefix(v, "^") && (strings.HasSuffix(v, "$") || strings.ContainsAny(v, "[\\("))
}

// plainSecret returns a note for a value that is only worth reporting under
// a password or secret name: words joined by - _ or .
// (correct-horse-battery-staple), or twelve or more digits that are not a
// run or a repeat. It returns "" for anything else.
func plainSecret(name, val string) string {
	strict := false
	for _, w := range nameWords(name) {
		if anywhereWords[w] {
			strict = true
		}
	}
	if !strict || sequential(val) || hasLongRun(val, 6) || genericPlaceholder.MatchString(val) {
		return ""
	}
	if len(val) >= 12 && strings.Trim(val, "0123456789") == "" {
		distinct := map[rune]bool{}
		for _, r := range val {
			distinct[r] = true
		}
		if len(distinct) >= 6 && !digitRun(val, 6) {
			return "only digits; if this is a real secret it is a weak one"
		}
		return ""
	}
	parts := strings.FieldsFunc(val, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	if len(parts) < 3 || len(val) < 15 || strings.Count(val, ".") >= 2 {
		// a.b.c is an i18n key or a hostname, not a passphrase.
		return ""
	}
	seen := map[string]bool{}
	for _, p := range parts {
		if len(p) < 3 || len(p) > 12 || strings.Trim(p, "abcdefghijklmnopqrstuvwxyz") != "" || uiWords[p] || seen[p] {
			return ""
		}
		seen[p] = true
	}
	for _, w := range nameWords(name) {
		if seen[w] {
			return ""
		}
	}
	return "a passphrase of dictionary words; real, but guessable"
}

// digitRun reports n digits counting up or down (123456, 987654).
func digitRun(s string, n int) bool {
	for _, step := range []int{1, -1} {
		run := 1
		for i := 1; i < len(s); i++ {
			if int(s[i])-int(s[i-1]) == step {
				run++
				if run >= n {
					return true
				}
			} else {
				run = 1
			}
		}
	}
	return false
}

// uiWords are the vocabulary of password fields, CSS classes and labels; a
// "passphrase" built from them (password-input-field) is UI text.
var uiWords = set("password", "passwd", "passphrase", "pass", "secret", "new", "old", "current", "confirm", "confirmation",
	"input", "field", "label", "hint", "placeholder", "reset", "forgot", "show", "hide", "toggle", "error", "required",
	"invalid", "valid", "your", "here", "enter", "form", "login", "logout", "user", "username", "email", "value", "min", "max",
	"length", "auth", "page", "modal", "dialog", "button", "btn", "icon", "text", "title", "help", "strength", "meter",
	"weak", "strong", "medium", "change", "update", "submit", "cancel", "save", "token", "key", "api", "test", "demo",
	"example", "sample", "default", "admin", "root", "guest", "container", "wrapper", "visible", "hidden", "disabled")

// codeLike catches a quoted fragment of code captured as a value, as in
// token="+encodeURIComponent(r)+" or ').concat(n,'.
func codeLike(v string) bool {
	if strings.ContainsAny(v[:1], "+,;)]}") || strings.ContainsAny(v[len(v)-1:], "+,;([{") {
		return true
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if strings.IndexByte("(){}[];,", v[i]) >= 0 {
			n++
		}
	}
	return n >= 2 || strings.Contains(v, "||") || strings.Contains(v, "&&") || strings.Contains(v, "==")
}

// wordLike tells an identifier made of words (updatePesAuthToken,
// login-methods) from random letters (PywhDauBuftx): every camelCase or
// separated part of a word has three or more letters and a vowel.
func wordLike(s string) bool {
	// Identifiers have regular case: each separated piece is camelCase,
	// PascalCase or ALL CAPS. Random letters (YKpiXMCBSEOL) do not.
	for _, piece := range strings.FieldsFunc(s, func(r rune) bool { return !(r < utf8.RuneSelf && isAlnum(byte(r))) }) {
		if !caseShape.MatchString(piece) {
			return false
		}
	}
	parts := nameWords(s)
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		if len(p) < 3 || !strings.ContainsAny(p, "aeiou") {
			return false
		}
	}
	return true
}

// offsets maps a position in a decoded view back to the original text. It
// keeps one entry per change, not one per byte: a per-byte table of 8-byte
// offsets would cost 200 MB for a 25 MB bundle.
type offsets []struct{ dec, orig int32 }

func (o offsets) original(d int) int {
	i := sort.Search(len(o), func(i int) bool { return int(o[i].dec) > d }) - 1
	if i < 0 {
		return d
	}
	return int(o[i].orig) + d - int(o[i].dec)
}

// decodeEscapes builds a view of the code with two disguises undone: \xHH,
// \uHHHH and \u{H} escapes that stand for plain ASCII letters, digits and
// _ - . + / (a minifier never writes those on its own), and string literals
// split with + ("sk_live_" + "..."). It returns "" when there is nothing to
// undo, and otherwise the view, the offset map, and the view offsets where
// something was undone.
func decodeEscapes(text string) (string, offsets, []int) {
	if !strings.Contains(text, `\x`) && !strings.Contains(text, `\u`) && !strings.Contains(text, "+") {
		return "", nil, nil
	}
	var b strings.Builder
	var offs offsets
	var changes []int
	mark := func(orig int) { offs = append(offs, struct{ dec, orig int32 }{int32(b.Len()), int32(orig)}) }
	for i := 0; i < len(text); {
		if q := text[i]; q == '"' || q == '\'' {
			if n := concatLen(text[i:], q); n > 0 {
				// "abc" + "def": drop the closing quote, the plus and the
				// opening quote so the halves join.
				i += n
				changes = append(changes, b.Len())
				mark(i)
				continue
			}
		}
		if text[i] == '\\' && i+1 < len(text) {
			if r, n := escapeAt(text[i:]); n > 0 && r < utf8.RuneSelf && plainASCII(byte(r)) {
				changes = append(changes, b.Len())
				mark(i)
				b.WriteByte(byte(r))
				i += n
				mark(i)
				continue
			}
			// Keep any other escape as-is so the text stays aligned.
			b.WriteByte(text[i])
			b.WriteByte(text[i+1])
			i += 2
			continue
		}
		b.WriteByte(text[i])
		i++
	}
	if len(changes) == 0 {
		return "", nil, nil
	}
	return b.String(), offs, changes
}

// concatLen returns the length of `" + "` (or `' + "`) at the start of s,
// or 0.
func concatLen(s string, q byte) int {
	i := 1
	for i < len(s) && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t') {
		i++
	}
	if i >= len(s) || s[i] != '+' {
		return 0
	}
	i++
	for i < len(s) && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t') {
		i++
	}
	if i < len(s) && (s[i] == '"' || s[i] == '\'') {
		return i + 1
	}
	return 0
}

func escapeAt(s string) (rune, int) {
	switch {
	case len(s) >= 4 && s[1] == 'x':
		if v, err := strconv.ParseUint(s[2:4], 16, 8); err == nil {
			return rune(v), 4
		}
	case len(s) >= 6 && s[1] == 'u' && s[2] != '{':
		if v, err := strconv.ParseUint(s[2:6], 16, 16); err == nil {
			return rune(v), 6
		}
	case len(s) >= 4 && s[1] == 'u' && s[2] == '{':
		if end := strings.IndexByte(s, '}'); end > 3 && end <= 10 {
			if v, err := strconv.ParseUint(s[3:end], 16, 32); err == nil {
				return rune(v), end + 1
			}
		}
	}
	return 0, 0
}

func plainASCII(c byte) bool {
	return isAlnum(c) || strings.IndexByte("_-.+/=", c) >= 0
}

// docExamples are values that vendors publish in their own documentation and
// SDKs: they ship in real bundles and grant nothing.
var docExamples = map[string]bool{
	// Azurite storage emulator account key (in @azure/storage-blob).
	"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==": true,
	// Google reCAPTCHA v2 test secret and site key.
	"6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe": true,
	"6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI": true,
}

// sequential spots demo filler such as 1234567890abcdef or abcdefghij...:
// ten characters in a row that each follow the previous one. Eight turned
// up by chance in about one random token in 200,000.
func sequential(s string) bool {
	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1]+1 {
			run++
			if run >= 10 {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

var stockPasswords = set("password", "passw", "pass", "secret", "mysecretpassword", "yourstrongpassword", "randompassword",
	"mypassword", "redispw", "example", "guest", "changeme", "admin", "root", "postgres", "mysql", "user", "test",
	"letmein", "qwerty", "welcome", "default", "pwd", "passwd", "toor", "foobar", "mongo", "rabbitmq")

func weakPassword(v string) bool {
	for _, l := range []string{lettersOnly(v), lettersOnly(deLeet(v)), lettersOnly(deLeet(trimTail(v)))} {
		if stockPasswords[l] || strings.HasPrefix(l, "your") && strings.Contains(l, "pass") {
			return true
		}
	}
	return false
}

// trimTail drops the digits and symbols people append to a word
// (Password1!, P@ssw0rd123) so the word itself can be compared.
func trimTail(v string) string {
	return strings.TrimRight(strings.ToLower(v), "0123456789!@#$%^&*.?_-")
}

// deLeet undoes the usual digit-for-letter swaps so p4ssw0rd reads password.
func deLeet(v string) string {
	return strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s").Replace(strings.ToLower(v))
}

func lettersOnly(v string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r
		}
		return -1
	}, strings.ToLower(v))
}
