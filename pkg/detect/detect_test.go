package detect

import (
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/NotChaosuu/bundlexray/pkg/model"
)

// Fixtures are assembled at runtime from a seeded generator so no
// credential-shaped literal sits in the source for secret scanners to flag.
var gen = rand.New(rand.NewSource(1))

func randFrom(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[gen.Intn(len(set))]
	}
	return string(b)
}

const (
	alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b32   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	hex   = "0123456789abcdef"
	b64u  = alnum + "_-"
)

func mixed(n int) string {
	for {
		v := randFrom(alnum, n)
		if classes(v) == 3 {
			return v
		}
	}
}

var (
	fakeAWS     = "AK" + "IA" + randFrom(b32, 16)
	fakeGoogle  = "AI" + "za" + randFrom(b64u, 35)
	fakeStripe  = "sk_" + "live_" + mixed(40)
	fakeStripPK = "pk_" + "live_" + mixed(40)
	fakeGitHub  = "gh" + "p_" + mixed(36)
	fakeSlack   = "xo" + "xb-" + randFrom("0123456789", 12) + "-" + randFrom("0123456789", 13) + "-" + mixed(24)
	fakeAnthro  = "sk-" + "ant-api03-" + randFrom(b64u, 93) + "AA"
	fakeOpenAI  = "sk-" + "proj-" + randFrom(b64u, 74) + "T3Blbk" + "FJ" + randFrom(b64u, 74)
	pemBody     = randFrom(alnum+"+/", 640)
	privateKey  = "-----BEGIN RSA PRIVATE KEY-----\\n" + pemBody + "\\n-----END RSA PRIVATE KEY-----"
)

func types(secrets []model.Secret) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, s := range secrets {
		m[s.Type] = s.Severity
	}
	return m
}

func one(t *testing.T, js string) []model.Secret {
	t.Helper()
	return Secrets("x.js", []byte(js))
}

func TestSecretRulesDetectKnownKeys(t *testing.T) {
	js := "var a='" + fakeAWS + "';var s='" + fakeStripe + "';var h='" + fakeGitHub +
		"';var k='" + fakeSlack + "';var p=`" + privateKey + "`;var o='" + fakeOpenAI + "';"
	got := types(one(t, js))
	want := map[string]model.Severity{
		"AWS Access Key":    model.High,
		"Stripe Secret Key": model.High,
		"GitHub Token":      model.High,
		"Slack Token":       model.High,
		"Private Key":       model.High,
		"OpenAI API Key":    model.High,
	}
	for typ, sev := range want {
		if got[typ] != sev {
			t.Errorf("missing/wrong %q: got %v want %v (all: %v)", typ, got[typ], sev, got)
		}
	}
}

func TestOverlappingKeyDedupedToMostSpecific(t *testing.T) {
	secrets := one(t, `const key = "`+fakeAnthro+`"`)
	if len(secrets) != 1 || secrets[0].Type != "Anthropic API Key" {
		t.Fatalf("sk-ant- key should report once, as Anthropic: %+v", secrets)
	}
}

// Prefixes must start a token. These come from production bundles: Tailwind
// mask utilities, BEM class names, base64-encoded WASM.
func TestPrefixesNeedTokenBoundary(t *testing.T) {
	for _, js := range []string{
		`{"mask-image-linear-from-pos":[{"mask-linear-from":q()}]}`,
		`{"mask-image-radial-from-color":1}`,
		`mix:"ask-ai-button__promo-onboarding"`,
		`"feature-title-disk-public-links-orgs-restrictions"`,
		`"unlock-key-` + randFrom(hex, 32) + `"`,
		`"my-sk-proj-` + mixed(48) + `"`,
		`"AgAoAmQRAAALAkAgAUGAAnFFDQAgACAAKgJEO` + "AK" + "IA" + `SAAKAKMASIBRQ0AIAAgASABKAIAKAJMEQkA"`,
		`"FDQBBACEMIAFBADYCiAEgBUHgAGohBiABQeAAaiEIA0AgDCAFKAKIAU8NASABKAKIASILQQRLDQEgBiAMQQJ0aig"`,
	} {
		if hit := one(t, js); len(hit) != 0 {
			t.Errorf("mid-token match must not be reported: %s\n  got %+v", js, hit)
		}
	}
}

// The boundary check must still accept a key after an escape sequence, a
// percent-escape or an escaped quote.
func TestBoundaryAcceptsEscapes(t *testing.T) {
	for _, js := range []string{
		`var m="hdr\n` + fakeAWS + `\nend"`,
		`fetch("https://s3.example.com/o?X-Amz-Credential%3D` + fakeAWS + `%2F2026")`,
		`var s='{\"k\":\"` + fakeAWS + `\"}'`,
	} {
		if got := types(one(t, js)); got["AWS Access Key"] != model.High {
			t.Errorf("key after an escape not found: %s -> %v", js, got)
		}
	}
}

// Keys that are meant to be in a front end are informational, never a CI
// failure.
func TestPublicByDesignKeysAreInfo(t *testing.T) {
	anon := jwt(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","exp":4102444800}`)
	js := `a("` + fakeGoogle + `");b("` + fakeStripPK + `");c("` + anon + `");d("pk.eyJ1IjoiYWNtZSIsImEiOiJ` + mixed(20) + `.` + randFrom(b64u, 22) + `")`
	for _, s := range one(t, js) {
		if s.Severity != model.Info {
			t.Errorf("%s should be info, got %s", s.Type, s.Severity)
		}
	}
	if n := len(one(t, js)); n != 4 {
		t.Errorf("want 4 informational findings, got %d", n)
	}
}

// An env-style name inlined at build time is the classic real leak; it must
// trip the CI gate.
func TestInlinedEnvSecretIsMedium(t *testing.T) {
	val := "!2#Aou" + mixed(14) + "j&"
	got := one(t, `{ADS:"https://x.example/gpt.js",HUBVISOR_LEO_API_KEY:"`+val+`"}`)
	if len(got) != 1 || got[0].Severity != model.Medium || got[0].Value != val {
		t.Fatalf("env-style secret should be medium: %+v", got)
	}
	got = one(t, `var s='{\"clientSecret\":\"`+mixed(40)+`\"}'`)
	if len(got) != 1 || got[0].Severity != model.Medium {
		t.Errorf("clientSecret in escaped JSON should be medium: %+v", got)
	}
}

func TestGenericRuleSkipsIdentifiersAndPlaceholders(t *testing.T) {
	for _, js := range []string{
		`const apiKey = "your-api-key-here-xx"`,
		`const apiKey = "aaaaaaaaaaaaaaaaaaaa"`,
		`const secret = "example-token-value1"`,
		`UPDATE_AUTH_TOKEN:"updatePesAuthToken"`,
		`RESET_PASSWORD:"auth.reset_password.title"`,
		`password:"[type=password]"`,
		`apiKey:"https://api.example.com/v1/key"`,
		`apiKey:"${process.env.KEY}abcdef"`,
	} {
		if hit := one(t, js); len(hit) != 0 {
			t.Errorf("must not flag %s: %+v", js, hit)
		}
	}
}

func TestClientSDKKeysAreInfo(t *testing.T) {
	got := one(t, `amplitudeApiKey = '`+randFrom(hex, 32)+`'`)
	if len(got) != 1 || got[0].Severity != model.Info {
		t.Errorf("analytics SDK key should be info: %+v", got)
	}
}

// A PEM header constant (crypto libraries ship them) is not a key.
func TestPrivateKeyNeedsKeyMaterial(t *testing.T) {
	for _, js := range []string{
		`vUeAp:"-----BEGIN PRIVATE KEY-----",RIghY:"-----END PRIVATE KEY-----"`,
		`var e="-----BEGIN RSA PRIVATE KEY-----\n",t="3082025e02010002";return e+t`,
	} {
		if hit := one(t, js); len(hit) != 0 {
			t.Errorf("bare PEM header must not flag: %s -> %+v", js, hit)
		}
	}
}

func TestAWSDocumentationKeyIgnored(t *testing.T) {
	if hit := one(t, `var k="`+"AKIA"+"IOSFODNN7EXAMPLE"+`"`); len(hit) != 0 {
		t.Errorf("AWS documentation example key must not flag: %+v", hit)
	}
}

func jwt(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." + randFrom(b64u, 43)
}

func TestJWTGrading(t *testing.T) {
	cases := []struct {
		payload string
		want    model.Severity
	}{
		{`{"iss":"supabase","role":"service_role","exp":4102444800}`, model.High},
		{`{"sub":"123","exp":946684800}`, model.Info},
		{`{"sub":"123","exp":4102444800}`, model.Low},
	}
	for _, c := range cases {
		got := one(t, `t="`+jwt(c.payload)+`"`)
		if len(got) != 1 || got[0].Severity != c.want {
			t.Errorf("%s: want %s, got %+v", c.payload, c.want, got)
		}
	}
	// eyJ...eyJ... that does not decode to JSON is not a JWT.
	if got := one(t, `t="eyJ`+mixed(20)+`.eyJ`+mixed(20)+`.`+mixed(20)+`"`); len(got) != 0 {
		t.Errorf("undecodable token must not flag: %+v", got)
	}
}

func TestSecretRepeatedInFileReportedOnce(t *testing.T) {
	js := strings.Repeat(`x("`+fakeGitHub+`");`, 5)
	if got := one(t, js); len(got) != 1 {
		t.Errorf("want one finding for a repeated value, got %d", len(got))
	}
}

func TestSecretLineAndColumn(t *testing.T) {
	js := "line1\nline2\nvar k='" + fakeGitHub + "'\nline4"
	hit := one(t, js)
	if len(hit) != 1 || hit[0].Line != 3 || hit[0].Column != 8 {
		t.Errorf("position wrong: %+v", hit)
	}
}

// Overlap checks and line lookups must stay linear in the match count.
func TestManyMatchesScaleLinearly(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40000; i++ {
		b.WriteString(`t="` + jwt(`{"sub":"`+randFrom(alnum, 8)+`","exp":4102444800}`) + "\"\n")
	}
	start := time.Now()
	got := Secrets("x.js", []byte(b.String()))
	if len(got) != 40000 {
		t.Fatalf("want 40000 findings, got %d", len(got))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("40000 matches took %s", d)
	}
}

func cats(eps []model.Endpoint) map[string]string {
	m := map[string]string{}
	for _, e := range eps {
		m[e.Value] = e.Category
	}
	return m
}

func TestEndpointExtractionAndClassification(t *testing.T) {
	js := `fetch("/api/v2/users");post("/auth/login");go("https://api.example.com/graphql");` +
		`x("/admin/settings");img("/static/logo.png");normal("/blog/post/hello");ws("wss://rt.example.com/socket")`
	got := cats(Endpoints("app.js", []byte(js)))
	checks := map[string]string{
		"/api/v2/users":                   "api",
		"/auth/login":                     "auth",
		"https://api.example.com/graphql": "graphql",
		"/admin/settings":                 "admin",
		"/blog/post/hello":                "path",
		"wss://rt.example.com/socket":     "websocket",
	}
	for path, cat := range checks {
		if got[path] != cat {
			t.Errorf("endpoint %q: got category %q want %q", path, got[path], cat)
		}
	}
	if _, ok := got["/static/logo.png"]; ok {
		t.Error("asset .png should be filtered out of endpoints")
	}
}

// Category words only count as whole path segments.
func TestEndpointCategoriesMatchWholeSegments(t *testing.T) {
	js := `a("https://pagead2.googlesyndication.com/pagead/managed/dict/");` +
		`b("http://www.solidworks.com/sw/products/electrical-design/charge-up-collaboration");` +
		`c("/manage/users");d("/billing/invoices");e("https://login.thetimes.com");f("https://static.example.com/login-banner/")`
	got := cats(Endpoints("x.js", []byte(js)))
	want := map[string]string{
		"https://pagead2.googlesyndication.com/pagead/managed/dict/":                      "path",
		"http://www.solidworks.com/sw/products/electrical-design/charge-up-collaboration": "path",
		"/manage/users":                            "admin",
		"/billing/invoices":                        "payment",
		"https://login.thetimes.com":               "auth",
		"https://static.example.com/login-banner/": "path",
	}
	for v, cat := range want {
		if got[v] != cat {
			t.Errorf("%s: got %q want %q", v, got[v], cat)
		}
	}
}

func TestEndpointsDropTemplateFragments(t *testing.T) {
	js := "a(`https://manager.`);b(\"https://${host}/api\");c('https://{{domain}}/x')"
	if eps := Endpoints("x.js", []byte(js)); len(eps) != 0 {
		t.Errorf("template fragments are not endpoints: %+v", eps)
	}
}

func TestEndpointsDedupe(t *testing.T) {
	js := `a("/api/x");b("/api/x");c("/api/x")`
	if eps := Endpoints("x.js", []byte(js)); len(eps) != 1 {
		t.Errorf("duplicate endpoints should dedupe: %+v", eps)
	}
}

// Twilio auth tokens have no prefix; they are found next to their SID.
func TestTwilioPositional(t *testing.T) {
	sid, tok := "AC"+randFrom(hex, 32), randFrom(hex, 32)
	for _, js := range []string{
		`const client=require("twilio")("` + sid + `","` + tok + `");`,
		`new Twilio('` + sid + `', '` + tok + `')`,
		`fetch("https://` + sid + `:` + tok + `@api.twilio.com/2010-04-01/Accounts")`,
	} {
		ss := Secrets("x.js", []byte(js))
		found := false
		for _, s := range ss {
			if s.Type == "Twilio Auth Token" && s.Value == tok && s.Severity == model.High {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: %+v", js, ss)
		}
	}
	key, sec := "SK"+randFrom(hex, 32), randFrom(alnum, 32)
	if ss := Secrets("x.js", []byte(`twilio("`+key+`","`+sec+`",{accountSid:a})`)); len(ss) == 0 || ss[0].Type != "Twilio API Key Secret" {
		t.Errorf("api key secret: %+v", ss)
	}
	// All zeros after a real SID is a placeholder.
	if ss := Secrets("x.js", []byte(`twilio("`+sid+`","00000000000000000000000000000000")`)); len(ss) != 0 {
		t.Errorf("placeholder: %+v", ss)
	}
}
