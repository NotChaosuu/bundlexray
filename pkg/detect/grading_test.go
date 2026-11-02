package detect

import (
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"

	"github.com/NotChaosuu/bundlexray/pkg/model"
)

func gradeOf(t *testing.T, js string) model.Severity {
	t.Helper()
	best := model.Severity("")
	for _, s := range Secrets("x.js", []byte(js)) {
		if best == "" || s.Severity.Rank() < best.Rank() {
			best = s.Severity
		}
	}
	return best
}

// Secret-named values must never be demoted by a vendor or "public" word
// found somewhere inside the name.
func TestNameGrading(t *testing.T) {
	v := func() string { return mixed(32) }
	cases := map[string]model.Severity{
		"SENTRY_AUTH_TOKEN":             model.Medium,
		"POSTHOG_PERSONAL_API_KEY":      model.Medium,
		"LAUNCHDARKLY_API_KEY":          model.Medium,
		"LAUNCHDARKLY_SDK_KEY":          model.Medium,
		"ONESIGNAL_REST_API_KEY":        model.Medium,
		"BRAZE_REST_API_KEY":            model.Medium,
		"ALGOLIA_WRITE_API_KEY":         model.Medium,
		"ALGOLIA_ADMIN_API_KEY":         model.Medium,
		"ALGOLIA_ADMIN_KEY":             model.Medium,
		"INTERCOM_ACCESS_TOKEN":         model.Medium,
		"DATADOG_API_KEY":               model.Medium,
		"DATADOG_APP_KEY":               model.Medium,
		"CANONICAL_API_SECRET":          model.Medium,
		"REPUBLIC_BANK_API_KEY":         model.Medium,
		"CHEAPEST_API_KEY":              model.Medium,
		"NEXT_PUBLIC_STRIPE_SECRET_KEY": model.Medium,
		"NEXT_PUBLIC_DB_PASSWORD":       model.Medium,
		"THEAPPSECRET":                  model.Medium,
		"twilioAuthToken":               model.Medium,
		"amplitudeApiKey":               model.Info,
		"mparticleapikey":               model.Info,
		"SEGMENT_WRITE_KEY":             model.Info,
		"POSTHOG_WRITE_KEY":             model.Info,
		"AMPLITUDE_EXPORT_API_KEY":      model.Medium,
		"recaptchaSiteKey":              model.Info,
		"PUBLIC_ANALYTICS_API_KEY":      model.Low,
		"NEXT_PUBLIC_MAPS_API_KEY":      model.Low,
	}
	for name, want := range cases {
		if got := gradeOf(t, `var e={`+name+`:"`+v()+`"};`); got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

// Real false positives from production pages and bundles.
func TestGenericRejectsLabelsAndCode(t *testing.T) {
	for _, js := range []string{
		`{WWW_ACCOUNT_PAGES_LOGIN_METHODS_V2_PASSWORD:"www-account-pages/login-methods-v2-password"}`,
		`t.password&&(t.password="%filtered%")`,
		`o+="encoded_token="+encodeURIComponent(r)+"&device_position=back"`,
		`o=["publisherToken="+n.publisherId,"timeout="+i]`,
		`"?token=").concat(n,"&referrer=")`,
		`{csrfToken:"Zq3kV9xR2mT7wY1bN5cL8dF4"}`,
		`{key:"a1b2c3d4e5f6g7h8"}`,
		`var lP={SPOPassword:"SPOPassword",SitePath:"SitePath"}`,
		`{CLIENT_SECRET:"payment-flow/step2-confirm"}`,
	} {
		if got := gradeOf(t, js); got != "" {
			t.Errorf("must not flag %s (got %s)", js, got)
		}
	}
}

func TestContexts(t *testing.T) {
	tg := randFrom("0123456789", 10) + ":AA" + randFrom(b64u, 33)
	stripe := "sk_" + "live_51" + mixed(40)
	pem := "-----BEGIN PRIVATE KEY-----\\\\n" + randFrom(alnum+"+/", 640) + "\\\\n-----END PRIVATE KEY-----"
	hexStripe := `\x73k_live_51` + mixed(40)
	cases := map[string]model.Severity{
		`fetch("https://api.telegram.org/bot` + tg + `/sendMessage")`:                                                            model.High,
		`git("https://gh` + `p_` + mixed(36) + `@github.com/o/r")`:                                                               model.High,
		`fetch("/v1/` + stripe + `/charges")`:                                                                                    model.High,
		`var s=JSON.parse("{\"private_key\":\"` + pem + `\"}")`:                                                                  model.High,
		`var k="` + hexStripe + `"`:                                                                                              model.High,
		`var k="sk_` + `live_"+"51` + stripe[10:] + `"`:                                                                          model.High,
		`var c=JSON.parse(atob("` + base64.StdEncoding.EncodeToString([]byte(`{"k":"`+stripe+`"}`)) + `"))`:                      model.High,
		`{"cfg":{"CLIENT_SECRET":"ab\/` + mixed(20) + `"}}`:                                                                      model.Medium,
		`var e={API_TOKEN:"` + mixed(40) + `"}`:                                                                                  model.Medium,
		`var e={BOT_TOKEN:"` + mixed(40) + `"}`:                                                                                  model.Medium,
		`var e={DB_PASS:"` + mixed(20) + `"}`:                                                                                    model.Medium,
		`headers:{Authorization:"Bearer ` + mixed(40) + `"}`:                                                                     model.Medium,
		`apiKey:e.apiKey||"` + mixed(32) + `"`:                                                                                   model.Low,
		`var e={apiToken:"` + mixed(40) + `"}`:                                                                                   model.Low,
		`fetch("https://discord.com/api/webhooks/1187329456021837824/` + randFrom(b64u, 68) + `")`:                               model.High,
		`var s="GOCSPX-` + randFrom(b64u, 28) + `"`:                                                                              model.High,
		`var c="DefaultEndpointsProtocol=https;AccountName=a;AccountKey=` + randFrom(alnum+"+/", 86) + `==;"`:                    model.High,
		`var t="dop_v1_` + randFrom(hex, 64) + `"`:                                                                               model.High,
		`var t="PMAK-` + randFrom(hex, 24) + `-` + randFrom(hex, 34) + `"`:                                                       model.High,
		`var t="access_token$production$` + randFrom("abcdefghijklmnopqrstuvwxyz0123456789", 16) + `$` + randFrom(hex, 32) + `"`: model.High,
		`var t="sntrys_` + mixed(60) + `"`:                                                                                       model.High,
		`var t="whsec_` + mixed(32) + `"`:                                                                                        model.High,
		`var d="mongodb+srv://svc:` + mixed(16) + `@cluster0.example.net/x"`:                                                     model.High,
		`var d="postgres://app:` + mixed(16) + `@db.internal:5432/prod"`:                                                         model.High,
	}
	for js, want := range cases {
		if got := gradeOf(t, js); got != want {
			t.Errorf("got %q want %q for %s", got, want, js)
		}
	}
	if got := gradeOf(t, `var d="postgres://user:password@localhost/db"`); got != "" {
		t.Errorf("placeholder DB URL flagged: %s", got)
	}
}

// Every random token of a supported shape must be caught at full severity.
// Each value is generated fresh, so a rule that drops one token in a few
// thousand shows up here.
func TestRandomTokenRecall(t *testing.T) {
	r := rand.New(rand.NewSource(99))
	g := func(set string, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = set[r.Intn(len(set))]
		}
		return string(b)
	}
	const digits = "0123456789"
	types := []struct {
		name string
		want model.Severity
		f    func() string
	}{
		{"aws", model.High, func() string { return `var k="AK` + `IA` + g(b32, 16) + `";` }},
		{"ghp", model.High, func() string { return `var k="gh` + `p_` + g(alnum, 36) + `";` }},
		{"npm", model.High, func() string { return `var k="np` + `m_` + g(alnum, 36) + `";` }},
		{"mailgun", model.High, func() string { return `var k="ke` + `y-` + g(hex, 32) + `";` }},
		{"shopify", model.High, func() string { return `var k="shp` + `at_` + g(hex, 32) + `";` }},
		{"xoxp", model.High, func() string {
			return `var k="xo` + `xp-` + g(digits, 12) + "-" + g(digits, 12) + "-" + g(digits, 13) + "-" + g(hex, 32) + `";`
		}},
		{"xoxb", model.High, func() string {
			return `var k="xo` + `xb-` + g(digits, 12) + "-" + g(digits, 13) + "-" + g(alnum, 24) + `";`
		}},
		{"stripe", model.High, func() string { return `var k="sk_` + `live_51` + g(alnum, 97) + `";` }},
		{"telegram", model.High, func() string { return `var k="` + g(digits, 10) + ":AA" + g(b64u, 33) + `";` }},
		{"sendgrid", model.High, func() string { return `var k="S` + `G.` + g(b64u, 22) + "." + g(b64u, 43) + `";` }},
		{"gitlab", model.High, func() string { return `var k="glp` + `at-` + g(alnum+"_-", 20) + `";` }},
		{"secret 32hex", model.Medium, func() string { return `var e={CLIENT_SECRET:"` + g(hex, 32) + `"};` }},
		{"secret 20hex", model.Medium, func() string { return `var e={APP_SECRET:"` + g(hex, 20) + `"};` }},
		{"secret 16", model.Medium, func() string { return `var e={CLIENT_SECRET:"` + g(alnum, 16) + `"};` }},
		{"secret 12", model.Medium, func() string { return `var e={CLIENT_SECRET:"` + g(alnum, 12) + `"};` }},
	}
	n := 4000
	if testing.Short() {
		n = 500
	}
	for _, ty := range types {
		missed := 0
		var ex string
		for i := 0; i < n; i++ {
			js := ty.f()
			if got := gradeOf(t, js); got == "" || got.Rank() > ty.want.Rank() {
				missed++
				if ex == "" {
					ex = js
				}
			}
		}
		// Digits-only or letters-only short secrets are ambiguous with IDs
		// and labels; allow a small share of those.
		limit := 0
		if strings.HasPrefix(ty.name, "secret") {
			limit = n / 100
		}
		if missed > limit {
			t.Errorf("%s: missed %d of %d (e.g. %s)", ty.name, missed, n, ex)
		}
	}
}
