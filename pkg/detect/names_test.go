package detect

import (
	"testing"

	"github.com/NotChaosuu/bundlexray/pkg/model"
)

// The credential word can sit anywhere in a name, followed by environment,
// version and format qualifiers, or run together in one word.
func TestCredentialWordAnywhereInName(t *testing.T) {
	v := func() string { return mixed(20) }
	medium := []string{
		"JWT_SECRET_PROD", "SECRET_KEY_BASE", "API_KEY_V2", "STRIPE_SECRET_KEY_LIVE", "DB_PASSWORD_1", "password2",
		"clientSecretValue", "adminPasswordProd", "ACCESSTOKEN", "GITHUBTOKEN", "DBPASS", "HMAC_KEY",
		"RECAPTCHA_SECRET_KEY_SITE", "SECRET_TOKEN_STAGING", "dbPassword2", "apiSecretV3", "SIGNING_KEY_B64",
		"SESSION_SECRET_OLD", "smtpPassword", "ROOTPASSWORD", "privateKeyPem2", "ENCRYPTION_KEY_HEX", "BOTTOKEN",
	}
	for _, n := range medium {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got != model.Medium {
			t.Errorf("%s: got %q want medium", n, got)
		}
	}
	if got := gradeOf(t, `var c={"Secret Key":"`+v()+`"};`); got != model.Medium {
		t.Errorf(`"Secret Key": got %q want medium`, got)
	}
	for _, n := range []string{"apiKey2", `"API Key"`, "x_api_key", "appKey"} {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got != model.Low {
			t.Errorf("%s: got %q want low", n, got)
		}
	}
}

// Names that only mention a credential word, and words that contain one.
func TestNamesThatAreNotCredentials(t *testing.T) {
	v := func() string { return mixed(20) }
	for _, n := range []string{
		"passwordPolicy", "passwordMinLength", "secretary", "tokenizer", "adminEmail", "csrfToken", "cacheKey",
		"sortKey", "idToken", "pageToken", "nextPageToken", "cursorToken", "continuationToken", "resumeToken",
		"i18nToken", "designToken", "colorToken", "passKey", "passkey", "secretHash", "masterCardKey",
		"SERVICE_WORKER_TOKEN", "PASSWORD_RESET_PATH_TOKEN", "tokenCount", "secretVisible", "keyboardShortcut",
		"bypassCache", "compassHeading", "monkeyPatch", "turkeyPassport", "API_KEY_ID", "passwordStrength",
	} {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got != "" {
			t.Errorf("%s: got %q, want no finding", n, got)
		}
	}
}

// Browser SDK keys and public keys are not MEDIUM even with env-style names.
func TestClientSDKAndPublicKeyNames(t *testing.T) {
	v := func() string { return mixed(20) }
	for _, n := range []string{
		"TINYMCE_API_KEY", "BUGSNAG_API_KEY", "ROLLBAR_ACCESS_TOKEN", "CONTENTFUL_ACCESS_TOKEN", "ALGOLIA_API_KEY",
		"ADMIN_PUBLIC_KEY", "RSA_PUBLIC_KEY", "applicationServerKey", "LOGROCKET_APP_ID_KEY", "VAPID_PUBLIC_KEY",
	} {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got == model.Medium || got == model.High {
			t.Errorf("%s: got %q, want below medium", n, got)
		}
	}
	for _, c := range []struct{ name, val string }{
		{"GROWTHBOOK_CLIENT_KEY", "sdk-" + v()}, {"STATSIG_CLIENT_KEY", "client-" + v()}, {"SOME_CLIENT_KEY", "client-" + v()},
	} {
		if got := gradeOf(t, `var c={`+c.name+`:"`+c.val+`"};`); got != model.Info {
			t.Errorf("%s: got %q want info", c.name, got)
		}
	}
	// A secret word still wins over a vendor or public word.
	for _, n := range []string{"CONTENTFUL_MANAGEMENT_TOKEN", "ALGOLIA_ADMIN_KEY", "BUGSNAG_SECRET", "PUBLIC_STRIPE_SECRET"} {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got != model.Medium {
			t.Errorf("%s: got %q want medium", n, got)
		}
	}
}

// Values vendors publish (emulator keys, test keys, documentation connection
// strings, demo sequences) are not leaks.
func TestPublishedExampleValues(t *testing.T) {
	for _, js := range []string{
		`var c="DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"`,
		`var d="postgres://postgres:mysecretpassword@localhost:5432/postgres"`,
		`var d="mssql://sa:YourStrong!Passw0rd@localhost:1433"`,
		`var d="redis://default:redispw@localhost:6379"`,
		`var d="postgresql://johndoe:randompassword@localhost:5432/mydb"`,
		`var d="mysql://janedoe:mypassword@localhost:3306/mydb"`,
		`var d="redis://:p4ssw0rd@redis:6379"`,
		`var d="amqp://guest:guest@localhost:5672"`,
		`var t="whsec_1234567890abcdefghijklmnopqrstuv"`,
		`var u="https://discord.com/api/webhooks/1187329456021837824/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"`,
		`var c={secretKey:"6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"}`,
		`var c={PASSWORD:"Password1!"}`,
		`var c={dbPassword:"P@ssw0rd123"}`,
		`var c={secret:"sha256-Hk3j9Qz7Lm2PxV8wRt5NqWeRtYuIoPa="}`,
		`var c={password:"^(?=.*[A-Z])(?=.*[0-9]).{8,}$"}`,
		`var c={apiKey:"abcdefgh12345678"}`,
	} {
		if got := gradeOf(t, js); got == model.High || got == model.Medium {
			t.Errorf("example value flagged %s: %s", got, js)
		}
	}
	// The real thing next to them still is.
	if got := gradeOf(t, `var d="postgres://app:`+mixed(16)+`@db.internal:5432/prod"`); got != model.High {
		t.Errorf("real DB URL: got %q", got)
	}
}

// A secret word decides the name wherever it sits: any trailing word that
// does not describe the secret (backup, replica, sandbox, fallbacks) keeps
// it a credential, and pagination or device words never hide one.
func TestSecretWordsWinOverTrailingAndNoiseWords(t *testing.T) {
	v := func() string { return mixed(24) }
	for _, n := range []string{
		"JWT_SECRET_BACKUP", "JWT_SECRET_ROTATED", "JWT_SECRET_NEXT", "DB_PASSWORD_REPLICA", "DB_PASSWORD_RO", "DB_PASSWORD_TEMP",
		"SECRET_KEY_FALLBACKS", "STRIPE_SECRET_KEY_SANDBOX", "STRIPE_SECRET_KEY_LEGACY", "adminPasswordBackup",
		"API_KEY_PRIVATE", "API_KEY_INTERNAL", "API_TOKEN_SANDBOX", "ADMIN_TOKEN_TMP", "MONGO_PASSWORD_ATLAS",
		"RESET_TOKEN_SECRET", "ID_TOKEN_SECRET", "DEVICE_TOKEN_SECRET", "PUSH_TOKEN_SECRET", "PAGE_ACCESS_TOKEN",
		"SEARCH_ADMIN_TOKEN", "RUNNER_REGISTRATION_TOKEN", "WEBHOOK_VERIFICATION_TOKEN", "CSRF_SECRET",
		"MAILCHIMPAPIKEY", "TWILIOAUTHTOKEN", "SUPABASESERVICEKEY", "JWTSIGNINGKEY", "ALGOLIAADMINKEY", "GITHUBPAT",
		"GITHUB_PAT", "THEAPPSECRET", "OLDPASSWORD", "REDIS_PWD_RO", "PRIVATE_KEY_BACKUP",
	} {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got != model.Medium {
			t.Errorf("%s: got %q want medium", n, got)
		}
	}
	// Words that end in "pass" or "key" without a credential word before
	// them, and names about a secret rather than the secret.
	for _, n := range []string{
		"compass", "heroImageCompass", "firstImpressionsHeroImageCompass", "bypass", "ssoBypass", "encompass",
		"monkeyKey", "hotkey", "userPat", "secretName", "secretArn", "passwordResetSent", "passwordless",
		"passwordConfirm", "SERVICE_WORKER_TOKEN", "nextPageToken", "pushToken", "deviceToken",
	} {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got != "" {
			t.Errorf("%s: got %q, want no finding", n, got)
		}
	}
}

// Shopify Storefront tokens are public by design.
func TestShopifyStorefrontIsInfo(t *testing.T) {
	for _, js := range []string{
		`headers:{'X-Shopify-Storefront-Access-Token': '` + mixed(32) + `'}`,
		`var c={SHOPIFY_STOREFRONT_TOKEN:"` + mixed(32) + `"};`,
	} {
		if got := gradeOf(t, js); got != model.Info {
			t.Errorf("%s: got %q want info", js, got)
		}
	}
}

// A weak real password is a finding (LOW), not a documentation example to
// drop; the bare defaults and pure filler are still dropped.
func TestWeakPasswordsAreReported(t *testing.T) {
	for _, p := range []string{"Welcome2024!", "Admin@2024", "P@ssw0rd2024!", "Default#2024", "ExampleCorp#2024"} {
		if got := gradeOf(t, `var c={DB_PASSWORD:"`+p+`"};`); got != model.Low {
			t.Errorf("%s: got %q want low", p, got)
		}
	}
	if got := gradeOf(t, `var c={DB_PASSWORD:"Summer2024!"};`); got == "" {
		t.Error("Summer2024! dropped")
	}
	for _, p := range []string{"mysecretpassword", "your-password-here", "<insert-password>", "example12345", "[REDACTED]x"} {
		if got := gradeOf(t, `var c={DB_PASSWORD:"`+p+`"};`); got != "" {
			t.Errorf("%s: got %q want no finding", p, got)
		}
	}
	// A random value that happens to contain a placeholder word is kept.
	for _, w := range []string{"insert", "replace", "dummy", "example", "secret"} {
		v := mixed(10) + w + mixed(10)
		if got := gradeOf(t, `var c={API_SECRET:"`+v+`"};`); got == "" {
			t.Errorf("%s dropped", v)
		}
	}
	// Random letters around the name's own word are not a label.
	for _, v := range []string{"JsRLVZsecreterqGjppEmMgdt", "PfPgKeFHjhsecretZpKwQ"} {
		if got := gradeOf(t, `var c={API_SECRET:"`+v+`"};`); got == "" {
			t.Errorf("%s dropped", v)
		}
	}
	if got := gradeOf(t, `var c={SPO_PASSWORD:"SPOPassword"};`); got != "" {
		t.Errorf("label value reported: %s", got)
	}
	if got := gradeOf(t, `var d="postgres://app:Welcome2024!@db.internal:5432/prod"`); got != model.Low {
		t.Errorf("weak DB URL password: got %q want low", got)
	}
}

// A descriptor after a secret word does not hide a key or token after it,
// and names about a key (fingerprint, proof, question) or UI state are not
// credentials.
func TestDescriptorThenHead(t *testing.T) {
	v := func() string { return mixed(24) }
	for _, n := range []string{
		"SECRET_MANAGER_TOKEN", "SECRETS_MANAGER_ACCESS_KEY", "PASSWORD_MANAGER_API_KEY", "SECRET_STORE_TOKEN",
		"SECRET_STORAGE_KEY", "PASSWORD_RESET_HMAC_KEY", "PASSWORD_RESET_SIGNING_KEY", "PASSWORD_RESET_ENCRYPTION_KEY",
		"SESSION_SECRET_ROTATION_KEY", "ADMIN_PASSWORD_PLAIN_TEXT", "FORGOT_PASSWORD_JWT_KEY", "GPG_PASSPHRASE",
		"NEW_RELIC_INSERT_KEY", "STORAGE_ACCOUNT_KEY", "CONVEX_DEPLOY_KEY", "NEW_RELIC_LICENSE_KEY",
	} {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got != model.Medium {
			t.Errorf("%s: got %q want medium", n, got)
		}
	}
	if got := gradeOf(t, `var c={passwordPlainText:"`+v()+`"};`); got == "" {
		t.Error("passwordPlainText dropped")
	}
	for _, n := range []string{
		"privateKeyFingerprint", "appSecretProof", "secretQuestion", "secretSantaGroup", "showPassword", "passThroughKey",
		"USDC_TOKEN", "STAKING_TOKEN", "LP_TOKEN", "secretsManagerRegion",
	} {
		if got := gradeOf(t, `var c={`+n+`:"`+v()+`"};`); got == model.Medium || got == model.High {
			t.Errorf("%s: got %q, want below medium", n, got)
		}
	}
	if got := gradeOf(t, `var c={AG_GRID_LICENSE_KEY:"`+v()+`"};`); got != model.Low {
		t.Errorf("UI licence key: got %q want low", got)
	}
}

// Base64 secrets may start with / or + or end with +; paths may not pass.
func TestBase64EdgesKept(t *testing.T) {
	for _, v := range []string{
		"/" + randFrom(alnum, 30) + "9Aa+" + randFrom(alnum, 5),
		"+" + randFrom(alnum, 34) + "Zz9/x",
		randFrom(alnum, 36) + "aZ9+",
	} {
		if got := gradeOf(t, `var c={AWS_SECRET_ACCESS_KEY:"`+v+`"};`); got == "" {
			t.Errorf("%s dropped", v)
		}
	}
	if got := gradeOf(t, `var c={secretPath:"/static/assets/images/Logo2xRetinaHeader/x9"};`); got != "" {
		t.Errorf("path kept: %s", got)
	}
}

// Passwords that start with # or ^ are not selectors or patterns; real
// selectors and patterns are still dropped.
func TestPasswordsLookingLikeSelectors(t *testing.T) {
	for _, v := range []string{"#UUz^O4IIVSTn*@#", "^JwviuBVuSV#%O%V", "#jXTeSb6GK2mQ!x", "[Qm9z!Tr4@Lp2"} {
		if got := gradeOf(t, `var c={DB_PASSWORD:"`+v+`"};`); got == "" {
			t.Errorf("%s dropped", v)
		}
	}
	for _, v := range []string{"#password-input", "[type=password]", ".field-password:focus", "^[a-z0-9]{8,}$"} {
		if got := gradeOf(t, `var c={password:"`+v+`"};`); got != "" {
			t.Errorf("%s reported: %s", v, got)
		}
	}
}

// A dictionary passphrase and a long run of digits are reported at LOW
// under a password or secret name, and nowhere else.
func TestPassphrasesAndDigits(t *testing.T) {
	for _, js := range []string{
		`var c={DB_PASSWORD:"correct-horse-battery-staple"};`,
		`var c={backupPassphrase:"purple_monkey_dishwasher_lamp"};`,
		`var c={API_SECRET:"84719305628374"};`,
		`var c={adminPassword:"9038475610294857"};`,
	} {
		if got := gradeOf(t, js); got != model.Low {
			t.Errorf("%s: got %q want low", js, got)
		}
	}
	for _, js := range []string{
		`var c={passwordInputClass:"password-input-field"};`,
		`var c={PASSWORD_HINT:"use-a-strong-one"};`,
		`var c={password:"new-password"};`,
		`var c={autocomplete:"current-password-field"};`,
		`var c={passwordKey:"auth.password.label"};`,
		`var c={API_KEY:"correct-horse-battery-staple"};`,
		`var c={orderId:"84719305628374"};`,
		`var c={DB_PASSWORD:"1234567890123"};`,
		`var c={DB_PASSWORD:"111111111111"};`,
		`var c={SECRET_ID:"84719305628374"};`,
	} {
		if got := gradeOf(t, js); got != "" {
			t.Errorf("%s: got %q want nothing", js, got)
		}
	}
}
