package detect

import "testing"

// How the code uses a path decides its category: a router table or a link
// names an app page, a fetch or a url: field is an API call, and docs pages
// about hooks are not webhooks.
func TestEndpointContext(t *testing.T) {
	js := `const routes=[{path:"/admin",element:A},{path:"/login",element:L}];
		navigate("/settings/billing");
		jsx(Link,{to:"/account/admin"});
		fetch("/internal/billing/refunds",{method:"POST"});
		axios.post("/api/v2/session",d);
		const r={url:"/admin/users/export"};
		const s=api+"/session";
		const sdk={method:"POST",path:"/v1/upload"};
		const d="/reference/react/hooks";
		const e="/docs/admin/roles";
		const w="/api/webhooks";
		const x={href:"https://twitter.com/admin"};`
	want := map[string]struct {
		cat, ctx string
		partial  bool
	}{
		"/admin":                    {"route", "route", false},
		"/login":                    {"route", "route", false},
		"/settings/billing":         {"route", "route", false},
		"/account/admin":            {"route", "route", false},
		"/internal/billing/refunds": {"admin", "request", false},
		"/api/v2/session":           {"auth", "request", false},
		"/admin/users/export":       {"admin", "request", false},
		"/session":                  {"auth", "request", true},
		"/v1/upload":                {"upload", "route", false},
		"/reference/react/hooks":    {"path", "", false},
		"/docs/admin/roles":         {"path", "", false},
		"/api/webhooks":             {"webhook", "", false},
		"https://twitter.com/admin": {"admin", "route", false},
	}
	got := map[string]bool{}
	for _, e := range Endpoints("x.js", []byte(js)) {
		got[e.Value] = true
		w, ok := want[e.Value]
		if !ok {
			continue
		}
		if e.Category != w.cat || e.Context != w.ctx || e.Partial != w.partial {
			t.Errorf("%s: got %s/%s/%v, want %s/%s/%v", e.Value, e.Category, e.Context, e.Partial, w.cat, w.ctx, w.partial)
		}
	}
	for v := range want {
		if !got[v] {
			t.Errorf("%s not found", v)
		}
	}
}

// A value seen as a route in one place and as a request in another is a
// request; a full value beats a concatenation tail.
func TestEndpointMerge(t *testing.T) {
	es := Endpoints("x.js", []byte(`a={path:"/admin/users"};b=base+"/admin/users";fetch("/admin/users")`))
	if len(es) != 1 || es[0].Category != "admin" || es[0].Context != "request" || es[0].Partial {
		t.Fatalf("%+v", es)
	}
}
