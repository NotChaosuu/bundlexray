package detect

import (
	"strings"
	"testing"
)

func FuzzSecrets(f *testing.F) {
	f.Add(`var a="` + fakeAWS + `";x={HUBVISOR_LEO_API_KEY:"!2#Aou` + mixed(14) + `j&"}`)
	f.Add(privateKey)
	f.Add(`t="` + jwt(`{"role":"service_role"}`) + `"`)
	f.Add("-----BEGIN PRIVATE KEY-----\\n-----END ")
	f.Fuzz(func(t *testing.T, js string) {
		for _, s := range Secrets("f.js", []byte(js)) {
			if !strings.Contains(js, s.Value) || s.Line < 1 || s.Column < 1 {
				t.Fatalf("bad finding %+v", s)
			}
		}
		for _, e := range Endpoints("f.js", []byte(js)) {
			if !strings.Contains(js, e.Value) {
				t.Fatalf("endpoint not in input: %+v", e)
			}
		}
	})
}
