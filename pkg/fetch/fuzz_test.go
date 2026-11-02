package fetch

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzEnumerate(f *testing.F) {
	f.Add(`<base href="//cdn.example/x/"><script src=a.js></script><link rel=modulepreload href=b.js><script>x</script>`)
	f.Add(`<script src="data:text/javascript;base64,eA=="></script><script src="javascript:1"></script>`)
	base, _ := url.Parse("https://site.example/p/")
	f.Fuzz(func(t *testing.T, page string) {
		p := enumerate(base.String(), base, []byte(page))
		for _, s := range p.Scripts {
			if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
				t.Fatalf("non-http script %q", s)
			}
		}
	})
}

func FuzzDecodeDataURI(f *testing.F) {
	f.Add("data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==")
	f.Add("data:text/javascript,var%20a")
	f.Fuzz(func(t *testing.T, u string) {
		_ = DecodeDataURI(u)
		_ = FindSourceMapURL([]byte(u), "")
	})
}
