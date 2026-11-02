package sourcemap

import (
	"strings"
	"testing"
)

// The sanitized path must never climb out, be absolute, or contain a segment
// Windows would reinterpret; sanitizing twice must not change it.
func FuzzSanitizeSourcePath(f *testing.F) {
	for _, s := range []string{"../../etc/passwd", "C:\\x\\..\\y", "webpack:///./a.js", "a/./b/../c", "nul", "COM1.js", "f:g", "...", "a. /b ", "\x00x", "//server/share/x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := SanitizeSourcePath(in)
		if out != SanitizeSourcePath(out) {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, out, SanitizeSourcePath(out))
		}
		if strings.HasPrefix(out, "/") || strings.ContainsAny(out, "\\:<>\"|?*") {
			t.Fatalf("unsafe output %q from %q", out, in)
		}
		if out == "" {
			return
		}
		for _, seg := range strings.Split(out, "/") {
			if seg == "" || seg == "." || seg == ".." || isReservedName(seg) ||
				strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
				t.Fatalf("bad segment %q in %q from %q", seg, out, in)
			}
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte(`)]}'` + "\n" + `{"version":3,"sections":[{"map":{"version":3,"sources":["a"],"sourcesContent":["x"]}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		sm, err := Parse(data)
		if err == nil && sm.RecoverableCount() > len(sm.Sources) {
			t.Fatalf("more recoverable files than sources")
		}
	})
}
