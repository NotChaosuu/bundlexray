package fetch

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"net/http"
	"testing"
	"time"
)

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// Bodies the server compressed without being asked to (deflate, raw
// deflate, gzip applied twice) are decoded rather than failing the script;
// an encoding Go cannot decode still fails, and a decompression bomb stops
// at the body cap.
func TestEncodedBodies(t *testing.T) {
	js := []byte(`var cfg={k:1};console.log(cfg);`)
	var z, raw bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(js)
	zw.Close()
	fw, _ := flate.NewWriter(&raw, flate.BestCompression)
	fw.Write(js)
	fw.Close()
	bodies := map[string]struct {
		enc  string
		body []byte
	}{
		"/deflate.js":  {"deflate", z.Bytes()},
		"/rawdefl.js":  {"deflate", raw.Bytes()},
		"/gzgz.js":     {"gzip, gzip", gz(gz(js))},
		"/gzdefl.js":   {"deflate, gzip", gz(z.Bytes())},
		"/bomb.js":     {"gzip", gz(bytes.Repeat([]byte("a"), 50<<20))},
		"/zstd.js":     {"zstd", js},
		"/corrupt.js":  {"gzip", []byte("not gzip")},
		"/identity.js": {"identity", js},
	}
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		b := bodies[r.URL.Path]
		w.Header().Set("Content-Encoding", b.enc)
		w.Write(b.body)
	})
	c := New(Options{Timeout: 5 * time.Second, AllowPrivate: true, MaxBody: 1 << 20})
	for _, p := range []string{"/deflate.js", "/rawdefl.js", "/gzgz.js", "/gzdefl.js", "/identity.js"} {
		resp, err := c.Get(srv.URL + p)
		if err != nil || !bytes.Equal(resp.Body, js) {
			t.Errorf("%s: %v %+v", p, err, resp)
		}
	}
	if resp, err := c.Get(srv.URL + "/bomb.js"); err != nil || !resp.Truncated || len(resp.Body) != 1<<20 {
		t.Errorf("bomb: %v", err)
	}
	for _, p := range []string{"/zstd.js", "/corrupt.js"} {
		if _, err := c.Get(srv.URL + p); err == nil {
			t.Errorf("%s: want an error, got %v", p, err)
		}
	}
}
