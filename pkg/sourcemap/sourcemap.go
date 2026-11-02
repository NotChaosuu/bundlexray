package sourcemap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SourceMap holds the fields of a v3 source map that matter for recovery.
type SourceMap struct {
	Version        json.RawMessage `json:"version"`
	File           string          `json:"file"`
	SourceRoot     string          `json:"sourceRoot"`
	Sources        []string        `json:"sources"`
	SourcesContent []string        `json:"sourcesContent"`
	Sections       []struct {
		Map *SourceMap `json:"map"`
		URL string     `json:"url"`
	} `json:"sections"`
}

// ErrNotSourceMap is returned for JSON (or HTML) that is not a v3 source map.
var ErrNotSourceMap = errors.New("not a source map")

// Parse reads a v3 source map. Index maps (with "sections") are flattened so
// their sources count and reconstruct like a normal map.
func Parse(data []byte) (*SourceMap, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	// The spec allows a ")]}'" first line to defeat XSSI; it must be skipped.
	if bytes.HasPrefix(data, []byte(")]}")) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	var sm SourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotSourceMap, err)
	}
	// Some generators write the version as a string.
	if v := strings.Trim(string(sm.Version), `"`); v != "3" {
		return nil, fmt.Errorf("%w: version %s", ErrNotSourceMap, string(sm.Version))
	}
	if len(sm.Sections) > 0 {
		if err := sm.flatten(0); err != nil {
			return nil, err
		}
	}
	return &sm, nil
}

// maxSectionDepth bounds index-map nesting; deeper is reported, not dropped.
const maxSectionDepth = 32

func (sm *SourceMap) flatten(depth int) error {
	if depth > maxSectionDepth {
		return fmt.Errorf("%w: index map nested deeper than %d", ErrNotSourceMap, maxSectionDepth)
	}
	for _, sec := range sm.Sections {
		if sec.Map == nil {
			continue
		}
		if err := sec.Map.flatten(depth + 1); err != nil {
			return err
		}
		for i, src := range sec.Map.Sources {
			if sec.Map.SourceRoot != "" {
				src = joinRoot(sec.Map.SourceRoot, src)
			}
			sm.Sources = append(sm.Sources, src)
			content := ""
			if i < len(sec.Map.SourcesContent) {
				content = sec.Map.SourcesContent[i]
			}
			for len(sm.SourcesContent) < len(sm.Sources)-1 {
				sm.SourcesContent = append(sm.SourcesContent, "")
			}
			sm.SourcesContent = append(sm.SourcesContent, content)
		}
	}
	sm.Sections = nil
	return nil
}

func joinRoot(root, src string) string {
	if strings.Contains(src, "://") || strings.HasPrefix(src, "/") {
		return src
	}
	return strings.TrimSuffix(root, "/") + "/" + src
}

// HasContent reports whether any original source is embedded.
func (sm *SourceMap) HasContent() bool {
	return sm.RecoverableCount() > 0
}

// RecoverableCount counts sources with embedded content.
func (sm *SourceMap) RecoverableCount() int {
	n := 0
	for i, c := range sm.SourcesContent {
		if c != "" && i < len(sm.Sources) {
			n++
		}
	}
	return n
}

// Result reports what Reconstruct put on disk. Written counts only files that
// were read back at the expected size.
type Result struct {
	Written int
	Failed  int
	Errors  []string
}

// Reconstruct writes every embedded source under outDir. A file that cannot be
// written is counted in Failed and the rest still go out.
func (sm *SourceMap) Reconstruct(outDir string) (Result, error) {
	var res Result
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return res, err
	}
	t := newTree()
	for i, src := range sm.Sources {
		if i >= len(sm.SourcesContent) || sm.SourcesContent[i] == "" {
			continue
		}
		if sm.SourceRoot != "" {
			src = joinRoot(sm.SourceRoot, src)
		}
		rel := SanitizeSourcePath(src)
		if rel == "" {
			rel = fmt.Sprintf("unknown/source_%d.js", i)
		}
		rel = t.claim(rel)
		content := []byte(sm.SourcesContent[i])
		target := filepath.Join(outDir, filepath.FromSlash(rel))
		if err := writeVerified(target, content); err != nil {
			res.Failed++
			if len(res.Errors) < 20 {
				res.Errors = append(res.Errors, err.Error())
			}
			continue
		}
		res.Written++
	}
	return res, nil
}

func writeVerified(target string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(target, content, 0o644); err != nil {
		return err
	}
	fi, err := os.Stat(target)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() != int64(len(content)) {
		return fmt.Errorf("%s: wrote %d bytes, found %d on disk", target, len(content), fi.Size())
	}
	return nil
}

// tree hands out output paths that cannot collide on a case-insensitive
// filesystem, and never uses a name as both a file and a directory.
type tree struct {
	files map[string]bool
	dirs  map[string]bool
}

func newTree() *tree { return &tree{files: map[string]bool{}, dirs: map[string]bool{}} }

func (t *tree) claim(rel string) string {
	segs := strings.Split(rel, "/")
	prefix := ""
	for i := 0; i < len(segs)-1; i++ {
		for t.files[strings.ToLower(join(prefix, segs[i]))] {
			segs[i] += "_dir"
		}
		prefix = join(prefix, segs[i])
		t.dirs[strings.ToLower(prefix)] = true
	}
	name := join(prefix, segs[len(segs)-1])
	for t.files[strings.ToLower(name)] || t.dirs[strings.ToLower(name)] {
		name = bumpName(name)
	}
	t.files[strings.ToLower(name)] = true
	return name
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "/" + b
}

// SanitizeSourcePath turns an untrusted "sources" entry into a relative path
// that cannot leave the output directory: bundler schemes, drive letters,
// query/fragment and every "." / ".." segment are removed. Segments are also
// made valid on Windows, so the same tree can be written on any OS.
func SanitizeSourcePath(s string) string {
	if i := strings.Index(s, "://"); i >= 0 && i < 24 && !strings.ContainsAny(s[:i], "/\\") {
		s = s[i+3:]
	}
	s = strings.ReplaceAll(s, "\\", "/")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if len(s) >= 2 && s[1] == ':' {
		s = s[2:]
	}
	var clean []string
	for _, p := range strings.Split(s, "/") {
		p = cleanSegment(p)
		if p == "" {
			continue
		}
		clean = append(clean, p)
	}
	return strings.Join(clean, "/")
}

func cleanSegment(p string) string {
	p = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return -1
		case r == 0x200e || r == 0x200f || r == 0x061c || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069:
			// Bidi controls make "\u202egnp.js" display as "sj.png".
			return -1
		case strings.ContainsRune(`<>:"|?*`, r):
			// ':' would otherwise write an NTFS alternate data stream.
			return '_'
		}
		return r
	}, p)
	p = strings.TrimSpace(p)
	if len(p) > 120 {
		ext := filepath.Ext(p)
		if len(ext) > 16 {
			ext = ""
		}
		p = truncateRunes(p[:len(p)-len(ext)], 120-len(ext)) + ext
	}
	// Windows drops trailing dots and spaces, so "a." would land on "a" and a
	// segment of only dots ("...") is not a usable name at all. Trim after
	// truncating, or the cut can leave a new trailing space.
	p = strings.TrimRightFunc(p, func(r rune) bool { return r == '.' || unicode.IsSpace(r) })
	if p == "" {
		return ""
	}
	if isReservedName(p) {
		p = "_" + p
	}
	// "VERYLO~1" is an 8.3 short name and can alias a long directory name.
	if shortName.MatchString(p) {
		p = strings.ReplaceAll(p, "~", "_")
	}
	return p
}

var shortName = regexp.MustCompile(`~[0-9]`)

// truncateRunes cuts s to at most n bytes without splitting a character.
func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// isReservedName matches the DOS device names Windows maps to devices instead
// of files, with or without an extension (NUL, nul.txt, COM1.js, LPT¹).
func isReservedName(seg string) bool {
	base := seg
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) >= 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
		switch base[3:] {
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return true
		}
	}
	return false
}

func bumpName(rel string) string {
	ext := filepath.Ext(rel)
	if strings.Contains(ext, "/") {
		ext = ""
	}
	base := strings.TrimSuffix(rel, ext)
	return base + "_dup" + ext
}
