package model

import (
	"strings"
	"unicode/utf8"
)

// Severity grades a finding: high, medium, low or info.
type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
	Info   Severity = "info"
)

var severityRank = map[Severity]int{High: 0, Medium: 1, Low: 2, Info: 3}

// Rank orders severities from most (0) to least severe. Unknown values sort last.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return len(severityRank)
}

// ParseSeverity accepts high, medium, low or info in any case.
func ParseSeverity(s string) (Severity, bool) {
	sev := Severity(strings.ToLower(s))
	_, ok := severityRank[sev]
	return sev, ok
}

// Secret is one credential found in a script. Value is unredacted; callers
// redact it for display.
type Secret struct {
	Type     string   `json:"type"`
	Value    string   `json:"value"`
	Severity Severity `json:"severity"`
	Source   string   `json:"source"`
	Line     int      `json:"line"`
	Column   int      `json:"column,omitempty"`
	Note     string   `json:"note,omitempty"`
	AlsoIn   []string `json:"also_in,omitempty"`
}

// Endpoint is a URL or absolute path found in a script.
type Endpoint struct {
	Value    string `json:"value"`
	Category string `json:"category"`
	Source   string `json:"source"`
	// Context says how the code uses the value: "request" (fetch, axios,
	// XHR, a url: field, api+"/path") or "route" (a router table, a link or
	// a navigate call). Empty when the code around it says neither.
	Context string `json:"context,omitempty"`
	// Partial marks the tail of a URL built by concatenation (api+"/session").
	Partial bool `json:"partial,omitempty"`
}

// Source-map statuses. Only Exposed means a map was read; Unreadable means we
// could not tell, which makes the scan incomplete.
const (
	MapExposed    = "exposed"
	MapNotFound   = "not_found"
	MapUnreadable = "unreadable"
	MapInvalid    = "invalid"
)

// SourceMapHit is the outcome of looking for one bundle's source map.
type SourceMapHit struct {
	Bundle            string   `json:"bundle"`
	AlsoReferencedBy  []string `json:"also_referenced_by,omitempty"`
	MapURL            string   `json:"map_url"`
	Status            string   `json:"status"`
	Error             string   `json:"error,omitempty"`
	Sources           int      `json:"sources"`
	HasContent        bool     `json:"has_content"`
	Recoverable       int      `json:"recoverable"`
	Reconstructed     int      `json:"reconstructed,omitempty"`
	ReconstructFailed int      `json:"reconstruct_failed,omitempty"`
	DumpDir           string   `json:"dump_dir,omitempty"`
	// Guessed is set for a map found at <bundle>.map with no reference to it
	// (webpack's hidden-source-map output).
	Guessed bool `json:"guessed,omitempty"`
}

// FetchError is a script the scan wanted to read and could not.
type FetchError struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error"`
}

// Skipped is a script deliberately not fetched (scope policy, duplicate content).
type Skipped struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
}

// Report is the full result of one scan, as written by --json.
type Report struct {
	Target     string   `json:"target"`
	FinalURL   string   `json:"final_url,omitempty"`
	Complete   bool     `json:"complete"`
	Incomplete []string `json:"incomplete_reasons"`
	// IncompleteKinds parallels Incomplete: page, scripts, scope, limit or maps.
	IncompleteKinds []string `json:"incomplete_kinds"`
	Scripts         []string `json:"scripts"`
	ScriptsScanned  int      `json:"scripts_scanned"`
	// ScriptsFollowed counts scripts found by following imports, workers,
	// chunk maps and frames rather than listed in the page.
	ScriptsFollowed int `json:"scripts_followed"`
	// ScriptsNotFetched counts referenced scripts left unread by --max-scripts
	// or --max-time.
	ScriptsNotFetched int          `json:"scripts_not_fetched"`
	InlineScanned     int          `json:"inline_scanned"`
	Errors            []FetchError `json:"errors"`
	// Unconfirmed lists chunk references that 404: a guess from a chunk
	// list that the server does not have. They do not make a scan
	// incomplete, but they are reported rather than dropped.
	Unconfirmed []FetchError   `json:"unconfirmed_refs"`
	Skipped     []Skipped      `json:"skipped"`
	Warnings    []string       `json:"warnings"`
	Secrets     []Secret       `json:"secrets"`
	Endpoints   []Endpoint     `json:"endpoints"`
	SourceMaps  []SourceMapHit `json:"source_maps"`
}

// NewReport returns a report whose slices marshal as [] rather than null.
func NewReport(target string) *Report {
	return &Report{
		Target:          target,
		Incomplete:      []string{},
		IncompleteKinds: []string{},
		Scripts:         []string{},
		Errors:          []FetchError{},
		Unconfirmed:     []FetchError{},
		Skipped:         []Skipped{},
		Warnings:        []string{},
		Secrets:         []Secret{},
		Endpoints:       []Endpoint{},
		SourceMaps:      []SourceMapHit{},
	}
}

// Kinds of incompleteness. Map-only gaps are separable because some hosts
// (Vercel) refuse every .map request, which says nothing about the scripts.
const (
	GapPage    = "page"
	GapScripts = "scripts"
	GapScope   = "scope"
	GapLimit   = "limit"
	GapMaps    = "maps"
)

// AddIncomplete records why the scan cannot vouch for what it did not read.
func (r *Report) AddIncomplete(kind, reason string) {
	r.Incomplete = append(r.Incomplete, reason)
	r.IncompleteKinds = append(r.IncompleteKinds, kind)
}

// OnlyMapGaps reports whether every incompleteness reason is about maps.
func (r *Report) OnlyMapGaps() bool {
	for _, k := range r.IncompleteKinds {
		if k != GapMaps {
			return false
		}
	}
	return len(r.IncompleteKinds) > 0
}

// ExposedMaps returns only the maps that were actually read.
func (r *Report) ExposedMaps() []SourceMapHit {
	var out []SourceMapHit
	for _, m := range r.SourceMaps {
		if m.Status == MapExposed {
			out = append(out, m)
		}
	}
	return out
}

// Redact keeps the first six and last four characters of a value, counted in
// runes so multibyte values are not cut mid-character.
func Redact(v string) string {
	n := utf8.RuneCountInString(v)
	r := []rune(v)
	if n <= 10 {
		return string(r[:n/2]) + "…"
	}
	return string(r[:6]) + "…" + string(r[n-4:])
}
