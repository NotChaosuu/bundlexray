package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/NotChaosuu/bundlexray/pkg/model"
)

func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

type painter bool

func (p painter) c(code, s string) string {
	if !p {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func (p painter) badge(s model.Severity) string {
	switch s {
	case model.High:
		return p.c("91;1", "HIGH  ")
	case model.Medium:
		return p.c("93;1", "MEDIUM")
	case model.Low:
		return p.c("96", "LOW   ")
	default:
		return p.c("2", "INFO  ")
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func printReport(w io.Writer, r *model.Report, secretsOnly, endpointsOnly, verbose bool, minSev model.Severity) {
	p := painter(useColor(w))
	bold := func(s string) string { return p.c("1", s) }
	dim := func(s string) string { return p.c("2", s) }

	showInfo := verbose || minSev == model.Info
	var shown []model.Secret
	hiddenInfo := 0
	for _, s := range r.Secrets {
		if s.Severity == model.Info && !showInfo {
			hiddenInfo++
			continue
		}
		shown = append(shown, s)
	}
	exposed := r.ExposedMaps()

	// A guessed chunk that does not exist was never one of the site's
	// scripts. Leave it out of the total so a complete scan doesn't read
	// "35 of 36".
	total := len(r.Scripts) + r.ScriptsNotFetched - len(r.Unconfirmed)
	scanned := fmt.Sprintf("%d of %s", r.ScriptsScanned, plural(total, "script", "scripts"))
	if r.ScriptsFollowed > 0 {
		scanned += fmt.Sprintf(" (%d found by following imports)", r.ScriptsFollowed)
	}
	if r.InlineScanned > 0 {
		scanned += fmt.Sprintf(", %d inline", r.InlineScanned)
	}
	if n := len(r.Unconfirmed); n > 0 {
		scanned += dim(fmt.Sprintf(", %s not found", plural(n, "guessed chunk", "guessed chunks")))
	}
	if !r.Complete {
		scanned += "  " + p.c("91;1", "INCOMPLETE")
	}
	fmt.Fprintf(w, "  %s  %s\n", bold("Scanned:"), scanned)
	if r.FinalURL != "" {
		fmt.Fprintf(w, "  %s  %s\n", bold("Landed: "), r.FinalURL)
	}
	found := fmt.Sprintf("%s, %s, %s", plural(len(shown), "secret", "secrets"),
		plural(len(r.Endpoints), "endpoint", "endpoints"), plural(len(exposed), "exposed source map", "exposed source maps"))
	if hiddenInfo > 0 {
		found += dim(fmt.Sprintf("  (+%d public-by-design keys, -v to show)", hiddenInfo))
	}
	fmt.Fprintf(w, "  %s  %s\n\n", bold("Found:  "), found)

	if !r.Complete {
		fmt.Fprintf(w, "  %s\n", p.c("91;1", "Scan incomplete. What could not be read is not covered by this report:"))
		for _, reason := range r.Incomplete {
			fmt.Fprintf(w, "    - %s\n", reason)
		}
		limit := len(r.Errors)
		if !verbose && limit > 10 {
			limit = 10
		}
		// A heading of their own, or the URLs read as detail of the last
		// reason (often a source-map one).
		if limit > 0 {
			fmt.Fprintf(w, "    %s\n", dim("failed requests:"))
		}
		for _, e := range r.Errors[:limit] {
			why := e.Error
			if e.Status != 0 {
				why = fmt.Sprintf("HTTP %d", e.Status)
			}
			fmt.Fprintf(w, "      %s  %s\n", e.URL, dim(why))
		}
		if limit < len(r.Errors) {
			fmt.Fprintf(w, "      %s\n", dim(fmt.Sprintf("+ %d more (use -v)", len(r.Errors)-limit)))
		}
		fmt.Fprintln(w)
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "  %s %s\n", p.c("93", "warning:"), warn)
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w)
	}

	if !endpointsOnly && len(shown) > 0 {
		fmt.Fprintf(w, "  %s\n\n", bold("Secrets"))
		for _, s := range shown {
			fmt.Fprintf(w, "    %s  %s  %s\n", p.badge(s.Severity), bold(s.Type), dim(model.Redact(s.Value)))
			loc := location(s.Source, s.Line, s.Column)
			if n := len(s.AlsoIn); n > 0 {
				loc += fmt.Sprintf(" (+%s)", plural(n, "other file", "other files"))
			}
			fmt.Fprintf(w, "            %s\n", dim(loc))
			if s.Note != "" {
				fmt.Fprintf(w, "            %s\n", dim(s.Note))
			}
		}
		fmt.Fprintln(w)
	}

	if !secretsOnly {
		printMaps(w, p, r, exposed, verbose)
	}

	if !secretsOnly && len(r.Endpoints) > 0 {
		fmt.Fprintf(w, "  %s (%d)\n\n", bold("Endpoints"), len(r.Endpoints))
		byCat := map[string][]string{}
		for _, e := range r.Endpoints {
			v := e.Value
			if e.Partial {
				// The tail of a concatenated URL (api+"/session").
				v = "..." + v
			}
			byCat[e.Category] = append(byCat[e.Category], v)
		}
		for _, cat := range []string{"auth", "admin", "payment", "upload", "webhook", "graphql", "websocket", "api", "path", "route"} {
			vals := byCat[cat]
			if len(vals) == 0 {
				continue
			}
			sort.Strings(vals)
			title := strings.ToUpper(cat)
			if cat == "route" {
				title = "APP ROUTES"
			}
			fmt.Fprintf(w, "    %s (%d)\n", p.c("96", title), len(vals))
			limit := len(vals)
			if !verbose && limit > 12 {
				limit = 12
			}
			for _, v := range vals[:limit] {
				fmt.Fprintf(w, "      %s\n", v)
			}
			if limit < len(vals) {
				fmt.Fprintf(w, "      %s\n", dim(fmt.Sprintf("+ %d more (use -v)", len(vals)-limit)))
			}
		}
		fmt.Fprintln(w)
	}

	if verbose && len(r.Skipped) > 0 {
		fmt.Fprintf(w, "  %s\n", bold("Skipped"))
		for _, s := range r.Skipped {
			fmt.Fprintf(w, "    %s  %s\n", s.URL, dim(s.Reason))
		}
		fmt.Fprintln(w)
	} else if len(r.Skipped) > 0 {
		fmt.Fprintf(w, "  %s\n\n", dim(fmt.Sprintf("%s skipped by scope or as duplicates (-v to list)", plural(len(r.Skipped), "URL", "URLs"))))
	}

	if len(shown) == 0 && len(exposed) == 0 && len(r.Endpoints) == 0 {
		if r.Complete {
			fmt.Fprintf(w, "  %s\n\n", dim("nothing exposed on these axes"))
		} else {
			fmt.Fprintf(w, "  %s\n\n", p.c("93", "no findings in what could be read; this is not a clean result"))
		}
	}
}

func printMaps(w io.Writer, p painter, r *model.Report, exposed []model.SourceMapHit, verbose bool) {
	bold := func(s string) string { return p.c("1", s) }
	dim := func(s string) string { return p.c("2", s) }
	if len(exposed) > 0 {
		fmt.Fprintf(w, "  %s\n\n", bold("Exposed source maps"))
		for _, sm := range exposed {
			sev := model.High
			note := fmt.Sprintf("%d original files", sm.Sources)
			if sm.HasContent {
				note += fmt.Sprintf(", %d recoverable", sm.Recoverable)
			} else {
				sev = model.Low
				note += " (file list only, no embedded content)"
			}
			if sm.Reconstructed > 0 || sm.ReconstructFailed > 0 {
				note += fmt.Sprintf(", %d written", sm.Reconstructed)
				if sm.ReconstructFailed > 0 {
					note += fmt.Sprintf(", %d failed", sm.ReconstructFailed)
				}
			}
			if sm.Guessed {
				note += " (not referenced; found at <bundle>.map)"
			}
			fmt.Fprintf(w, "    %s  %s\n", p.badge(sev), bold(sm.Bundle))
			fmt.Fprintf(w, "            %s — %s\n", dim(sm.MapURL), note)
			if n := len(sm.AlsoReferencedBy); n > 0 {
				fmt.Fprintf(w, "            %s\n", dim(fmt.Sprintf("also referenced by %s", plural(n, "other bundle", "other bundles"))))
			}
		}
		fmt.Fprintln(w)
	}
	var other []model.SourceMapHit
	for _, sm := range r.SourceMaps {
		if sm.Status == model.MapUnreadable || (verbose && sm.Status != model.MapExposed) {
			other = append(other, sm)
		}
	}
	if len(other) > 0 {
		fmt.Fprintf(w, "  %s\n\n", bold("Referenced source maps not read"))
		for _, sm := range other {
			fmt.Fprintf(w, "    %-10s %s  %s\n", sm.Status, sm.MapURL, dim(sm.Error))
		}
		fmt.Fprintln(w)
	}
}

func location(source string, line, col int) string {
	if line <= 0 {
		return source
	}
	if col > 1 {
		return fmt.Sprintf("%s:%d:%d", source, line, col)
	}
	return fmt.Sprintf("%s:%d", source, line)
}

func emitJSON(w io.Writer, r *model.Report) {
	out := struct {
		Tool    string        `json:"tool"`
		Version string        `json:"version"`
		Report  *model.Report `json:"report"`
	}{"bundlexray", version, r}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
