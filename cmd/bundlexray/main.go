package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/NotChaosuu/bundlexray/pkg/fetch"
	"github.com/NotChaosuu/bundlexray/pkg/model"
	"github.com/NotChaosuu/bundlexray/pkg/scan"
)

// version is overridden at release time with -X main.version; go build and
// go install report this default.
var version = "1.0.0"

// maxConcurrency bounds --concurrency: each worker can hold a 25 MB body, so
// a large value runs the machine out of memory within seconds.
const maxConcurrency = 64

// Exit codes. 1 is reserved for "--exit-code found something" so CI can tell
// a finding from a broken run.
const (
	exitOK         = 0
	exitFindings   = 1
	exitError      = 2
	exitIncomplete = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

type config struct {
	quiet, verbose, asJSON     bool
	dump                       string
	secretsOnly, endpointsOnly bool
	minSev                     string
	insecure                   bool
	timeout                    time.Duration
	concurrency                int
	exitCode, allowIncomplete  bool
	allowPrivate, sameSite     bool
	allowHosts                 listFlag
	userAgent                  string
	showVersion                bool
	maxScripts                 int
	maxTime                    time.Duration
	noGuessMaps                bool
	allowUnreadableMaps        bool
}

func newFlagSet(cfg *config, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("bundlexray", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&cfg.quiet, "q", false, "suppress banner and progress")
	fs.BoolVar(&cfg.verbose, "v", false, "show everything: info-level keys, all endpoints, maps that were not found")
	fs.BoolVar(&cfg.asJSON, "json", false, "emit JSON report to stdout")
	fs.StringVar(&cfg.dump, "dump", "", "reconstruct exposed source maps into this directory")
	fs.BoolVar(&cfg.secretsOnly, "secrets-only", false, "report only secrets")
	fs.BoolVar(&cfg.endpointsOnly, "endpoints-only", false, "report only endpoints")
	fs.StringVar(&cfg.minSev, "min-severity", "", "only report secrets at or above this severity (high|medium|low|info)")
	fs.BoolVar(&cfg.insecure, "insecure", false, "skip TLS certificate verification")
	fs.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "per-request timeout")
	fs.IntVar(&cfg.concurrency, "concurrency", 6, "max parallel fetches (1-64)")
	fs.DurationVar(&cfg.maxTime, "max-time", scan.DefaultMaxTime, "time limit for the whole scan; what is unread when it runs out makes the scan incomplete")
	fs.BoolVar(&cfg.exitCode, "exit-code", false, "CI gate: exit 1 on a high/medium secret or an exposed source map with recoverable code, 3 if the scan was incomplete")
	fs.BoolVar(&cfg.allowIncomplete, "allow-incomplete", false, "with --exit-code, do not fail on an incomplete scan")
	fs.BoolVar(&cfg.allowPrivate, "allow-private", false, "allow requests to loopback/private/link-local addresses")
	fs.BoolVar(&cfg.sameSite, "same-site", false, "only fetch from the target's registrable domain (and --allow-host)")
	fs.Var(&cfg.allowHosts, "allow-host", "extra host allowed with --same-site (repeatable, comma-separated)")
	fs.StringVar(&cfg.userAgent, "user-agent", "", "User-Agent header (default names bundlexray; a refused script is retried once as a browser unless this is set)")
	fs.IntVar(&cfg.maxScripts, "max-scripts", scan.DefaultMaxScripts, "most scripts to fetch, counting ones found by following imports; hitting it makes the scan incomplete")
	fs.BoolVar(&cfg.noGuessMaps, "no-guess-maps", false, "do not probe <bundle>.map for same-site bundles that reference no map")
	fs.BoolVar(&cfg.allowUnreadableMaps, "allow-unreadable-maps", false, "with --exit-code, do not fail when the only gap is source maps that could not be read (hosts that refuse every .map)")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version and exit")
	fs.Usage = func() {
		usage(stderr)
		fmt.Fprintln(stderr, "\nflags (before or after the URL):")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\nexit codes: 0 ok, 1 findings (--exit-code), 2 error, 3 incomplete scan (--exit-code)")
	}
	return fs
}

// parseArgs accepts flags before and after the target. The standard flag
// package stops at the first positional, which would silently drop
// "bundlexray https://x --exit-code".
func parseArgs(args []string, cfg *config, stderr io.Writer) ([]string, error) {
	fs := newFlagSet(cfg, stderr)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: bundlexray [flags] <https://your-site.example>")
	fmt.Fprintln(w, "\nAudits a site YOU OWN or are authorized to test for secrets, endpoints,")
	fmt.Fprintln(w, "and exposed source maps in its JavaScript. Run with -h for flags.")
}

func run(args []string, stdout, stderr io.Writer) int {
	var cfg config
	pos, err := parseArgs(args, &cfg, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitError
	}
	if cfg.showVersion {
		fmt.Fprintln(stdout, "bundlexray", version)
		return exitOK
	}
	if len(pos) != 1 {
		if len(pos) > 1 {
			fmt.Fprintf(stderr, "error: one target at a time, got %d: %s\n\n", len(pos), strings.Join(pos, " "))
		}
		usage(stderr)
		return exitError
	}
	target := pos[0]
	var minSev model.Severity
	if cfg.minSev != "" {
		s, ok := model.ParseSeverity(cfg.minSev)
		if !ok {
			fmt.Fprintf(stderr, "error: --min-severity must be high, medium, low or info, got %q\n", cfg.minSev)
			return exitError
		}
		minSev = s
	}
	if cfg.timeout <= 0 {
		fmt.Fprintf(stderr, "error: --timeout must be positive, got %s\n", cfg.timeout)
		return exitError
	}
	if cfg.concurrency < 1 || cfg.concurrency > maxConcurrency {
		fmt.Fprintf(stderr, "error: --concurrency must be 1-%d, got %d\n", maxConcurrency, cfg.concurrency)
		return exitError
	}
	if cfg.maxTime <= 0 {
		fmt.Fprintf(stderr, "error: --max-time must be positive, got %s\n", cfg.maxTime)
		return exitError
	}
	if cfg.maxScripts < 1 {
		fmt.Fprintf(stderr, "error: --max-scripts must be at least 1, got %d\n", cfg.maxScripts)
		return exitError
	}
	if cfg.secretsOnly && cfg.endpointsOnly {
		fmt.Fprintln(stderr, "error: --secrets-only and --endpoints-only are mutually exclusive")
		return exitError
	}

	q := cfg.quiet || cfg.asJSON
	progress := func(msg string) {
		if !q {
			fmt.Fprintf(stderr, "  %s\n", msg)
		}
	}
	if !q {
		fmt.Fprintf(stderr, "\n  bundlexray %s — %s\n\n", version, target)
	}

	report, err := scan.Run(target, scan.Options{
		Fetch: fetch.Options{
			Insecure:     cfg.insecure,
			Timeout:      cfg.timeout,
			UserAgent:    cfg.userAgent,
			AllowPrivate: cfg.allowPrivate,
			SameSite:     cfg.sameSite,
			AllowHosts:   cfg.allowHosts,
		},
		Concurrency: cfg.concurrency,
		DumpDir:     cfg.dump,
		Progress:    progress,
		MaxScripts:  cfg.maxScripts,
		MaxTime:     cfg.maxTime,
		NoGuessMaps: cfg.noGuessMaps,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		if fetch.IsBlocked(err) {
			fmt.Fprintln(stderr, "       (the target itself is out of scope; check --same-site / --allow-private)")
		}
		return exitError
	}
	if minSev != "" {
		report.Secrets = filterSeverity(report.Secrets, minSev)
	}
	if !q {
		fmt.Fprintln(stderr)
	}

	if cfg.asJSON {
		emitJSON(stdout, report)
	} else {
		printReport(stdout, report, cfg.secretsOnly, cfg.endpointsOnly, cfg.verbose, minSev)
	}

	if !cfg.exitCode {
		return exitOK
	}
	if gated(report, minSev, cfg.secretsOnly, cfg.endpointsOnly) {
		return exitFindings
	}
	if !report.Complete && !cfg.allowIncomplete && !(cfg.allowUnreadableMaps && report.OnlyMapGaps()) {
		return exitIncomplete
	}
	return exitOK
}

// gated reports whether anything shown should fail a CI run: a high or medium
// secret (subject to --min-severity) or a source map with recoverable code.
// What --secrets-only or --endpoints-only hides does not gate.
func gated(r *model.Report, minSev model.Severity, secretsOnly, endpointsOnly bool) bool {
	if endpointsOnly {
		return false
	}
	floor := model.Medium.Rank()
	if minSev != "" && minSev.Rank() < floor {
		floor = minSev.Rank()
	}
	for _, s := range r.Secrets {
		if s.Severity.Rank() <= floor {
			return true
		}
	}
	if secretsOnly {
		return false
	}
	for _, m := range r.ExposedMaps() {
		if m.HasContent {
			return true
		}
	}
	return false
}

func filterSeverity(secrets []model.Secret, min model.Severity) []model.Secret {
	out := []model.Secret{}
	for _, s := range secrets {
		if s.Severity.Rank() <= min.Rank() {
			out = append(out, s)
		}
	}
	return out
}
