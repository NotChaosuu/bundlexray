// Package scan runs one bundlexray audit: enumerate a page's scripts, follow
// what they load, look for secrets, endpoints and source maps, and record
// everything it could not read so a clean report can be trusted.
package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NotChaosuu/bundlexray/pkg/detect"
	"github.com/NotChaosuu/bundlexray/pkg/fetch"
	"github.com/NotChaosuu/bundlexray/pkg/model"
	"github.com/NotChaosuu/bundlexray/pkg/sourcemap"
)

// DefaultMaxScripts caps how many scripts one scan fetches, counting the ones
// found by following imports. Hitting it makes the scan incomplete.
const DefaultMaxScripts = 400

// htmlLabel is the source name for findings in the page markup itself.
const htmlLabel = "(page HTML)"

// Options configures a scan.
type Options struct {
	Fetch       fetch.Options
	Concurrency int
	DumpDir     string
	Progress    func(string)
	MaxScripts  int
	// NoGuessMaps turns off probing <bundle>.map for same-site bundles that
	// do not reference a map.
	NoGuessMaps bool
	// MaxTime bounds the whole scan. What is still unread when it runs out
	// makes the scan incomplete.
	MaxTime time.Duration
}

// DefaultMaxTime bounds a scan whose caller sets no limit.
const DefaultMaxTime = 10 * time.Minute

// maxFrameDepth is how many levels of same-site iframes are followed.
const maxFrameDepth = 3

// Run scans target. The error is non-nil only when the page itself could not
// be read; every other failure is recorded in the report.
func Run(target string, o Options) (*model.Report, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("target must be an http(s) URL, got %q", target)
	}
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
	if o.MaxScripts <= 0 {
		o.MaxScripts = DefaultMaxScripts
	}
	if o.MaxTime <= 0 {
		o.MaxTime = DefaultMaxTime
	}
	deadline := time.Now().Add(o.MaxTime)

	client := fetch.New(o.Fetch)
	client.SetTarget(u)
	client.SetDeadline(deadline)
	o.Progress("enumerating scripts...")
	page, err := client.Enumerate(target)
	var pageNotes []string
	if ua := client.RetryUA(); ua != "" {
		// Some sites refuse the tool's user agent outright, or serve it a
		// crawler or prerendered page with a fraction of the scripts.
		switch st := fetch.StatusOf(err); {
		case st == 403 || st == 404:
			if p2, err2 := client.EnumerateAs(target, ua); err2 == nil {
				page, err = p2, nil
				pageNotes = append(pageNotes, fmt.Sprintf("the site answered HTTP %d to the default user agent; the page was read as a browser", st))
			}
		case err == nil && page.Direct == nil && thinPage(page):
			if p2, err2 := client.EnumerateAs(target, ua); err2 == nil && p2.Direct == nil && scriptCount(p2) > scriptCount(page) {
				pageNotes = append(pageNotes, fmt.Sprintf("the site served the default user agent a smaller page (%d scripts) than a browser (%d); the browser's page was scanned",
					scriptCount(page), scriptCount(p2)))
				page = p2
			}
		}
	}
	if err == nil && page.Direct == nil && scriptCount(page) == 0 && page.Refresh != "" && client.SameSite(page.Refresh) {
		// <meta http-equiv="refresh"> to the real page.
		p2, err2 := client.Enumerate(page.Refresh)
		if st := fetch.StatusOf(err2); (st == 403 || st == 404) && client.RetryUA() != "" {
			p2, err2 = client.EnumerateAs(page.Refresh, client.RetryUA())
		}
		if err2 == nil {
			pageNotes = append(pageNotes, "followed the page's meta refresh to "+page.Refresh)
			page = p2
		}
	}
	if err != nil {
		return nil, err
	}

	r := model.NewReport(target)
	r.Warnings = append(r.Warnings, pageNotes...)
	if page.FinalURL != "" && page.FinalURL != target {
		r.FinalURL = page.FinalURL
	}
	s := &state{
		r: r, client: client, opts: o, page: page, deadline: deadline,
		seen: map[string]bool{}, hashes: map[[32]byte]string{}, maps: map[string]bool{},
		secrets: map[string]int{}, eps: map[string]int{}, ord: map[string]int{}, ids: map[string]bool{},
	}

	if page.Challenge != "" {
		r.AddIncomplete(model.GapPage, "the page is a "+page.Challenge+" interstitial, not the site; its real scripts were never seen")
	}
	if page.Truncated {
		r.AddIncomplete(model.GapPage, "the page exceeded the download cap and was truncated")
	}

	if page.Direct != nil {
		// The target is itself a script: scan it as one.
		s.enqueue(job{url: page.FinalURL, strong: true, pre: page.Direct})
	} else {
		s.scanPage(page, 0)
		s.scanFrames(page.Frames, 1)
		if len(page.Scripts) == 0 && len(page.Inline) == 0 && s.frameScripts == 0 && page.Challenge == "" {
			r.AddIncomplete(model.GapPage, "the page has no scripts; if it is an error or block page, the site's code was never seen")
		}
	}

	o.Progress(fmt.Sprintf("fetching %d script(s), following what they load...", len(s.strongQ)+len(s.weakQ)))
	s.drain()

	if s.failed > 0 {
		r.AddIncomplete(model.GapScripts, fmt.Sprintf("%d of %d script(s) could not be read", s.failed, s.fetched))
	}
	if s.outOfScope > 0 {
		r.AddIncomplete(model.GapScope, fmt.Sprintf("%d script(s) outside the scan's scope were not read", s.outOfScope))
	}
	if n := s.capped + s.cappedWeak; n > 0 {
		why := fmt.Sprintf("limit of %d reached (--max-scripts)", o.MaxScripts)
		if s.timedOut {
			why = fmt.Sprintf("time limit of %s reached (--max-time)", o.MaxTime)
		}
		r.AddIncomplete(model.GapLimit, fmt.Sprintf("%d referenced script(s) not fetched (%d from chunk lists): %s", n, s.cappedWeak, why))
	}
	if len(s.idList) == 0 {
		for _, ll := range s.live {
			r.AddIncomplete(model.GapScripts, fmt.Sprintf("the chunk loader in %s (%s) builds file names from chunk ids, and no code read loads a chunk by id; those chunks were not read",
				ll.g.at, ll.l.at))
		}
	}
	for _, g := range s.groups {
		switch {
		case g.total > 0 && g.missed == g.total:
			r.AddIncomplete(model.GapScripts, fmt.Sprintf("none of the %d chunk file(s) the chunk loader in %s names exist under %s; its lazy chunks were not read",
				g.total, g.at, g.base))
		case !g.literal && g.missed > 0:
			r.AddIncomplete(model.GapScripts, fmt.Sprintf("the chunk loader in %s sets its public path at run time, and %d of %d chunk file(s) guessed under %s do not exist",
				g.at, g.missed, g.total, g.base))
		case !g.literal && g.total > 0:
			r.Warnings = append(r.Warnings, fmt.Sprintf("the chunk loader in %s sets its public path at run time; its %d chunk(s) were read from %s, which the live site may not use",
				g.at, g.total, g.base))
		}
	}
	if len(r.Unconfirmed) > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d guessed chunk reference(s) return 404 (listed under unconfirmed_refs)", len(r.Unconfirmed)))
	}
	if s.computed > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d script URL(s) built at run time from a variable (\"x/\"+name+\".js\") could not be resolved and were not followed", s.computed))
	}

	if len(s.mapJobs) > 0 {
		guessed := 0
		for _, j := range s.mapJobs {
			if j.guess {
				guessed++
			}
		}
		msg := fmt.Sprintf("checking %d source map(s)", len(s.mapJobs))
		if guessed > 0 {
			msg += fmt.Sprintf(" (%d guessed at <bundle>.map)", guessed)
		}
		o.Progress(msg + "...")
	}
	s.runMaps()

	r.ScriptsNotFetched = s.capped + s.cappedWeak
	r.Complete = len(r.Incomplete) == 0
	s.sortFindings()
	return r, nil
}

type job struct {
	url    string
	strong bool
	// exact is a path from a list the bundler wrote: a 404 is a gap.
	exact bool
	// group numbers the chunk loader a guessed chunk URL came from (1-based).
	group int
	// json is a JSON module (import ... with {type:"json"}).
	json bool
	// followed marks a script found by following another one (or a frame)
	// rather than listed in the page.
	followed bool
	pre      *fetch.Response
}

type result struct {
	job  job
	resp *fetch.Response
	err  error
}

type state struct {
	r      *model.Report
	client *fetch.Client
	opts   Options
	page   *fetch.Page

	strongQ      []job
	weakQ        []job
	stopped      bool
	timedOut     bool
	deadline     time.Time
	seen         map[string]bool
	fetched      int
	failed       int
	outOfScope   int
	capped       int
	cappedWeak   int
	frameScripts int
	hashes       map[[32]byte]string

	mapJobs []mapJob
	maps    map[string]bool

	groups   []*guessGroup
	computed int
	live     []liveLoader
	// dataModules counts data: modules scanned in place.
	dataModules int
	ids         map[string]bool
	idList      []string

	secrets map[string]int
	eps     map[string]int
	ord     map[string]int
}

// guessGroup tracks the chunk URLs one chunk loader produced. Its file names
// are exact, but where they live depends on the public path: when none of
// them exist, or the path is computed at run time and some do not, the
// loader's chunks were not read.
type guessGroup struct {
	at, base      string
	literal       bool
	total, missed int
}

func (s *state) order(label string) int {
	if o, ok := s.ord[label]; ok {
		return o
	}
	s.ord[label] = len(s.ord)
	return s.ord[label]
}

// scanPage scans what the page itself carries (inline scripts, the HTML) and
// queues its external scripts. Inline scripts in a frame are labelled with
// the frame's URL so they cannot be confused with the top page's.
func (s *state) scanPage(page *fetch.Page, depth int) {
	for _, in := range page.Inline {
		label := in.Label
		if depth > 0 {
			label = in.Label + " in " + page.FinalURL
		}
		s.scanCode(label, in.Code)
		s.r.InlineScanned++
		s.queueRefs(string(in.Code), page.Base, page)
		if ref := fetch.FindSourceMapURL(in.Code, ""); ref != "" {
			s.addMap(mapJob{bundle: label, base: page.Base, ref: ref})
		}
	}
	if len(page.HTML) > 0 {
		s.scanSecrets(htmlLabel, page.HTML)
	}
	for _, src := range page.Scripts {
		if depth > 0 {
			s.frameScripts++
		}
		s.enqueue(job{url: src, strong: true, followed: depth > 0})
	}
	// Scripts a framework loads from attributes (Astro islands, Qwik
	// handlers, Vite legacy entries) are listed files; any other same-site
	// .js URL in an attribute or in the page's inline scripts and JSON
	// (route manifests, hydration data) is at least a guess.
	for _, h := range page.Hints {
		if h.Exact || s.client.SameSite(h.URL) {
			s.enqueue(job{url: h.URL, exact: h.Exact, followed: true})
		}
	}
	for _, in := range page.Inline {
		code := strings.ReplaceAll(string(in.Code), `\/`, "/")
		for _, m := range quotedJSRe.FindAllStringSubmatch(code, 2000) {
			if abs := fetch.Resolve(page.Base, m[1]); abs != "" && s.client.SameSite(abs) {
				s.enqueue(job{url: abs, followed: true})
			}
		}
	}
}

// quotedJSRe finds a quoted script URL or path in inline code and JSON.
var quotedJSRe = regexp.MustCompile(`["']((?:/|\./|https?://)[^"'\s<>\\]*?\.m?js)(?:[?#][^"'\s<>\\]*)?["']`)

// thinPage reports a page that may be a crawler or prerender version: few
// scripts, or a marker saying so.
func thinPage(p *fetch.Page) bool {
	l := bytes.ToLower(p.HTML[:min(len(p.HTML), 256<<10)])
	return scriptCount(p) <= 3 || bytes.Contains(l, []byte(`class="crawler`)) || bytes.Contains(l, []byte("prerender")) ||
		bytes.Contains(l, []byte("<noscript>")) && scriptCount(p) <= 10
}

func scriptCount(p *fetch.Page) int { return len(p.Scripts) + len(p.Inline) + len(p.Hints) }

// scanFrames follows same-site iframes up to maxFrameDepth levels; a frame
// whose src is a script is scanned as one. Third-party embeds are someone
// else's code and are listed as skipped.
func (s *state) scanFrames(frames []string, depth int) {
	unread := 0
	for _, f := range frames {
		if s.seen["frame:"+f] {
			continue
		}
		s.seen["frame:"+f] = true
		if !s.client.SameSite(f) {
			s.r.Skipped = append(s.r.Skipped, model.Skipped{URL: f, Reason: "third-party frame"})
			continue
		}
		if p := strings.ToLower(strings.SplitN(f, "?", 2)[0]); strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") {
			s.frameScripts++
			s.enqueue(job{url: f, strong: true, followed: true})
			continue
		}
		if depth > maxFrameDepth {
			s.r.AddIncomplete(model.GapLimit, fmt.Sprintf("frames nested deeper than %d were not followed", maxFrameDepth))
			continue
		}
		fp, err := s.client.Enumerate(f)
		if err != nil {
			unread++
			s.r.Errors = append(s.r.Errors, model.FetchError{URL: f, Status: fetch.StatusOf(err), Error: "frame: " + err.Error()})
			continue
		}
		if fp.Direct != nil {
			s.frameScripts++
			s.enqueue(job{url: fp.FinalURL, strong: true, followed: true, pre: fp.Direct})
			continue
		}
		s.scanPage(fp, depth)
		s.scanFrames(fp.Frames, depth+1)
	}
	if unread > 0 {
		s.r.AddIncomplete(model.GapPage, fmt.Sprintf("%d same-site frame(s) could not be read", unread))
	}
}

func (s *state) enqueue(j job) {
	if s.seen[j.url] {
		return
	}
	s.seen[j.url] = true
	if strings.HasPrefix(j.url, "data:") {
		// An import of a data: module (an import map can point a name at
		// one): the code is in the URL.
		if code := fetch.DecodeDataURI(j.url); len(code) > 0 {
			label := fmt.Sprintf("(data: module #%d)", s.dataModules+1)
			s.dataModules++
			s.scanCode(label, code)
			s.r.InlineScanned++
			s.queueRefs(string(code), s.page.Base, s.page)
		}
		return
	}
	if s.stopped {
		s.countCapped(j)
		return
	}
	if j.strong {
		s.strongQ = append(s.strongQ, j)
	} else {
		s.weakQ = append(s.weakQ, j)
	}
}

func (s *state) countCapped(j job) {
	if j.strong {
		s.capped++
	} else {
		s.cappedWeak++
	}
}

// next takes the next job, strong references first so that guesses from
// chunk lists never use up the budget a real import needs. It returns false
// when the script limit or the time limit is reached; whatever is still
// queued is counted as not fetched.
func (s *state) next() (job, bool) {
	if !s.stopped && (s.fetched >= s.opts.MaxScripts || time.Now().After(s.deadline)) {
		s.stopped = true
		s.timedOut = time.Now().After(s.deadline)
		for _, j := range s.strongQ {
			s.countCapped(j)
		}
		for _, j := range s.weakQ {
			s.countCapped(j)
		}
		s.strongQ, s.weakQ = nil, nil
	}
	var j job
	switch {
	case s.stopped:
		return j, false
	case len(s.strongQ) > 0:
		j, s.strongQ = s.strongQ[0], s.strongQ[1:]
	case len(s.weakQ) > 0:
		j, s.weakQ = s.weakQ[0], s.weakQ[1:]
	default:
		return j, false
	}
	s.fetched++
	s.r.Scripts = append(s.r.Scripts, j.url)
	if j.followed {
		s.r.ScriptsFollowed++
	}
	s.order(j.url)
	return j, true
}

// drain fetches the queue with bounded parallelism and handles each result as
// it arrives, so at most Concurrency bodies are held in memory at once.
func (s *state) drain() {
	jobs := make(chan job)
	results := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < s.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if j.pre != nil {
					results <- result{job: j, resp: j.pre}
					continue
				}
				resp, err := s.client.Get(j.url)
				if st := fetch.StatusOf(err); (st == 403 || st == 404) && s.client.RetryUA() != "" {
					// Some CDNs refuse anything that does not look like a
					// browser; ask once more as one before calling it missing.
					if r2, err2 := s.client.GetAs(j.url, s.client.RetryUA()); err2 == nil {
						resp, err = r2, nil
					}
				}
				results <- result{job: j, resp: resp, err: err}
			}
		}()
	}
	inflight := 0
	var held *job
	for {
		if held == nil {
			if j, ok := s.next(); ok {
				held = &j
			}
		}
		if held == nil && inflight == 0 {
			break
		}
		var send chan job
		var j job
		if held != nil {
			send, j = jobs, *held
		}
		select {
		case send <- j:
			held = nil
			inflight++
		case res := <-results:
			inflight--
			s.handle(res)
		}
	}
	close(jobs)
	wg.Wait()
}

func (s *state) handle(res result) {
	j, r := res.job, s.r
	fail := func(status int, why string) {
		// A guess that 404s is noted, and counted against its loader; a
		// strong or listed reference that 404s, or anything that fails
		// another way (403, 5xx, a block page), is a chunk that could not be
		// read.
		if !j.strong && !j.exact && (status == 404 || status == 410) {
			if j.group > 0 {
				s.groups[j.group-1].missed++
			}
			r.Unconfirmed = append(r.Unconfirmed, model.FetchError{URL: j.url, Status: status, Error: why})
			s.unconfirmed(j)
			return
		}
		s.failed++
		r.Errors = append(r.Errors, model.FetchError{URL: j.url, Status: status, Error: why})
	}
	if res.err != nil {
		if time.Now().After(s.deadline) {
			// Cut off by --max-time rather than failed: count it with what
			// was never fetched.
			s.timedOut = true
			s.countCapped(j)
			for i, u := range r.Scripts {
				if u == j.url {
					r.Scripts = append(r.Scripts[:i], r.Scripts[i+1:]...)
					break
				}
			}
			return
		}
		weak := !j.strong && !j.exact && j.group == 0
		if fetch.IsBlocked(res.err) {
			r.Skipped = append(r.Skipped, model.Skipped{URL: j.url, Reason: res.err.Error()})
			if !weak {
				s.outOfScope++
			}
			return
		}
		if weak && fetch.NoSuchHost(res.err) {
			// Import text in a string pointing at a host that does not
			// exist (analytics.company.com in a docs sample) is not code
			// the site loads.
			r.Unconfirmed = append(r.Unconfirmed, model.FetchError{URL: j.url, Error: res.err.Error()})
			s.unconfirmed(j)
			return
		}
		// A 404 on a script the page lists counts too: a CDN that filters
		// by user agent or region looks exactly like this.
		fail(fetch.StatusOf(res.err), res.err.Error())
		return
	}
	check := fetch.NotScript
	if j.json {
		check = fetch.NotJSONModule
	}
	if why := check(res.resp); why != "" {
		fail(0, "server returned "+why)
		return
	}
	r.ScriptsScanned++
	if res.resp.Truncated {
		r.AddIncomplete(model.GapLimit, j.url+" exceeded the download cap; only the first part was scanned")
	}
	body := res.resp.Body
	h := sha256.Sum256(body)
	if first, dup := s.hashes[h]; dup {
		r.Skipped = append(r.Skipped, model.Skipped{URL: j.url, Reason: "same content as " + first})
		return
	}
	s.hashes[h] = j.url
	s.scanCode(j.url, body)
	if j.json {
		return
	}
	s.queueRefs(string(body), res.resp.FinalURL, s.page)
	if ref := fetch.FindSourceMapURL(body, res.resp.SourceMapHeader); ref != "" {
		s.addMap(mapJob{bundle: j.url, base: res.resp.FinalURL, ref: ref})
	} else if !s.opts.NoGuessMaps && s.client.SameSite(res.resp.FinalURL) {
		s.addMap(mapJob{bundle: j.url, base: res.resp.FinalURL, ref: guessMapURL(res.resp.FinalURL), guess: true})
	}
}

// queueRefs follows what a script loads: static and dynamic imports
// (through the page's import map), workers, bundler lists (Vite, Next.js,
// Parcel, SystemJS, module federation) and chunk loaders. A loader it
// recognises but cannot read makes the scan incomplete.
func (s *state) queueRefs(code, scriptURL string, page *fetch.Page) {
	root := page.Base
	if u, err := url.Parse(page.Base); err == nil {
		root = u.Scheme + "://" + u.Host + "/"
	}
	nc := nonCode(code)
	refs, unparsed := findRefsIn(code, nc)
	for _, rf := range refs {
		var abs string
		switch {
		case rf.module || rf.bare:
			abs = page.ImportMap.Resolve(rf.spec, scriptURL)
		case rf.base == fromRoot:
			abs = fetch.Resolve(viteBase(scriptURL, rf.spec, root), rf.spec)
		case rf.base == fromNext:
			abs = fetch.Resolve(nextBase(scriptURL, page, root), rf.spec)
		case rf.base == fromPage:
			abs = fetch.Resolve(page.Base, rf.spec)
		default:
			abs = fetch.Resolve(scriptURL, rf.spec)
		}
		if abs != "" {
			s.enqueue(job{url: abs, strong: rf.strong, exact: rf.exact, json: rf.json, followed: true})
		}
	}
	ls := chunkLoaders(code, nc)
	for _, u := range append(unparsed, ls.unparsed...) {
		s.r.AddIncomplete(model.GapScripts, "chunk loader in "+scriptURL+" not understood ("+u+"); the chunks it loads were not read")
	}
	s.computed += ls.computed
	type path struct {
		pub           string
		auto, literal bool
	}
	paths := map[string]path{}
	for _, l := range ls.loaders {
		pp, ok := paths[l.rt]
		if !ok {
			pp.pub, pp.auto, pp.literal = publicPath(code, l.rt)
			paths[l.rt] = pp
		}
		pub, auto, literal := pp.pub, pp.auto, pp.literal
		base := scriptURL
		switch {
		case l.rt == "":
			// Not a bundler runtime: a script URL set from code resolves
			// against the document.
			base, literal = page.Base, true
		case auto && pub != "":
			base = fetch.Resolve(scriptURL, pub)
		case auto:
		case literal || pub != "":
			base = fetch.Resolve(page.Base, pub)
		}
		g := &guessGroup{at: scriptURL, base: base, literal: literal || auto}
		s.groups = append(s.groups, g)
		s.queueGuesses(g, len(s.groups), l.files)
		if l.pass {
			s.live = append(s.live, liveLoader{l: l, g: g, gi: len(s.groups)})
			s.queueGuesses(g, len(s.groups), l.more(s.idList))
		}
	}
	// Chunk ids this script loads by number (r.e(123)) feed every loader that
	// names chunks by id, here or in scripts read before or after.
	var fresh []string
	for _, id := range chunkCalls(code) {
		if !s.ids[id] {
			s.ids[id] = true
			s.idList = append(s.idList, id)
			fresh = append(fresh, id)
		}
	}
	for _, ll := range s.live {
		s.queueGuesses(ll.g, ll.gi, ll.l.more(fresh))
	}
}

// unconfirmed drops a guess that turned out not to exist from
// ScriptsFollowed; it was never one of the site's scripts.
func (s *state) unconfirmed(j job) {
	if j.followed && s.r.ScriptsFollowed > 0 {
		s.r.ScriptsFollowed--
	}
}

// liveLoader is a chunk loader that passes ids through unmapped: every chunk
// id found later is evaluated with it.
type liveLoader struct {
	l  loader
	g  *guessGroup
	gi int
}

func (s *state) queueGuesses(g *guessGroup, gi int, files []string) {
	for _, f := range files {
		abs := fetch.Resolve(g.base, f)
		if abs == "" || s.seen[abs] {
			continue
		}
		g.total++
		s.enqueue(job{url: abs, followed: true, group: gi})
	}
}

// nextBase finds Next.js's /_next/ folder, which its chunk lists are
// relative to: from the script's own URL, else from the page's scripts.
func nextBase(scriptURL string, page *fetch.Page, root string) string {
	for _, u := range append([]string{scriptURL}, page.Scripts...) {
		if i := strings.Index(u, "/_next/"); i >= 0 {
			return u[:i+len("/_next/")]
		}
	}
	return root + "_next/"
}

// viteBase finds the base Vite's preload list is relative to. Entries look
// like assets/x.js and the importing script lives at <base>assets/entry.js,
// often on a CDN path rather than the site root.
func viteBase(scriptURL, spec, root string) string {
	seg, _, ok := strings.Cut(strings.TrimPrefix(spec, "./"), "/")
	if !ok || seg == "" {
		return root
	}
	u, err := url.Parse(scriptURL)
	if err != nil {
		return root
	}
	u.RawQuery, u.Fragment = "", ""
	if i := strings.LastIndex(u.Path, "/"+seg+"/"); i >= 0 {
		u.Path = u.Path[:i+1]
		return u.String()
	}
	// The build's own folders (assets/, chunks/, entry/) sit side by side,
	// so the base is the parent of the script's folder.
	dir := u.Path[:strings.LastIndex(u.Path, "/")]
	if j := strings.LastIndex(dir, "/"); j >= 0 {
		u.Path = dir[:j+1]
		return u.String()
	}
	return root
}

func guessMapURL(scriptURL string) string {
	u, err := url.Parse(scriptURL)
	if err != nil {
		return ""
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path += ".map"
	return u.String()
}

// scanCode adds one script's findings.
func (s *state) scanCode(label string, code []byte) {
	s.order(label)
	s.scanSecrets(label, code)
	for _, e := range detect.Endpoints(label, code) {
		if i, ok := s.eps[e.Value]; ok {
			s.r.Endpoints[i] = detect.Merge(s.r.Endpoints[i], e)
			continue
		}
		s.eps[e.Value] = len(s.r.Endpoints)
		s.r.Endpoints = append(s.r.Endpoints, e)
	}
}

// scanSecrets adds findings; a secret seen before is folded into the first
// finding's AlsoIn list rather than reported again.
func (s *state) scanSecrets(label string, code []byte) {
	s.order(label)
	for _, sec := range detect.Secrets(label, code) {
		key := sec.Type + "\x00" + sec.Value
		if i, ok := s.secrets[key]; ok {
			// Capped so a key baked into every chunk does not bloat the report.
			if label != htmlLabel && len(s.r.Secrets[i].AlsoIn) < 50 {
				s.r.Secrets[i].AlsoIn = append(s.r.Secrets[i].AlsoIn, sec.Source)
			}
			continue
		}
		s.secrets[key] = len(s.r.Secrets)
		s.r.Secrets = append(s.r.Secrets, sec)
	}
}

// sortFindings makes output independent of fetch completion order.
func (s *state) sortFindings() {
	sort.SliceStable(s.r.Secrets, func(i, j int) bool {
		a, b := s.r.Secrets[i], s.r.Secrets[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if s.ord[a.Source] != s.ord[b.Source] {
			return s.ord[a.Source] < s.ord[b.Source]
		}
		return a.Line < b.Line || a.Line == b.Line && a.Column < b.Column
	})
	sort.SliceStable(s.r.Endpoints, func(i, j int) bool {
		return s.ord[s.r.Endpoints[i].Source] < s.ord[s.r.Endpoints[j].Source]
	})
	// Fetches finish in any order; sort so the same site gives the same
	// report.
	byURL := func(l []model.FetchError) {
		sort.SliceStable(l, func(i, j int) bool { return l[i].URL < l[j].URL })
	}
	byURL(s.r.Errors)
	byURL(s.r.Unconfirmed)
	sort.SliceStable(s.r.Skipped, func(i, j int) bool { return s.r.Skipped[i].URL < s.r.Skipped[j].URL })
}

type mapJob struct {
	bundle string
	base   string
	ref    string
	guess  bool
	key    string
	also   []string
}

func (s *state) addMap(j mapJob) {
	if strings.HasPrefix(j.ref, "data:") {
		// Keyed on the content: two frames can each have an
		// "(inline script #1)" with a different map.
		sum := sha256.Sum256([]byte(j.ref))
		j.key = "data:" + hex.EncodeToString(sum[:8])
	} else {
		j.key = fetch.Resolve(j.base, j.ref)
		if j.key == "" {
			s.r.Warnings = append(s.r.Warnings, fmt.Sprintf("%s: unusable sourceMappingURL %q", j.bundle, j.ref))
			return
		}
	}
	if s.maps[j.key] {
		for i := range s.mapJobs {
			if s.mapJobs[i].key == j.key && !j.guess {
				s.mapJobs[i].also = append(s.mapJobs[i].also, j.bundle)
			}
		}
		return
	}
	s.maps[j.key] = true
	s.mapJobs = append(s.mapJobs, j)
}

type mapOutcome struct {
	idx     int
	hit     model.SourceMapHit
	sm      *sourcemap.SourceMap
	skipped string
	drop    bool
	late    bool
}

// runMaps loads every distinct map with bounded parallelism and handles each
// as it arrives (secrets in sourcesContent, --dump), dropping it afterwards.
func (s *state) runMaps() {
	jobs := s.mapJobs
	out := make(chan mapOutcome)
	sem := make(chan struct{}, s.opts.Concurrency)
	go func() {
		var wg sync.WaitGroup
		for i, j := range jobs {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, j mapJob) {
				defer wg.Done()
				defer func() { <-sem }()
				if time.Now().After(s.deadline) {
					out <- mapOutcome{idx: i, late: true}
					return
				}
				o := s.loadMap(j)
				if o.hit.Status == model.MapUnreadable && time.Now().After(s.deadline) {
					o = mapOutcome{late: true}
				}
				o.idx = i
				out <- o
			}(i, j)
		}
		wg.Wait()
		close(out)
	}()

	hits := make([]*model.SourceMapHit, len(jobs))
	unreadable, invalid, scoped, late := 0, 0, 0, 0
	for o := range out {
		j := jobs[o.idx]
		if o.late {
			if !j.guess {
				late++
			}
			continue
		}
		if o.drop {
			continue
		}
		if o.skipped != "" {
			s.r.Skipped = append(s.r.Skipped, model.Skipped{URL: j.key, Reason: o.skipped})
			if !j.guess {
				scoped++
			}
			continue
		}
		hit := o.hit
		hit.Bundle, hit.AlsoReferencedBy, hit.Guessed = j.bundle, j.also, j.guess
		switch hit.Status {
		case model.MapUnreadable:
			unreadable++
		case model.MapInvalid:
			invalid++
		}
		if o.sm != nil {
			for i, src := range o.sm.Sources {
				if i < len(o.sm.SourcesContent) && o.sm.SourcesContent[i] != "" {
					s.scanSecrets(fmt.Sprintf("%s (source %s)", hit.MapURL, src), []byte(o.sm.SourcesContent[i]))
				}
			}
			if s.opts.DumpDir != "" && o.sm.HasContent() {
				s.dump(&hit, o.sm, j)
			}
		}
		hits[o.idx] = &hit
	}
	for _, h := range hits {
		if h != nil {
			s.r.SourceMaps = append(s.r.SourceMaps, *h)
		}
	}
	if unreadable > 0 {
		s.r.AddIncomplete(model.GapMaps, fmt.Sprintf("%d referenced source map(s) could not be retrieved", unreadable))
	}
	if scoped > 0 {
		s.r.AddIncomplete(model.GapScope, fmt.Sprintf("%d referenced source map(s) outside the scan's scope were not read", scoped))
	}
	if invalid > 0 {
		s.r.AddIncomplete(model.GapMaps, fmt.Sprintf("%d referenced source map(s) returned something that is not a map", invalid))
	}
	if late > 0 {
		s.r.AddIncomplete(model.GapLimit, fmt.Sprintf("%d referenced source map(s) not checked: time limit of %s reached (--max-time)", late, s.opts.MaxTime))
	}
}

func (s *state) dump(hit *model.SourceMapHit, sm *sourcemap.SourceMap, j mapJob) {
	dir := filepath.Join(s.opts.DumpDir, dumpDir(j.key, j.bundle))
	res, err := sm.Reconstruct(dir)
	// Report forward slashes on every OS so text and JSON output match
	// across platforms.
	shown := filepath.ToSlash(dir)
	hit.DumpDir = shown
	hit.Reconstructed, hit.ReconstructFailed = res.Written, res.Failed
	if err != nil {
		hit.Error = "reconstruct: " + filepath.ToSlash(err.Error())
	} else if res.Failed > 0 {
		s.r.Warnings = append(s.r.Warnings, fmt.Sprintf("%s: %d of %d source files could not be written (first: %s)",
			hit.MapURL, res.Failed, res.Failed+res.Written, filepath.ToSlash(res.Errors[0])))
	}
	s.opts.Progress(fmt.Sprintf("reconstructed %d source files -> %s", res.Written, shown))
}

func (s *state) loadMap(j mapJob) mapOutcome {
	var data []byte
	hit := model.SourceMapHit{MapURL: j.key}
	if strings.HasPrefix(j.ref, "data:") {
		hit.MapURL = "(inline data: URI in " + j.bundle + ")"
		data = fetch.DecodeDataURI(j.ref)
		if data == nil {
			hit.Status, hit.Error = model.MapInvalid, "malformed data: URI"
			return mapOutcome{hit: hit}
		}
	} else {
		resp, err := s.client.Get(j.key)
		if st := fetch.StatusOf(err); (st == 403 || st == 404) && s.client.RetryUA() != "" {
			if r2, err2 := s.client.GetAs(j.key, s.client.RetryUA()); err2 == nil {
				resp, err = r2, nil
			}
		}
		switch {
		case j.guess && (err != nil || fetch.LooksLikeHTML(resp.Body)):
			// A guess that misses is the normal case, not a finding.
			return mapOutcome{drop: true}
		case err != nil && fetch.IsBlocked(err):
			return mapOutcome{skipped: err.Error()}
		case err != nil && time.Now().After(s.deadline):
			return mapOutcome{late: true}
		case err != nil:
			st := fetch.StatusOf(err)
			if st == 404 || st == 410 {
				hit.Status, hit.Error = model.MapNotFound, fmt.Sprintf("HTTP %d", st)
			} else {
				hit.Status, hit.Error = model.MapUnreadable, err.Error()
			}
			return mapOutcome{hit: hit}
		case fetch.LooksLikeHTML(resp.Body):
			// Most often an SPA serving index.html for every path: the map
			// is not there. A challenge page means we could not check.
			hit.Status, hit.Error = model.MapNotFound, "server returned an HTML page, not a map"
			if fetch.ChallengeMarker(resp.Body) != "" {
				hit.Status = model.MapUnreadable
				hit.Error = "bot challenge page instead of the map"
			}
			return mapOutcome{hit: hit}
		}
		data = resp.Body
	}
	sm, err := sourcemap.Parse(data)
	if err != nil {
		if j.guess {
			return mapOutcome{drop: true}
		}
		hit.Status, hit.Error = model.MapInvalid, err.Error()
		return mapOutcome{hit: hit}
	}
	hit.Status = model.MapExposed
	hit.Sources = len(sm.Sources)
	hit.Recoverable = sm.RecoverableCount()
	hit.HasContent = hit.Recoverable > 0
	return mapOutcome{hit: hit, sm: sm}
}

// dumpDir names one directory per map. The hash of the exact map URL keeps
// Bundle.js.map and bundle.js.map, or m.js.map and m.js, apart on a
// case-insensitive filesystem.
func dumpDir(mapKey, bundle string) string {
	u := mapKey
	if strings.HasPrefix(u, "data:") {
		u = bundle + "_inline-map"
	}
	sum := sha256.Sum256([]byte(mapKey))
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	u = strings.TrimSuffix(u, ".map")
	u = strings.NewReplacer("#", "", "?", "_", "(", "", ")", "", " ", "_").Replace(u)
	return sourcemap.SanitizeSourcePath(u) + "_" + hex.EncodeToString(sum[:4])
}
