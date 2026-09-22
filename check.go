package main

import (
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Severity of a finding, roughly in order of how confident it is
// that something is actually wrong.
type Severity string

const (
	SeverityHigh Severity = "high"
	SeverityWarn Severity = "warn"
)

// Finding is one flagged requirement.
type Finding struct {
	Module   string   `json:"module"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
	Detail   string   `json:"detail"`
}

const (
	recentWindow = 30 * 24 * time.Hour

	// typoMaxDistance is the absolute cap on edit distance, but it's
	// only allowed for names at or above typoScaledMaxLen — see below.
	typoMaxDistance = 2
	// typoMinNameLen excludes short base names (both the candidate's
	// and the popular module's) from typo comparison entirely. Found
	// empirically (run #30): scanning ~20 real go.mod files turned up
	// "term"~"pterm", "yaml"~"toml", "gin"~"gonp" and similar —
	// 2 edits is a huge fraction of a 3-6 letter string, so short
	// names collide constantly by chance, not by typosquatting.
	typoMinNameLen = 6
	// typoScaledMaxLen: below this length, only a single-edit distance
	// counts as suspicious. A 2-edit distance on an 8-9 letter name
	// (e.g. "go-retry"~"go-pretty", "gotenv"~"godotenv") is still just
	// as likely to be two unrelated real projects as a typosquat.
	typoScaledMaxLen = 10
)

// genericBaseNames are trailing path segments so conventional across
// the Go ecosystem that edit-distance proximity to them carries no
// typosquat signal — found empirically (run #52) by scanning 8 large
// real-world go.mod files (Kubernetes, Grafana, CockroachDB, etcd,
// Prometheus, Terraform, Hugo, Caddy): "errors" and "protobuf" alone
// produced a false positive in 5 of the 8, because dozens of unrelated
// orgs each ship their own "errors" or "*protobuf" subpackage by
// convention, and that's close (1-2 edits) to *some* popular module's
// base name by chance. Unlike a coined name (e.g. "logrus"), a near
// miss on a generic word says nothing about intent to deceive. This
// list only ever grows by evidence, the same way popularModules does —
// don't add a name here on suspicion alone. It's checked against both
// the candidate's base name and each popular module's base name: run
// #30's fix of adding the *victim* of a collision (e.g. "vtprotobuf")
// to popularModules is what created the "protobuf" false positive here
// in the first place — every generic word added to popularModules as
// an exemption is also a new magnet for the next unrelated package
// that happens to end in it.
var genericBaseNames = map[string]bool{
	"errors":     true,
	"protobuf":   true,
	"validator":  true,
	"validation": true,
	"decimal":    true,
	"common":     true,
}

// closestPopularMatch returns the popular module whose base name is
// within the allowed edit distance of name, or ("", false) if none is
// close enough to be suspicious. Exact matches don't count — a module
// that *is* the popular one isn't a typosquat of itself.
func closestPopularMatch(modPath, name string) (string, bool) {
	if len(name) < typoMinNameLen || genericBaseNames[toLower(name)] {
		return "", false
	}
	nameLen := utf8.RuneCountInString(name)
	best := ""
	bestDist := typoMaxDistance + 1
	for _, p := range popularModules {
		if p == modPath {
			return "", false // exact match on the real thing
		}
		pName := BaseName(p)
		if len(pName) < typoMinNameLen || genericBaseNames[toLower(pName)] {
			continue
		}
		// Edit distance is always >= the difference in rune length, so a
		// name/pName pair whose lengths already differ by more than
		// typoMaxDistance can never end up within the allowed distance —
		// skip the O(nameLen*len(pName)) Levenshtein DP entirely rather
		// than running it just to discard the result. This is a pure
		// performance guard (never changes which pair wins), but it's
		// also what keeps a single adversarially long candidate name (a
		// crafted or corrupted go.mod requirement) from costing
		// O(nameLen) work per popular module — found via a 10MB synthetic
		// name taking ~19s without this guard (run #109).
		pLen := utf8.RuneCountInString(pName)
		if diff := nameLen - pLen; diff > typoMaxDistance || diff < -typoMaxDistance {
			continue
		}
		d := Levenshtein(name, pName)
		allowed := typoMaxDistance
		if maxLen := max(len(name), len(pName)); maxLen < typoScaledMaxLen {
			allowed = 1
		}
		if d > 0 && d <= allowed && d < bestDist {
			best, bestDist = p, d
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// looksUnestablished reports whether status gives no reason to trust
// that a module is a real, maintained project — either it doesn't
// resolve at all, or it resolves but is thin enough to be indistinguishable
// from a name just registered to catch something (see CheckRequirement).
// Unknown (network trouble) counts as unestablished too: with no age
// data available, the collision check falls back to running rather than
// silently skipping.
func looksUnestablished(status ModuleStatus) bool {
	if status.Unknown || !status.Exists {
		return true
	}
	if status.VersionCount == 0 {
		// No tagged releases at all: @latest resolves to a pseudo-version
		// of the default branch tip, so LatestTime is the last commit
		// time, not a publish event. For an actively-maintained module
		// that never cuts tags, that's "recent" by definition no matter
		// how old the module actually is, so it carries no age signal —
		// unlike the VersionCount==1 case there's no tag to re-fetch a
		// trustworthy timestamp from either. Confirmed against a real
		// module: github.com/zmap/zcrypto (a decade-old dependency of
		// moby/moby and cilium/cilium, never tagged) always resolves to
		// a same-day pseudo-version, which made it permanently look
		// "unestablished" and mis-fired the high-severity name-collision
		// check against golang.org/x/crypto. Fall back to "not
		// unestablished" rather than treating an untrustworthy recency
		// signal as evidence.
		return false
	}
	return status.VersionCount == 1 && time.Since(status.LatestTime) < recentWindow
}

// CheckRequirement runs all heuristics against one go.mod requirement
// and returns any findings (zero, one, or more).
func CheckRequirement(req Requirement, proxy *ProxyClient) []Finding {
	status := proxy.Lookup(req.Path)
	return evaluateModuleStatus(req.Path, status, proxy)
}

// evaluateModuleStatus is CheckRequirement's finding logic, factored out
// so CheckTools can reuse it against a module path it resolved itself
// (via resolveToolPath) without a second, duplicate proxy fetch for the
// same path.
func evaluateModuleStatus(modPath string, status ModuleStatus, proxy *ProxyClient) []Finding {
	var findings []Finding

	switch {
	case status.Blocklisted:
		findings = append(findings, Finding{
			Module:   modPath,
			Severity: SeverityHigh,
			Reason:   "proxy-blocklisted-malicious",
			Detail:   "the Go module proxy has explicitly flagged this module as malicious and refuses to serve it — do not use it",
		})
		return findings
	case status.Unknown:
		// Network/proxy trouble — say nothing rather than a false finding.
	case status.Private:
		// The real `go` command never queries the public proxy for this
		// path either (GOPRIVATE/GONOPROXY covers it) — it fetches
		// directly from VCS instead. A miss on the public proxy is the
		// expected, correct outcome for a private module, not evidence
		// it's hallucinated.
	case !status.Exists:
		findings = append(findings, Finding{
			Module:   modPath,
			Severity: SeverityHigh,
			Reason:   "not-found",
			Detail:   "module does not resolve via the Go module proxy — if this came from AI-generated code, it may be a hallucinated import that was never real",
		})
	default:
		if status.VersionCount == 1 && time.Since(status.LatestTime) < recentWindow &&
			!proxy.IsMajorVersionBumpOfEstablished(modPath) {
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityWarn,
				Reason:   "new-and-thin",
				Detail:   "only one version published, in the last 30 days — could be a legitimate new project, but it's also the exact shape of a name registered to catch AI-hallucinated imports",
			})
		}
	}

	// Gated on age/existence (added run #55): an established package
	// (multiple versions, older than recentWindow) being a couple of
	// edits from a popular name is weak evidence on its own — real
	// typosquats are almost always both close-in-name *and* new, per
	// the run #52 decision log. Checking this unconditionally is what
	// produced the "gogo/protobuf"-style false positives that
	// genericBaseNames patches around one word at a time; requiring the
	// candidate to also look new or unresolved fixes the same class of
	// false positive structurally instead.
	if looksUnestablished(status) {
		if match, ok := closestPopularMatch(modPath, BaseName(modPath)); ok {
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityHigh,
				Reason:   "name-collision-risk",
				Detail:   "name is one or two edits away from well-known module " + match + " — verify this isn't a typosquat before trusting it",
			})
		}
	}

	return findings
}

// toolPrefixWalkCap bounds how many path-slash-separated prefixes
// resolveToolPath will query the proxy for. A `tool` directive names a
// *package* path, not necessarily a module path (e.g.
// golang.org/x/tools/cmd/stringer, whose module is golang.org/x/tools),
// so finding the owning module means walking prefixes from longest to
// shortest. Without a cap, an adversarially deep or long tool path (a
// crafted or corrupted go.mod, this tool's whole threat model — same
// class of concern as the run #109 unbounded-Levenshtein fix) could turn
// into an unbounded number of sequential network round-trips. 8 covers
// every real-world case seen (module paths rarely nest more than a
// handful of segments below the host) while keeping the worst case cheap.
const toolPrefixWalkCap = 8

// resolveToolPath finds the module that owns a tool directive's package
// import path, mirroring what `go` itself does: try the full path first,
// then progressively shorter slash-separated prefixes, until one exists
// (or is private, which the proxy can't distinguish from "doesn't
// exist" but which the caller must not treat as unresolved) on the
// module proxy. Returns the first prefix that resolves, its status (so
// the caller doesn't need to re-fetch it), and resolved=true — or
// ("", ModuleStatus{}, false) if no prefix resolves at all.
func resolveToolPath(pkgPath string, proxy *ProxyClient) (modPath string, status ModuleStatus, resolved bool) {
	segs := strings.Split(pkgPath, "/")
	attempts := len(segs)
	if attempts > toolPrefixWalkCap {
		attempts = toolPrefixWalkCap
	}
	for i := 0; i < attempts; i++ {
		prefix := strings.Join(segs[:len(segs)-i], "/")
		if prefix == "" {
			break
		}
		st := proxy.Lookup(prefix)
		if st.Exists || st.Private {
			return prefix, st, true
		}
	}
	return "", ModuleStatus{}, false
}

// CheckTools runs the same heuristics CheckRequirement runs, but against
// the package paths named by go.mod `tool` directives that aren't
// already covered by a `require` entry. A go.mod produced by `go get
// -tool` always pairs a `tool` line with a covering `require`, so those
// are already checked via the normal require scan; this only covers the
// gap a hand-written or AI-generated go.mod can leave — a `tool` line
// with no `require` behind it at all.
func CheckTools(tools []string, resolvedReqs []Requirement, proxy *ProxyClient) []Finding {
	seen := make(map[string]bool, len(tools))
	var deduped []string
	for _, t := range tools {
		if seen[t] {
			continue
		}
		seen[t] = true
		deduped = append(deduped, t)
	}

	var findings []Finding
	for _, tool := range deduped {
		covered := false
		for _, r := range resolvedReqs {
			if tool == r.Path || strings.HasPrefix(tool, r.Path+"/") {
				covered = true
				break
			}
		}
		if covered {
			continue
		}

		if modPath, status, ok := resolveToolPath(tool, proxy); ok {
			findings = append(findings, evaluateModuleStatus(modPath, status, proxy)...)
		} else {
			findings = append(findings, evaluateModuleStatus(tool, ModuleStatus{Exists: false}, proxy)...)
		}
	}
	return findings
}

// checkConcurrency caps how many CheckRequirement calls (each up to two
// sequential proxy HTTP round-trips) run at once. Found empirically (run
// #52): a real 250+ requirement go.mod (CockroachDB's) ran requirements
// fully sequentially and didn't finish within a minute. 16 is enough to
// turn that into a few seconds without hammering proxy.golang.org.
const checkConcurrency = 16

// CheckAll resolves replace directives against requirements and runs
// CheckRequirement over the result, concurrently (each call hits the
// module proxy over the network, so doing this sequentially doesn't
// scale to real dependency trees — see checkConcurrency). A requirement
// replaced with a local filesystem path is skipped entirely — there's
// no network-fetched code or meaningful alias name to check. A
// requirement replaced with another module is checked under that
// module's path, since that's what actually gets fetched and built.
// Findings are returned in the same order as reqs regardless of which
// goroutine finishes first, followed by any findings from tools (go.mod
// `tool` directive package paths not already covered by a requirement —
// see CheckTools).
func CheckAll(reqs []Requirement, reps []Replacement, tools []string, proxy *ProxyClient) []Finding {
	replacements := make(map[string]Replacement, len(reps))
	for _, r := range reps {
		replacements[r.Old] = r
	}

	var resolved []Requirement
	for _, r := range reqs {
		if rep, ok := replacements[r.Path]; ok {
			if rep.IsLocal() {
				continue
			}
			r.Path = rep.New
		}
		resolved = append(resolved, r)
	}

	results := make([][]Finding, len(resolved))
	sem := make(chan struct{}, checkConcurrency)
	var wg sync.WaitGroup
	for i, r := range resolved {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, r Requirement) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = CheckRequirement(r, proxy)
		}(i, r)
	}
	wg.Wait()

	var all []Finding
	for _, fs := range results {
		all = append(all, fs...)
	}
	all = append(all, CheckTools(tools, resolved, proxy)...)
	return all
}
