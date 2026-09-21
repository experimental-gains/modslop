package main

import (
	"sync"
	"time"
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
	var findings []Finding

	status := proxy.Lookup(req.Path)
	switch {
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
			Module:   req.Path,
			Severity: SeverityHigh,
			Reason:   "not-found",
			Detail:   "module does not resolve via the Go module proxy — if this came from AI-generated code, it may be a hallucinated import that was never real",
		})
	default:
		if status.VersionCount == 1 && time.Since(status.LatestTime) < recentWindow {
			findings = append(findings, Finding{
				Module:   req.Path,
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
		if match, ok := closestPopularMatch(req.Path, BaseName(req.Path)); ok {
			findings = append(findings, Finding{
				Module:   req.Path,
				Severity: SeverityHigh,
				Reason:   "name-collision-risk",
				Detail:   "name is one or two edits away from well-known module " + match + " — verify this isn't a typosquat before trusting it",
			})
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
// goroutine finishes first.
func CheckAll(reqs []Requirement, reps []Replacement, proxy *ProxyClient) []Finding {
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
	return all
}
