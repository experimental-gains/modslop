package main

import (
	"strconv"
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
	// floodedHistoryWindow gates the "version-flooded" finding: a module
	// can defeat the single-version recentWindow check simply by
	// publishing many versions before ever being referenced — see
	// evaluateModuleStatus's "version-flooded" case for the real
	// incident that motivated this (2026-09, the Graphalgo campaign's
	// gocommunity.io/orderedbtree published 16 versions between Jul 21
	// and Sep 2, all still well inside this window).
	// Wider than recentWindow on purpose: a burst of versions is itself
	// part of the evasion, so the same 30-day bar used for a single
	// version would be too easy to clear by tagging quickly.
	floodedHistoryWindow = 90 * 24 * time.Hour

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
// within the allowed edit distance of name, or an exact match of name at
// a *different* full path, or ("", "", false) if neither applies. exact
// reports which case fired, since the two carry different evidence and
// warrant different wording: a same-name-different-owner match isn't a
// typosquat (nothing is misspelled) — it's the impersonation technique
// documented in a real, disclosed, active Go supply-chain campaign
// (Bae & Yagemann, "Beyond Takedown: Measuring Malicious Go Module
// Persistence in the Wild", arXiv:2606.26291, 2026): attackers republish
// a popular module's exact name under a new, attacker-controlled owner
// rather than misspelling it (their worked example: the real
// portapps/drawio-portable re-uploaded verbatim as
// anotherteriy/drawio-portable). Before this, closestPopularMatch
// required d > 0, so an exact-name clone under a different owner was
// treated the same as "this is the real module" instead of flagged —
// confirmed live: closestPopularMatch("github.com/totallyfakeorg/zerolog",
// "zerolog") returned no match despite rs/zerolog being in
// popularModules. The exact-name case is reported directly, ahead of the
// edit-distance scan below, since identical-name evidence is at least as
// strong as a one- or two-edit near miss.
func closestPopularMatch(modPath, name string) (match string, exact bool, ok bool) {
	if len(name) < typoMinNameLen || genericBaseNames[toLower(name)] {
		return "", false, false
	}
	nameLen := utf8.RuneCountInString(name)
	best := ""
	bestDist := typoMaxDistance + 1
	for _, p := range popularModules {
		if p == modPath {
			return "", false, false // exact match on the real thing
		}
		pName := BaseName(p)
		if len(pName) < typoMinNameLen || genericBaseNames[toLower(pName)] {
			continue
		}
		if pName == name {
			return p, true, true
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
		// d can no longer be 0 here — the pName == name case above already
		// returned. Left implicit rather than asserting it, since gremlins
		// confirmed a `d > 0 &&` guard on this line is unreachable/dead
		// (LIVED, equivalent mutant) once that early return exists.
		d := Levenshtein(name, pName)
		allowed := typoMaxDistance
		if maxLen := max(len(name), len(pName)); maxLen < typoScaledMaxLen {
			allowed = 1
		}
		if d <= allowed && d < bestDist {
			best, bestDist = p, d
		}
	}
	if best == "" {
		return "", false, false
	}
	return best, false, true
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
	if status.VersionCount == 1 {
		return time.Since(status.LatestTime) < recentWindow
	}
	// Multiple versions don't make a module trustworthy by themselves if
	// every one of them was published recently — see the "version-
	// flooded" case in evaluateModuleStatus. An established project has
	// some real track record older than floodedHistoryWindow; a name
	// registered purely to catch something doesn't, however many
	// versions were tagged to make it look otherwise.
	return !status.EarliestTime.IsZero() && time.Since(status.EarliestTime) < floodedHistoryWindow
}

// looksUnestablishedForImpersonation is looksUnestablished's counterpart
// for the exact-name-collision check only. looksUnestablished's
// VersionCount==0 case deliberately treats an untagged module as "not
// unestablished" (see its own comment — needed to stop a real false
// positive on github.com/zmap/zcrypto, an old, legitimately-maintained,
// never-tagged module whose base name happens to be a *near* miss of
// "crypto"). That exemption is safe for the near-miss check, which
// exists to catch typos and needs real age evidence to avoid drowning
// users in false positives on generic near-collisions. It is not safe
// for an *exact* name match: identical name, different owner is itself
// high-confidence impersonation evidence (see the "Beyond Takedown"
// citation on closestPopularMatch) that doesn't depend on age at all —
// but VersionCount==0's blanket exemption meant a real attacker could
// evade this tool's own highest-severity check entirely just by never
// tagging the malicious module. Confirmed live/via fakeProxy
// (TestCheckRequirement_ExactNameCloneOfUntaggedPopular) that an
// untagged github.com/totallyfakeorg/zerolog produced zero findings at
// all before this fix — the exact impersonation shape this tool exists
// to catch, sailing through silently.
func looksUnestablishedForImpersonation(status ModuleStatus) bool {
	if status.VersionCount == 0 {
		return true
	}
	return looksUnestablished(status)
}

// CheckRequirement runs all heuristics against one go.mod requirement
// and returns any findings (zero, one, or more).
func CheckRequirement(req Requirement, proxy *ProxyClient) []Finding {
	status := proxy.Lookup(req.Path)
	return evaluateModuleStatus(req.Path, req.Version, status, proxy)
}

// evaluateModuleStatus is CheckRequirement's finding logic, factored out
// so CheckTools can reuse it against a module path it resolved itself
// (via resolveToolPath) without a second, duplicate proxy fetch for the
// same path. version is the specific version actually being pulled in
// (used only by the retraction check below); CheckTools passes "" since a
// `tool` directive names no version, and retraction() treats "" as
// nothing to check.
func evaluateModuleStatus(modPath, version string, status ModuleStatus, proxy *ProxyClient) []Finding {
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
		versionMissing := false
		if version != "" {
			if exists, unknown := proxy.VersionExists(modPath, version); !unknown && !exists {
				versionMissing = true
				findings = append(findings, Finding{
					Module:   modPath,
					Severity: SeverityHigh,
					Reason:   "version-not-found",
					Detail:   "the module exists, but this exact version was never published to the Go module proxy — if this came from AI-generated code, it may be a hallucinated version number for an otherwise-real module",
				})
			}
		}
		switch {
		case versionMissing:
			// The module-level new-and-thin/version-flooded heuristics
			// below answer "does this module look freshly squatted," which
			// is a different question from "does this exact pinned version
			// exist at all" and would just add a confusing, redundant
			// warning on top of the much clearer version-not-found finding
			// above.
		case status.VersionCount == 1 && time.Since(status.LatestTime) < recentWindow &&
			!proxy.IsMajorVersionBumpOfEstablished(modPath):
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityWarn,
				Reason:   "new-and-thin",
				Detail:   "only one version published, in the last 30 days — could be a legitimate new project, but it's also the exact shape of a name registered to catch AI-hallucinated imports",
			})
		case status.VersionCount > 1 && !status.EarliestTime.IsZero() && time.Since(status.EarliestTime) < floodedHistoryWindow &&
			!proxy.IsMajorVersionBumpOfEstablished(modPath):
			// Real incident (2026-09, the Graphalgo Terraform/npm
			// campaign's Go expansion): gocommunity.io/orderedbtree
			// published 16 versions over about six weeks, all with
			// realistic-looking version bumps — specifically defeating
			// the VersionCount==1 gate above. A module's whole tagged
			// history still starting inside floodedHistoryWindow is
			// itself the suspicious shape, regardless of how many
			// versions got tagged along the way.
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityWarn,
				Reason:   "version-flooded",
				Detail:   "multiple versions published, but the oldest one is still less than 90 days old — publishing many versions quickly is one way to defeat a single-version freshness check; could be a legitimate fast-moving new project, but a real 2026 Go supply-chain campaign used exactly this pattern",
			})
		}
	}

	// Independent of the switch above (a retracted version can be old,
	// established, and by every other measure trustworthy — retraction
	// is the maintainer's own explicit "don't use this exact version"
	// signal, not a freshness or existence problem). retraction() already
	// no-ops when LatestModBody is empty (Blocklisted/Unknown/Private/
	// !Exists never populate it, see ProxyClient.Lookup) or version is ""
	// (CheckTools has none to check), so this doesn't need its own status
	// guard. See retract.go for why it's the *latest* version's go.mod,
	// not the checked version's own, that carries the retract directive.
	if rationale, retracted := retraction(status.LatestModBody, version); retracted {
		explain := "no rationale was given in the retract directive"
		if rationale != "" {
			explain = "rationale given: " + strconv.Quote(rationale)
		}
		findings = append(findings, Finding{
			Module:   modPath,
			Severity: SeverityHigh,
			Reason:   "retracted",
			Detail:   "this exact version is covered by a `retract` directive in the module's own go.mod (" + explain + ") — retraction is advisory only, so proxy.golang.org and a plain `go install`/`go get` still serve it fine, but it's the maintainer's own explicit signal not to use this version",
		})
	}

	// Same independence rationale as retraction above, and reusing the
	// same status.LatestModBody fetch: a module can be deprecated
	// (superseded by a different import path) regardless of how
	// established or trustworthy it otherwise looks — this is exactly the
	// shape of mistake stale LLM training data produces, suggesting an
	// old, real, still-installable import path (e.g.
	// github.com/golang/protobuf) that the ecosystem has since moved off
	// of (google.golang.org/protobuf). deprecation() already no-ops on an
	// empty LatestModBody, so this needs no extra status guard either.
	// Severity is Warn, not High: unlike retraction (a version-specific
	// "don't use this" signal) or the malicious/typosquat checks above,
	// a deprecated module is real and legitimate, just superseded — worth
	// flagging, not the same alarm level as a supply-chain risk.
	if message, deprecated := deprecation(status.LatestModBody); deprecated {
		findings = append(findings, Finding{
			Module:   modPath,
			Severity: SeverityWarn,
			Reason:   "deprecated",
			Detail:   "the module's own go.mod deprecates it (" + strconv.Quote(message) + ") — this still resolves and installs fine, but it's the maintainer's own signal that the module has been superseded; worth double-checking this wasn't suggested from stale training data",
		})
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
	if match, exact, ok := closestPopularMatch(modPath, BaseName(modPath)); ok {
		switch {
		case exact && looksUnestablishedForImpersonation(status):
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityHigh,
				Reason:   "name-collision-exact",
				Detail:   "name is identical to well-known module " + match + " but this is a different, unestablished path — republishing a popular module's exact name under a new owner is a real, disclosed Go supply-chain impersonation technique; verify this isn't a malicious clone before trusting it",
			})
		case !exact && looksUnestablished(status):
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
//
// declaredReqs must be the *pre-replace* requirement paths (what CheckAll
// receives as its own reqs argument), not the post-replace resolved ones.
// A `tool` directive names an import path, and a replace directive never
// changes the import path packages under the replaced module are
// referenced by — only where the code backing that path comes from (see
// Replacement's doc comment and go.dev/ref/mod#go-mod-file-replace) — so
// a `tool` line paired with a `require`+`replace` pair for the same
// module still declares the *original* path, never the replacement's.
// Matching against resolved paths instead (this function's shape before
// this comment) made every such tool directive look uncovered, sending
// it through resolveToolPath under the stale pre-replace name instead of
// skipping it as already handled. Confirmed live with a concrete false
// positive this produced: `require example.com/oldtool v0.0.0` (a
// placeholder path never published, the normal shape for a full-rename
// fork) + `replace example.com/oldtool => github.com/real-org/realtool
// v1.2.3` (a real, clean, established module — already correctly
// resolved with zero findings via the ordinary require+replace check) +
// `tool example.com/oldtool/cmd/gen` produced a spurious high-severity
// "not-found" on the tool directive, because example.com/oldtool never
// resolves on its own and resolvedReqs no longer contains that path
// (CheckAll had already rewritten it to the replacement's path). Matching
// against the pre-replace path here makes the tool line register as
// covered, same as the require-level check already treats it — and, for
// a *local* replace (require+replace to a filesystem path, where the
// require-level check is itself skipped entirely — see CheckAll's own
// comment), this now consistently skips the tool line too instead of
// resolving it against public infrastructure under a name whose real
// backing code was never fetched from there at all.
func CheckTools(tools []string, declaredReqs []Requirement, proxy *ProxyClient) []Finding {
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
		for _, r := range declaredReqs {
			if tool == r.Path || strings.HasPrefix(tool, r.Path+"/") {
				covered = true
				break
			}
		}
		if covered {
			continue
		}

		if modPath, status, ok := resolveToolPath(tool, proxy); ok {
			findings = append(findings, evaluateModuleStatus(modPath, "", status, proxy)...)
		} else {
			findings = append(findings, evaluateModuleStatus(tool, "", ModuleStatus{Exists: false}, proxy)...)
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
// see CheckTools, which is deliberately handed the original pre-replace
// reqs here, not the post-replace resolved list — a `tool` directive
// names the module's declared, unreplaced path, and CheckTools's own
// doc comment explains the false positive that resulted from matching
// against resolved paths instead).
func CheckAll(reqs []Requirement, reps []Replacement, tools []string, proxy *ProxyClient) []Finding {
	replacements := make(map[string][]Replacement, len(reps))
	for _, r := range reps {
		replacements[r.Old] = append(replacements[r.Old], r)
	}

	var resolved []Requirement
	for _, r := range reqs {
		if rep, ok := selectReplace(replacements[r.Path], r.Version); ok {
			if rep.IsLocal() {
				continue
			}
			r.Path = rep.New
			// A remote-target replace always pins an exact version of the
			// replacement module (go.dev/ref/mod#go-mod-file-replace); use
			// it in place of the original requirement's version, which
			// names a version of a different module once replaced — see
			// parseReplaceLine's NewVersion doc comment. NewVersion is only
			// ever "" here for a malformed go.mod missing the
			// otherwise-mandatory new-side version, in which case falling
			// back to the stale original version is still strictly better
			// than the alternative of checking retraction against a
			// version string that was never a version of this module at
			// all.
			if rep.NewVersion != "" {
				r.Version = rep.NewVersion
			}
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
	all = append(all, CheckTools(tools, reqs, proxy)...)
	return all
}
