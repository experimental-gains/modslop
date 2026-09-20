package main

import "time"

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

// closestPopularMatch returns the popular module whose base name is
// within the allowed edit distance of name, or ("", false) if none is
// close enough to be suspicious. Exact matches don't count — a module
// that *is* the popular one isn't a typosquat of itself.
func closestPopularMatch(modPath, name string) (string, bool) {
	if len(name) < typoMinNameLen {
		return "", false
	}
	best := ""
	bestDist := typoMaxDistance + 1
	for _, p := range popularModules {
		if p == modPath {
			return "", false // exact match on the real thing
		}
		pName := BaseName(p)
		if len(pName) < typoMinNameLen {
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

// CheckRequirement runs all heuristics against one go.mod requirement
// and returns any findings (zero, one, or more).
func CheckRequirement(req Requirement, proxy *ProxyClient) []Finding {
	var findings []Finding

	if match, ok := closestPopularMatch(req.Path, BaseName(req.Path)); ok {
		findings = append(findings, Finding{
			Module:   req.Path,
			Severity: SeverityHigh,
			Reason:   "name-collision-risk",
			Detail:   "name is one or two edits away from well-known module " + match + " — verify this isn't a typosquat before trusting it",
		})
	}

	status := proxy.Lookup(req.Path)
	switch {
	case status.Unknown:
		// Network/proxy trouble — say nothing rather than a false finding.
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

	return findings
}

// CheckAll resolves replace directives against requirements and runs
// CheckRequirement over the result. A requirement replaced with a local
// filesystem path is skipped entirely — there's no network-fetched code
// or meaningful alias name to check. A requirement replaced with another
// module is checked under that module's path, since that's what actually
// gets fetched and built.
func CheckAll(reqs []Requirement, reps []Replacement, proxy *ProxyClient) []Finding {
	replacements := make(map[string]Replacement, len(reps))
	for _, r := range reps {
		replacements[r.Old] = r
	}

	var all []Finding
	for _, r := range reqs {
		if rep, ok := replacements[r.Path]; ok {
			if rep.IsLocal() {
				continue
			}
			r.Path = rep.New
		}
		all = append(all, CheckRequirement(r, proxy)...)
	}
	return all
}
