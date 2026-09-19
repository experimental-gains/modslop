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
	recentWindow    = 30 * 24 * time.Hour
	typoMaxDistance = 2
	typoMinNameLen  = 4
)

// closestPopularMatch returns the popular module whose base name is
// within typoMaxDistance edits of name, or ("", false) if none is
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
		d := Levenshtein(name, pName)
		if d > 0 && d <= typoMaxDistance && d < bestDist {
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
