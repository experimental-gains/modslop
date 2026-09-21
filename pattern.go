package main

import (
	"path"
	"strings"
)

// matchesPrefixPattern reports whether modulePath is covered by pattern,
// mirroring golang.org/x/mod/module.MatchPrefixPatterns exactly (the same
// algorithm the real `go` command applies to GOPRIVATE/GONOPROXY/
// GONOSUMDB, see `go help goproxy`): count the path separators in pattern
// to find how many leading segments of modulePath to keep as a prefix,
// then run a single path.Match of pattern against that whole prefix — not
// a per-segment path.Match, which silently breaks backslash-escaped
// separators and bracket expressions containing "/" (both valid
// path.Match glob syntax the real go command still honors correctly).
// Ported from goprivaudit's pattern.go, which reached this exact
// implementation after a fuzz pass (diffed against the real x/mod oracle)
// found and fixed the per-segment divergence — reused here rather than
// re-derived, and kept dependency-free for the same reason goprivaudit
// is: x/mod stays a test-only dependency (see fuzz_test.go), not a
// runtime one.
func matchesPrefixPattern(pattern, modulePath string) bool {
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		return false
	}
	n := strings.Count(pattern, "/")
	prefix := modulePath
	for i := 0; i < len(modulePath); i++ {
		if modulePath[i] == '/' {
			if n == 0 {
				prefix = modulePath[:i]
				break
			}
			n--
		}
	}
	if n > 0 {
		return false // modulePath has fewer segments than pattern requires
	}
	ok, err := path.Match(pattern, prefix)
	return err == nil && ok
}

// matchesAnyPattern reports whether modulePath is covered by any pattern in
// a GOPRIVATE/GONOPROXY-style pattern list.
func matchesAnyPattern(modulePath string, patterns []string) bool {
	for _, p := range patterns {
		if matchesPrefixPattern(p, modulePath) {
			return true
		}
	}
	return false
}

// splitPatterns splits a GOPRIVATE/GONOPROXY-style comma separated env
// value into its individual patterns, dropping empties.
func splitPatterns(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
