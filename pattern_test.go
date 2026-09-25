package main

import "testing"

// TestSplitPatterns checks that splitPatterns only splits on comma and
// drops genuinely empty entries, without trimming surrounding whitespace
// from the patterns it keeps — real `go`'s own
// golang.org/x/mod/module.MatchPrefixPatterns never trims a glob either,
// so a leading/trailing space around a pattern is part of the glob, not
// noise to clean up. A version of this test that expected trimming used
// to lock in a real divergence from `go`'s behavior; see splitPatterns'
// doc comment and TestSplitPatterns_LeadingSpaceBreaksMatch below.
func TestSplitPatterns(t *testing.T) {
	cases := map[string][]string{
		"":                            nil,
		"corp.example.invalid/*":      {"corp.example.invalid/*"},
		"a.example/*,b.example/*":     {"a.example/*", "b.example/*"},
		" a.example/* , b.example/* ": {" a.example/* ", " b.example/* "},
		"a.example/*,,b.example/*":    {"a.example/*", "b.example/*"},
	}
	for in, want := range cases {
		got := splitPatterns(in)
		if len(got) != len(want) {
			t.Errorf("splitPatterns(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("splitPatterns(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}

// TestSplitPatterns_LeadingSpaceBreaksMatch is the regression case for the
// real bug goproxycheck v0.1.23 found and fixed first (live differential
// testing against golang.org/x/mod and `go mod download -x`): a pattern
// with a leading space (as produced by a comma-separated list written
// with ", " for readability, e.g. GONOPROXY="nomatch/*, golang.org/x/text")
// must NOT match the unspaced module path, exactly like real `go` — so
// modslop must not silently skip auditing that module as "private".
func TestSplitPatterns_LeadingSpaceBreaksMatch(t *testing.T) {
	patterns := splitPatterns("nomatch/*, golang.org/x/text")
	if matchesAnyPattern("golang.org/x/text", patterns) {
		t.Errorf("matchesAnyPattern matched %q against patterns %v, but real `go` does not match a glob with a leading space against an unspaced module path", "golang.org/x/text", patterns)
	}
}

func TestMatchesAnyPattern(t *testing.T) {
	patterns := []string{"corp.example.invalid/*", "other.example.invalid/internal/*"}

	cases := map[string]bool{
		"corp.example.invalid/internal/widget":    true,
		"corp.example.invalid/anything":           true,
		"other.example.invalid/internal/deep/pkg": true,
		"other.example.invalid/public/pkg":        false,
		"github.com/sirupsen/logrus":              false,
		"corp.example.invalid":                    false, // pattern needs at least one more segment
	}
	for path, want := range cases {
		if got := matchesAnyPattern(path, patterns); got != want {
			t.Errorf("matchesAnyPattern(%q, %v) = %v, want %v", path, patterns, got, want)
		}
	}
}

func TestMatchesAnyPattern_NoPatternsMatchesNothing(t *testing.T) {
	if matchesAnyPattern("github.com/sirupsen/logrus", nil) {
		t.Error("expected no match with an empty pattern list")
	}
}
