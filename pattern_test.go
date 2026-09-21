package main

import "testing"

func TestSplitPatterns(t *testing.T) {
	cases := map[string][]string{
		"":                            nil,
		"corp.example.invalid/*":      {"corp.example.invalid/*"},
		"a.example/*,b.example/*":     {"a.example/*", "b.example/*"},
		" a.example/* , b.example/* ": {"a.example/*", "b.example/*"},
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
