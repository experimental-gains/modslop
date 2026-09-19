package main

import "testing"

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"gin", "gin", 0},
		{"gin", "giin", 1},
		{"gin", "gine", 1},
		{"cobra", "cobrra", 1},
		{"logrus", "logrusx", 1},
		{"", "abc", 3},
		{"GIN", "gin", 0}, // case-insensitive
		{"kitten", "sitting", 3},
	}
	for _, c := range cases {
		if got := Levenshtein(c.a, c.b); got != c.want {
			t.Errorf("Levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
