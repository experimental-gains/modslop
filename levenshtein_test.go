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
		{"abc", "", 3},
		{"GIN", "gin", 0}, // case-insensitive
		{"kitten", "sitting", 3},
	}
	for _, c := range cases {
		if got := Levenshtein(c.a, c.b); got != c.want {
			t.Errorf("Levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestToLower_ASCIIBoundaryChars pins toLower's `c >= 'A' && c <=
// 'Z'` range check at its two edges (found LIVED by mutation testing,
// run #127: TestLevenshtein's only case-insensitivity case, "GIN", has
// no letter at either the 'A' or 'Z' end of the range).
func TestToLower_ASCIIBoundaryChars(t *testing.T) {
	if got := toLower("Apple"); got != "apple" {
		t.Errorf("toLower(%q) = %q, want %q", "Apple", got, "apple")
	}
	if got := toLower("ZEBRA"); got != "zebra" {
		t.Errorf("toLower(%q) = %q, want %q", "ZEBRA", got, "zebra")
	}
}

// TestLevenshtein_AsymmetricLengthExercisesFullInitRow pins the DP
// table's init loop, `for j := 0; j <= lb; j++` (found LIVED by
// mutation testing, run #127: every existing case keeps both strings
// short and close in length, never exercising prev[lb] itself — a
// mutated `j < lb` leaves prev[lb] at its zero value, corrupting the
// deletion cost used to fill the last column of the first DP row).
func TestLevenshtein_AsymmetricLengthExercisesFullInitRow(t *testing.T) {
	if got := Levenshtein("cat", "caterpillar"); got != 8 {
		t.Errorf("Levenshtein(cat, caterpillar) = %d, want 8", got)
	}
}
