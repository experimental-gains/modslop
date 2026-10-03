package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// FuzzParseGoModRequire checks ParseGoMod's require-line parsing against
// golang.org/x/mod/modfile.ParseLax — the same oracle goproxycheck's and
// goprivaudit's fuzz suites already diff against for their own hand-rolled
// go.mod parsing. This is the first oracle-diff fuzz pass on modslop's own
// hand-rolled parser (gomod.go, kept dependency-free deliberately per its
// doc comment). The parser has already had two real bugs found against it
// by hand (a no-space-before-paren block-opener miss, a quoted-local-
// replace-path-with-a-space misclassification) — a fuzzer searches the
// same require-line syntax space exhaustively instead of one case at a
// time.
func FuzzParseGoModRequire(f *testing.F) {
	seeds := []string{
		"github.com/foo/bar v1.0.0",
		"github.com/foo/bar v1.0.0 // indirect",
		`"github.com/foo/bar" v1.0.0`,
		"github.com/foo/bar\tv1.0.0",
		`"github.com/foo/bar" v1.0.0 // indirect`,
		"github.com/foo/bar v1.0.0//no-space-comment",
		`"foo\"bar" v1.0.0`,
		"(",
		")",
		"0.0 v0",
		// A module path that legitimately contains "indirect" as an
		// ordinary substring, with no trailing comment at all — tripped
		// the old oracle below (bare strings.Contains(..., "indirect")),
		// which mistook this for a leaked "// indirect" comment marker
		// even though golang.org/x/mod/modfile itself reports
		// Indirect=false for it. Found live via this fuzzer; left
		// unfixed for several runs as a known, out-of-scope gap before
		// this fix.
		"github.com/foo/0.0indirect v1.0.0",
		// Same false-positive shape in the version field instead of the
		// path.
		"github.com/foo/bar v1.0.0-0.0indirect",
		// A real indirect comment with irregular spacing, and a trailing
		// comment that isn't "indirect" at all — both must still parse
		// to a bare path+version with no comment residue leaked, same as
		// the canonical "// indirect" seed above.
		"github.com/foo/bar v1.0.0 //    indirect",
		"github.com/foo/bar v1.0.0 // direct",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, rest string) {
		// Keep the fuzzed text confined to a single require line: a
		// literal newline would turn it into multi-line input (e.g. a
		// block), no longer an apples-to-apples single-line comparison.
		if strings.ContainsAny(rest, "\n\r") {
			return
		}
		if !utf8.ValidString(rest) {
			// A raw invalid-UTF-8 byte inside a quoted token makes
			// golang.org/x/mod/modfile's own lexer substitute the
			// Unicode replacement character when unquoting, which
			// ParseGoMod's leadingQuotedString doesn't replicate (byte-
			// for-byte copy instead) — found via this fuzzer on the
			// replace side below. Excluded rather than "fixed" here: any
			// resulting module path still fails module.CheckPath either
			// way (invalid UTF-8 is one of its rejection reasons,
			// confirmed live), so no real, working go.mod could ever
			// hand ParseGoMod a require line this divergence would
			// affect.
			return
		}

		content := "module test.example/mod\n\ngo 1.24\n\nrequire " + rest + "\n"

		mf, err := modfile.ParseLax("go.mod", []byte(content), nil)
		if err != nil || len(mf.Require) != 1 {
			// Not unambiguously "exactly one require line" per the
			// canonical parser (invalid syntax, zero entries, or the
			// fuzzed text itself smuggled in a second directive) — no
			// single oracle value to check against.
			return
		}
		wantPath := mf.Require[0].Mod.Path
		wantVersion := mf.Require[0].Mod.Version
		wantIndirect := mf.Require[0].Indirect
		if module.CheckPath(wantPath) != nil {
			// A real go.mod can never carry this as a require path: `go
			// build`/`go list -m` themselves refuse to load a module
			// whose path fails this exact check (e.g. the empty string,
			// or "v0" with no dot in its first path element), so no
			// working repo could ever hand this line to ParseGoMod in
			// practice. Confirmed live via module.CheckPath.
			return
		}

		reqs, reps, _, _, _, _, _, err := ParseGoMod(content)
		if err != nil {
			t.Fatalf("ParseGoMod errored on %q but golang.org/x/mod/modfile parsed one require line (path=%q version=%q): %v", content, wantPath, wantVersion, err)
		}
		if len(reps) != 0 {
			t.Fatalf("ParseGoMod(%q) found a replace directive from a require-only line: %+v", content, reps)
		}
		if len(reqs) != 1 {
			t.Fatalf("ParseGoMod(%q) found %d requirements, want exactly 1 (per golang.org/x/mod/modfile): %+v", content, len(reqs), reqs)
		}
		got := reqs[0]
		// Compare versions in canonical semver form, not as raw strings:
		// modfile.ParseLax itself canonicalizes a shortened-but-valid
		// semver like "v0" to "v0.0.0" when populating Mod.Version
		// (confirmed live), but ParseGoMod's own doc comment only
		// promises to "extract require ... entries", not to reimplement
		// semver canonicalization for a field CheckRequirement never
		// even reads (grep-verified against check.go) — comparing raw
		// strings here would fail the test over a cosmetic difference,
		// not a real extraction bug. Canonicalizing both sides still
		// catches a genuine extraction bug (wrong token, wrong split)
		// since semver.Canonical("") stays "" for non-semver garbage.
		if got.Path != wantPath || semver.Canonical(got.Version) != semver.Canonical(wantVersion) {
			t.Errorf("ParseGoMod(%q) = {%q %q}, want {%q %q} (per golang.org/x/mod/modfile)", content, got.Path, got.Version, wantPath, wantVersion)
		}
		// ParseGoMod's Requirement doesn't track Indirect, but it must
		// still strip a trailing line comment (most commonly "//
		// indirect", but any comment — "// direct", an irregularly
		// spaced "//    indirect", etc. — gets stripped identically by
		// stripComment before parseRequireLine ever runs) down to the
		// bare path+version, rather than leaving it attached to either
		// field.
		//
		// This used to be checked with a bare strings.Contains(...,
		// "indirect"), which is the same category of bug this whole
		// fuzzer exists to catch elsewhere: a substring match standing
		// in for a real token check. "indirect" can appear in a module
		// path or version as entirely ordinary text with no comment
		// involved at all (module.CheckPath and semver impose no
		// restriction against it) — e.g. a require line of
		// "github.com/foo/0.0indirect v1.0.0" is valid, un-commented,
		// and reports Indirect=false from golang.org/x/mod/modfile
		// itself, yet the substring check flagged it as a leak anyway.
		// Found live via this fuzzer, confirmed to still reproduce on
		// the pre-fix oracle via a git worktree at this commit.
		//
		// A leaked comment, by contrast, always drags a literal "//"
		// into the field with it. Neither a valid module path
		// (module.CheckPath rejects an empty path element, which is
		// what an embedded "//" produces) nor a valid semver version (no
		// "/" at all) can ever contain that sequence on its own, so
		// checking for "//" catches a genuine leak — of any trailing
		// comment, not just one that says "indirect" — without flagging
		// legitimate text that merely happens to contain the word.
		_ = wantIndirect
		if strings.Contains(got.Path, "//") || strings.Contains(got.Version, "//") {
			t.Errorf("ParseGoMod(%q) leaked a trailing comment into a field: %+v", content, got)
		}
	})
}

// FuzzParseGoModReplace checks ParseGoMod's replace-line parsing against
// golang.org/x/mod/modfile.Parse (the strict parser — ParseLax deliberately
// never populates Replace at all, since replace/exclude directives are
// ignored by the real go command outside the main module; confirmed live
// against a minimal go.mod before writing this fuzzer). Restricted to
// inputs the strict parser accepts, same skip-on-oracle-rejection pattern
// FuzzModuleFromGoMod (goproxycheck) and this file's own FuzzParseGoModRequire
// use.
func FuzzParseGoModReplace(f *testing.F) {
	seeds := []string{
		"github.com/foo/bar => github.com/baz/qux v1.0.0",
		"github.com/foo/bar => ../local",
		`github.com/foo/bar => "../local mod"`,
		`"github.com/foo/bar" => github.com/baz/qux v1.0.0`,
		"github.com/foo/bar v1.0.0 => github.com/baz/qux v2.0.0",
		"github.com/foo/bar => /abs/local/path",
		"github.com/foo/bar=>github.com/baz/qux v1.0.0",
		"\"\xd9\"=> 0 v0",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, rest string) {
		if strings.ContainsAny(rest, "\n\r") {
			return
		}
		if !utf8.ValidString(rest) {
			// Same invalid-UTF-8 exclusion as FuzzParseGoModRequire above
			// — found here first (both an Old and, separately, a local
			// New path containing a raw invalid byte). The Old side must
			// equal a require entry's Path to ever be looked up by
			// CheckAll, which (per the require fuzzer's filter) can never
			// contain invalid UTF-8 in practice; the New side only feeds
			// a check when it's a real remote module path (same
			// CheckPath constraint) — when it's a local filesystem path
			// instead, CheckAll skips it via IsLocal() before its exact
			// bytes are ever compared to anything, confirmed by reading
			// check.go.
			return
		}

		content := "module test.example/mod\n\ngo 1.24\n\nreplace " + rest + "\n"

		mf, err := modfile.Parse("go.mod", []byte(content), nil)
		if err != nil || len(mf.Replace) != 1 {
			return
		}
		wantOld := mf.Replace[0].Old.Path
		wantNew := mf.Replace[0].New.Path
		if module.CheckPath(wantOld) != nil {
			// The replace directive's left side is always a reference to
			// an existing require entry (CheckAll matches it by exact
			// Old-path string against Requirement.Path, itself always
			// CheckPath-valid per the require fuzzer's own filter above),
			// never a local filesystem path — so an Old that fails
			// module.CheckPath (confirmed live, e.g. a raw invalid-UTF-8
			// byte from a quoted string) could never correspond to any
			// requirement a real go.mod could have, and could only ever
			// cause CheckAll's map lookup to miss (fail closed, not
			// misattribute to a different real dependency).
			return
		}

		reqs, reps, _, _, _, _, _, err := ParseGoMod(content)
		if err != nil {
			t.Fatalf("ParseGoMod errored on %q but golang.org/x/mod/modfile parsed one replace line (old=%q new=%q): %v", content, wantOld, wantNew, err)
		}
		if len(reqs) != 0 {
			t.Fatalf("ParseGoMod(%q) found a require entry from a replace-only line: %+v", content, reqs)
		}
		if len(reps) != 1 {
			t.Fatalf("ParseGoMod(%q) found %d replace directives, want exactly 1 (per golang.org/x/mod/modfile): %+v", content, len(reps), reps)
		}
		got := reps[0]
		if got.Old != wantOld || got.New != wantNew {
			t.Errorf("ParseGoMod(%q) = {Old:%q New:%q}, want {Old:%q New:%q} (per golang.org/x/mod/modfile)", content, got.Old, got.New, wantOld, wantNew)
		}
	})
}
