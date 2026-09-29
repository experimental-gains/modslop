package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGoModBlock(t *testing.T) {
	content := `module example.com/foo

go 1.24

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/pkg/errors v0.9.1 // indirect
)

require golang.org/x/net v0.20.0
`
	reqs, reps, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []Requirement{
		{Path: "github.com/gin-gonic/gin", Version: "v1.9.1"},
		{Path: "github.com/pkg/errors", Version: "v0.9.1"},
		{Path: "golang.org/x/net", Version: "v0.20.0"},
	}
	if len(reqs) != len(want) {
		t.Fatalf("got %d reqs, want %d: %+v", len(reqs), len(want), reqs)
	}
	for i, r := range reqs {
		if r != want[i] {
			t.Errorf("req %d: got %+v, want %+v", i, r, want[i])
		}
	}
	if len(reps) != 0 {
		t.Errorf("expected no replace directives, got %+v", reps)
	}
}

// TestParseGoModBlockNoSpaceBeforeParen covers a real go.mod grammar
// gap: go.mod's own lexer (golang.org/x/mod/modfile, confirmed against
// `go mod edit -json`) doesn't require whitespace between the
// require/replace keyword and its opening "(" — gofmt just always
// produces one. A hand-written go.mod using "require(" (never
// gofmt'd) must not silently skip the block.
func TestParseGoModBlockNoSpaceBeforeParen(t *testing.T) {
	content := `module example.com/foo

require(
	github.com/gin-gonic/gin v1.9.1
)

replace(
	github.com/gin-gonic/gin => github.com/local/gin v1.9.1
)
`
	reqs, reps, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0] != (Requirement{Path: "github.com/gin-gonic/gin", Version: "v1.9.1"}) {
		t.Errorf("got reqs %+v, want one gin requirement", reqs)
	}
	if len(reps) != 1 || reps[0] != (Replacement{Old: "github.com/gin-gonic/gin", New: "github.com/local/gin", NewVersion: "v1.9.1"}) {
		t.Errorf("got reps %+v, want one gin replacement", reps)
	}
}

func TestParseGoModReplace(t *testing.T) {
	content := `module example.com/foo

require (
	micron-parser-go v0.0.0
	github.com/local/thing v1.0.0
	github.com/pinned/thing v1.0.0
)

replace micron-parser-go => github.com/real-org/micron-parser-go v1.2.0

replace (
	github.com/local/thing => ./third_party/thing
	github.com/pinned/thing v1.0.0 => github.com/pinned/thing v1.0.1
)
`
	_, reps, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []Replacement{
		{Old: "micron-parser-go", New: "github.com/real-org/micron-parser-go", NewVersion: "v1.2.0"},
		{Old: "github.com/local/thing", New: "./third_party/thing"},
		{Old: "github.com/pinned/thing", OldVersion: "v1.0.0", New: "github.com/pinned/thing", NewVersion: "v1.0.1"},
	}
	if len(reps) != len(want) {
		t.Fatalf("got %d replacements, want %d: %+v", len(reps), len(want), reps)
	}
	for i, r := range reps {
		if r != want[i] {
			t.Errorf("replacement %d: got %+v, want %+v", i, r, want[i])
		}
	}
	if !reps[1].IsLocal() {
		t.Errorf("expected %+v to be local", reps[1])
	}
	if reps[0].IsLocal() || reps[2].IsLocal() {
		t.Errorf("expected module-path replacements to not be local")
	}
}

func TestSelectReplace(t *testing.T) {
	general := Replacement{Old: "example.com/foo", New: "github.com/other/foo"}
	specific := Replacement{Old: "example.com/foo", OldVersion: "v1.0.0", New: "./local"}

	got, ok := selectReplace([]Replacement{general, specific}, "v1.0.0")
	if !ok || got != specific {
		t.Errorf("matching version: got %+v, %v; want %+v, true", got, ok, specific)
	}
	got, ok = selectReplace([]Replacement{specific, general}, "v1.0.0")
	if !ok || got != specific {
		t.Errorf("matching version (reversed order): got %+v, %v; want %+v, true", got, ok, specific)
	}

	got, ok = selectReplace([]Replacement{general, specific}, "v2.0.0")
	if !ok || got != general {
		t.Errorf("non-matching version: got %+v, %v; want %+v, true", got, ok, general)
	}
	got, ok = selectReplace([]Replacement{specific, general}, "v2.0.0")
	if !ok || got != general {
		t.Errorf("non-matching version (reversed order): got %+v, %v; want %+v, true", got, ok, general)
	}

	_, ok = selectReplace([]Replacement{specific}, "v2.0.0")
	if ok {
		t.Errorf("non-matching version with no general fallback: expected no replace to apply, got one")
	}

	_, ok = selectReplace(nil, "v1.0.0")
	if ok {
		t.Errorf("no entries: expected no replace to apply, got one")
	}
}

func TestReplacementIsLocalBareDotDot(t *testing.T) {
	// Verified against the real go toolchain: `replace foo => ..` (no
	// trailing slash) is a valid go.mod construct — `go build` accepts it
	// and `go list -m all` resolves it straight off disk, never touching
	// a proxy — but a naive HasPrefix("./"/"../") check misses this bare
	// form (golang.org/x/mod/modfile.IsDirectoryPath treats "." and ".."
	// as directory paths too, not just "./" and "../"). Before this was
	// fixed, CheckAll's "another module" branch sent the literal string
	// ".." to the module proxy, producing a guaranteed high-severity
	// "not-found"/hallucinated-import false positive for a purely local,
	// never-fetched replace.
	for _, p := range []string{".", ".."} {
		r := Replacement{Old: "example.com/bar", New: p}
		if !r.IsLocal() {
			t.Errorf("Replacement{New: %q}.IsLocal() = false, want true", p)
		}
	}
}

func TestParseGoModReplaceQuotedLocalPathWithSpace(t *testing.T) {
	// go mod edit itself writes this exact form for a local replace path
	// containing a space (verified against the real go toolchain), and
	// go build accepts it — the replacement must still be recognized as
	// local so CheckAll skips it instead of sending the garbled,
	// still-quoted path to the proxy as if it were a real dependency.
	content := "module example.com/foo\n\n" +
		"require github.com/pkg/errors v0.9.1\n\n" +
		"replace github.com/pkg/errors => \"../my mod\"\n"
	_, reps, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("want 1 replacement, got %d: %+v", len(reps), reps)
	}
	if reps[0].New != "../my mod" {
		t.Errorf("New = %q, want %q", reps[0].New, "../my mod")
	}
	if !reps[0].IsLocal() {
		t.Errorf("IsLocal() = false, want true for quoted local path %q", reps[0].New)
	}
}

// TestParseGoModReplaceBacktickQuotedPathIsNotLocal pins a real divergence
// from the go toolchain found via real-world testing (2026-09): go.mod
// syntax has no backtick raw-string form at all, despite its lexer
// (golang.org/x/mod/modfile's read.go) tokenizing a backtick-delimited run
// exactly like a double-quoted string — the rejection happens one layer up,
// in the semantic parseString (rule.go), which only ever unquotes a token
// starting with '"'. Confirmed live on both go1.24.4 and go1.26.8: a go.mod
// containing `` replace github.com/pkg/errors => `../my mod` `` makes `go
// build`/`go list -m all` fail immediately with "invalid quoted string:
// unquoted string cannot contain quote" — this go.mod can never be built,
// under any go version tested. Before this fix, ParseGoMod treated the
// backtick-quoted token exactly like a double-quoted one, extracting
// New="../my mod" with IsLocal()==true — so CheckAll silently skipped this
// replace as "purely local, nothing to check" (see CheckAll's own doc
// comment), treating a go.mod that cannot build at all as an unremarkable,
// clean local-vendor override. See leadingQuotedString's own doc comment
// for the full explanation, including why a real attacker or an AI
// assuming Go source code's backtick convention also applies to go.mod
// could exploit exactly this to make a requirement disappear from every
// check modslop runs.
func TestParseGoModReplaceBacktickQuotedPathIsNotLocal(t *testing.T) {
	content := "module example.com/foo\n\n" +
		"require github.com/pkg/errors v0.9.1\n\n" +
		"replace github.com/pkg/errors => `../my mod`\n"
	_, reps, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("got %+v, want exactly one replace entry", reps)
	}
	if reps[0].New == "../my mod" {
		t.Fatalf("New = %q — backtick must not be unquoted as if it were a double-quoted string; real go.mod syntax has no raw-string form", reps[0].New)
	}
	if reps[0].IsLocal() {
		t.Fatalf("IsLocal() = true for %+v, want false: a go.mod shaped like this can never build under the real go toolchain, so it must not be silently treated as an ordinary local replace", reps[0])
	}
}

// TestParseGoModToolSingleLine covers the go.mod grammar this run's fix
// is actually about: a Go 1.24+ single-line `tool` directive was
// previously silently skipped entirely (it matched neither "require" nor
// "replace" at top level), producing a false clean bill for a go.mod
// whose only reference to a hallucinated package was via `tool`.
// TestParseGoModReplaceQuotedLocalPathWithDoubleSlash covers a
// stripComment bug fixed in goprivaudit run #148 and independently
// present here: stripComment used a naive strings.Index(line, "//") that
// truncated mid-string the moment a quoted token contained a literal
// "//", instead of only treating "//" as a comment start outside any
// quoted string the way golang.org/x/mod/modfile's own lexer does. A
// local replace path with a doubled slash — real go.mod syntax, verified
// live against the actual go toolchain (`go build`/`go list -m all` both
// resolve it as the local path) — corrupted the parsed path, leaving a
// stray leading quote that broke the "../" local-path-prefix check in
// IsLocal() and would have sent a purely local, never-fetched
// replacement to the proxy as if it were a real module.
func TestParseGoModReplaceQuotedLocalPathWithDoubleSlash(t *testing.T) {
	content := "module example.com/foo\n\n" +
		"require github.com/pkg/errors v0.9.1\n\n" +
		"replace github.com/pkg/errors => \"../vendor//bar\"\n"
	_, reps, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("want 1 replacement, got %d: %+v", len(reps), reps)
	}
	if reps[0].New != "../vendor//bar" {
		t.Errorf("New = %q, want %q", reps[0].New, "../vendor//bar")
	}
	if !reps[0].IsLocal() {
		t.Errorf("IsLocal() = false, want true for quoted local path %q", reps[0].New)
	}
}

// TestParseGoModRequireQuotedPathWithHexEscape covers a real,
// previously-uncovered gap in leadingQuotedString: it decoded every
// backslash escape in a double-quoted token by copying the byte right
// after the backslash literally, which only happens to be correct for \\
// and \" (the two escapes goldenpath tests above already exercise). Every
// other Go string escape decodes to something else entirely — \x2e is a
// single '.' byte (0x2e), not the two literal characters 'x' and '2e'.
// Confirmed live against the real go toolchain: a go.mod with `require
// "github\x2ecom/pkg/errors" v0.9.1` — a real, existing dependency whose
// path happens to hex-escape its literal "." for no reason other than
// unusual (e.g. AI-generated) go.mod styling — is accepted by `go build`/
// `go mod tidy`, which normalize it straight to the plain `require
// github.com/pkg/errors v0.9.1`, confirming real go decodes \x2e as "."
// and resolves the real, legitimate module. Before this fix, ParseGoMod
// decoded the same line to Requirement{Path: "githubx2ecom/pkg/errors"}
// — a path that doesn't exist on any proxy — so modslop reported a false
// high-severity "not-found" (hallucinated-import) finding against a
// completely real, legitimate dependency purely because of how its
// require line happened to be quoted.
func TestParseGoModRequireQuotedPathWithHexEscape(t *testing.T) {
	content := "module example.com/foo\n\n" +
		`require "github\x2ecom/pkg/errors" v0.9.1` + "\n"
	reqs, _, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 requirement, got %d: %+v", len(reqs), reqs)
	}
	if reqs[0].Path != "github.com/pkg/errors" {
		t.Errorf("Path = %q, want %q (real go decodes \\x2e as \".\" here — confirmed live via `go mod tidy` normalizing this exact line)", reqs[0].Path, "github.com/pkg/errors")
	}
}

// TestParseGoModReplaceQuotedPathWithEscapedQuoteAndComment exercises
// stripComment's backslash-skip branch together with a trailing comment:
// a backslash-escaped quote inside the path must be consumed as string
// content, not mistaken for the closing quote, so scanning continues and
// the real "//" comment marker after the actual close quote is found.
func TestParseGoModReplaceQuotedPathWithEscapedQuoteAndComment(t *testing.T) {
	content := "module example.com/foo\n\n" +
		"require github.com/pkg/errors v0.9.1\n\n" +
		"replace github.com/pkg/errors => \"../a\\\"b\" // comment\n"
	_, reps, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Fatalf("want 1 replacement, got %d: %+v", len(reps), reps)
	}
	if reps[0].New != `../a"b` {
		t.Errorf("New = %q, want %q", reps[0].New, `../a"b`)
	}
	if !reps[0].IsLocal() {
		t.Errorf("IsLocal() = false, want true for %q", reps[0].New)
	}
}

func TestParseGoModToolSingleLine(t *testing.T) {
	content := `module example.com/foo

go 1.24

tool golang.org/x/tools/cmd/stringer
`
	_, _, tools, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0] != "golang.org/x/tools/cmd/stringer" {
		t.Errorf("got tools %+v, want one stringer tool path", tools)
	}
}

// TestParseGoModModuleDirective covers ParseGoMod's fifth return value:
// the audited go.mod's own `module` directive path, needed by CheckTools
// to recognize a `tool` directive naming a package inside the main
// module itself (see check.go's CheckTools doc comment and this run's
// fix).
func TestParseGoModModuleDirective(t *testing.T) {
	content := `module example.com/mymodule

go 1.24

tool example.com/mymodule/cmd/gen
`
	_, _, _, _, modulePath, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if modulePath != "example.com/mymodule" {
		t.Errorf("got modulePath %q, want %q", modulePath, "example.com/mymodule")
	}
}

// TestParseGoModModuleBlock covers the parenthesized block form of the
// `module` directive — golang.org/x/mod/modfile's own lexer treats
// "module" as a valid block verb exactly like require/replace/tool/
// exclude (rule.go's LineBlock switch explicitly lists it), and a real
// go.mod written this way builds and runs cleanly (confirmed live,
// 2026-09: `go build`/`go list -m`/`go tool gen` all succeed against
// this exact content, and `go mod tidy` rewrites it to the single-line
// form). Before this fix, ParseGoMod's `module` handling never checked
// for "(" the way every other directive's block-form check does, so it
// fed the literal string "(" into parseToolLine, set modulePath to the
// bogus value "(", and silently dropped the block's real path line —
// leaving CheckTools unable to recognize the `tool` directive below as
// covered by the main module and producing a spurious high-severity
// not-found finding on it.
func TestParseGoModModuleBlock(t *testing.T) {
	content := `module (
	example.com/mymodule
)

go 1.24

tool example.com/mymodule/cmd/gen
`
	_, _, tools, _, modulePath, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if modulePath != "example.com/mymodule" {
		t.Errorf("got modulePath %q, want %q", modulePath, "example.com/mymodule")
	}
	if len(tools) != 1 || tools[0] != "example.com/mymodule/cmd/gen" {
		t.Errorf("got tools %+v, want one gen tool path", tools)
	}
}

// TestParseGoModToolBlock covers the block form, same shape as the
// existing require/replace block tests — a `tool (...)` block was
// silently skipped too, for the same reason as the single-line form.
func TestParseGoModToolBlock(t *testing.T) {
	content := `module example.com/foo

go 1.24

tool (
	golang.org/x/tools/cmd/stringer
	github.com/some/other/cmd/thing
)
`
	_, _, tools, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"golang.org/x/tools/cmd/stringer", "github.com/some/other/cmd/thing"}
	if len(tools) != len(want) {
		t.Fatalf("got %d tools, want %d: %+v", len(tools), len(want), tools)
	}
	for i, tl := range tools {
		if tl != want[i] {
			t.Errorf("tool %d: got %q, want %q", i, tl, want[i])
		}
	}
}

// TestParseGoModToolQuotedPath exercises the same quoted-token machinery
// (leadingQuotedString via firstField) the replace tests already cover,
// applied to a tool path.
func TestParseGoModToolQuotedPath(t *testing.T) {
	content := "module example.com/foo\n\n" +
		"go 1.24\n\n" +
		`tool "some path with spaces"` + "\n"
	_, _, tools, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0] != "some path with spaces" {
		t.Errorf("got tools %+v, want one quoted tool path", tools)
	}
}

// TestParseGoModExcludeSingleLine covers the single-line `exclude`
// directive form, which ParseGoMod silently dropped before this — see
// ParseGoMod's own doc comment for the real-go-toolchain-verified
// consequence (a require+exclude pair for the same exact version makes
// `go build` fail outright, which modslop couldn't see at all while
// exclude was unparsed).
func TestParseGoModExcludeSingleLine(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

exclude github.com/pkg/errors v0.9.1
`
	reqs, _, _, excludes, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0] != (Requirement{Path: "github.com/pkg/errors", Version: "v0.9.1"}) {
		t.Errorf("got reqs %+v, want one errors requirement", reqs)
	}
	if len(excludes) != 1 || excludes[0] != (Requirement{Path: "github.com/pkg/errors", Version: "v0.9.1"}) {
		t.Errorf("got excludes %+v, want one errors exclude", excludes)
	}
}

// TestParseGoModExcludeBlock covers the block form, same shape as the
// existing require/replace/tool block tests, plus the "exclude(" (no
// space before the paren) grammar variant already exercised for
// require/replace in TestParseGoModBlockNoSpaceBeforeParen.
func TestParseGoModExcludeBlock(t *testing.T) {
	content := `module example.com/foo

go 1.24

exclude(
	github.com/pkg/errors v0.9.1
	golang.org/x/net v0.20.0
)
`
	_, _, _, excludes, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []Requirement{
		{Path: "github.com/pkg/errors", Version: "v0.9.1"},
		{Path: "golang.org/x/net", Version: "v0.20.0"},
	}
	if len(excludes) != len(want) {
		t.Fatalf("got %d excludes, want %d: %+v", len(excludes), len(want), excludes)
	}
	for i, e := range excludes {
		if e != want[i] {
			t.Errorf("exclude %d: got %+v, want %+v", i, e, want[i])
		}
	}
}

func TestParseRequireLine(t *testing.T) {
	if r, ok := parseRequireLine("github.com/pkg/errors v0.9.1 // indirect"); !ok {
		t.Fatal("expected ok=true for a valid indirect requirement")
	} else if r != (Requirement{Path: "github.com/pkg/errors", Version: "v0.9.1"}) {
		t.Errorf("got %+v", r)
	}

	if _, ok := parseRequireLine("github.com/pkg/errors"); ok {
		t.Error("expected ok=false when the line has no version field")
	}

	if _, ok := parseRequireLine(""); ok {
		t.Error("expected ok=false for an empty line")
	}
}

func TestLoadGoMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	content := "module example.com/foo\n\nrequire github.com/pkg/errors v0.9.1\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	reqs, _, _, _, _, err := LoadGoMod(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != "github.com/pkg/errors" {
		t.Errorf("got %+v", reqs)
	}

	if _, _, _, _, _, err := LoadGoMod(filepath.Join(dir, "missing.mod")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestBaseName(t *testing.T) {
	cases := map[string]string{
		"github.com/gin-gonic/gin":     "gin",
		"github.com/redis/go-redis/v9": "go-redis",
		"golang.org/x/net":             "net",
		"gopkg.in/yaml.v3":             "yaml.v3",
	}
	for in, want := range cases {
		if got := BaseName(in); got != want {
			t.Errorf("BaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBaseName_SingleSegmentVersionLikeDoesNotPanic pins the
// `len(segs) > 1` guard in BaseName (found LIVED by mutation testing,
// run #127: with the guard's boundary mutated to `>= 1`, a bare
// single-segment path that also happens to look like a major-version
// suffix — e.g. "v2" — would pass isMajorVersionSuffix and then index
// segs[len(segs)-2], a negative index, panicking). Confirmed live:
// BaseName must keep returning the string unchanged for a single
// segment, version-suffix-shaped or not.
func TestBaseName_SingleSegmentVersionLikeDoesNotPanic(t *testing.T) {
	if got := BaseName("v2"); got != "v2" {
		t.Errorf("BaseName(%q) = %q, want %q", "v2", got, "v2")
	}
}

// TestIsMajorVersionSuffix_ZeroDigitBoundary pins the `c < '0'`
// boundary in isMajorVersionSuffix (found LIVED by mutation testing,
// run #127: TestBaseName already covers the "v9" high-digit boundary
// but nothing exercised a suffix containing a literal '0' digit, e.g.
// "v10" or "v0" — a mutated `c <= '0'` would wrongly reject these).
func TestIsMajorVersionSuffix_ZeroDigitBoundary(t *testing.T) {
	if got := BaseName("github.com/foo/bar/v10"); got != "bar" {
		t.Errorf("BaseName with /v10 suffix = %q, want %q", got, "bar")
	}
}

// TestBaseName_V0V1NotAMajorVersionSuffix is the regression case for a
// real divergence from golang.org/x/mod/module.CheckPath's own documented
// rule (mirrored by the real go command): "for a final path element of
// the form /vN ... must not begin with a leading zero, must not be /v1."
// v0 and v1 are never valid explicit path-major suffixes — Go's
// import-compatibility rule omits the suffix entirely for those two — so
// a module path merely ending in the literal segment "v1" or "v0" names
// a distinct module whose own final segment happens to be that string,
// not "the v1/v0 release of" its parent path. Confirmed live, 2026-09:
// `require example.com/foo/v1 v1.0.0` (any version) fails outright with
// "malformed module path" on a real `go build`/`go list -m all` — the
// same is true of a leading-zero form like ".../v01". Before this fix,
// isMajorVersionSuffix accepted any "v"+digits string, so
// BaseName("example.com/foo/v1") stripped it down to "foo", same as it
// would for a genuine suffix like "v2" or "v9".
func TestBaseName_V0V1NotAMajorVersionSuffix(t *testing.T) {
	cases := map[string]string{
		"example.com/foo/v1":  "v1",
		"example.com/foo/v0":  "v0",
		"example.com/foo/v01": "v01", // leading zero: also not a valid suffix
		"example.com/foo/v2":  "foo", // v2+ is a real suffix, still stripped
	}
	for in, want := range cases {
		if got := BaseName(in); got != want {
			t.Errorf("BaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCutKeyword pins cutKeyword's separator check (found LIVED by
// mutation testing, run #127: `c != ' ' && c != '\t' && c != '('` at
// gomod.go:235 had no direct test at all — only indirectly exercised
// via space- and paren-separated require/replace lines in ParseGoMod
// tests, never the tab separator cutKeyword's own doc comment calls
// out, and never a string that starts with the keyword but isn't
// actually followed by a valid separator).
func TestCutKeyword(t *testing.T) {
	cases := []struct {
		s, kw    string
		wantOK   bool
		wantRest string
	}{
		{"require(x)", "require", true, "(x)"},
		{"require\t(x)", "require", true, "\t(x)"},
		{"require x", "require", true, " x"},
		{"requirex y", "require", false, ""},
		{"require", "require", false, ""},
	}
	for _, c := range cases {
		rest, ok := cutKeyword(c.s, c.kw)
		if ok != c.wantOK || (ok && rest != c.wantRest) {
			t.Errorf("cutKeyword(%q, %q) = %q, %v; want %q, %v", c.s, c.kw, rest, ok, c.wantRest, c.wantOK)
		}
	}
}

// TestLeadingQuotedString_EdgeCases pins edges in leadingQuotedString: an
// unterminated double-quoted string / one ending in a trailing backslash
// (found LIVED by mutation testing, run #127, gomod.go:204/206 — must
// return ok=false without panicking, not just "eventually" avoid a crash),
// and — since the real-world-testing fix that made backtick no longer a
// recognized quote character here (see the function's own doc comment for
// why: real go.mod syntax has no raw-string form, confirmed live against
// go1.24.4/go1.26.8, even though a backtick-quoted token is a hard parse
// error there, not a value) — both an empty and a non-empty backtick run
// must now report ok=false, the same as any other non-'"' leading byte.
func TestLeadingQuotedString_EdgeCases(t *testing.T) {
	if v, n, ok := leadingQuotedString("``rest"); ok || v != "" || n != 0 {
		t.Errorf("empty backtick string: v=%q n=%d ok=%v, want v=%q n=0 ok=false (real go.mod syntax has no raw-string form)", v, n, ok, "")
	}
	if v, n, ok := leadingQuotedString("`../my mod` extra"); ok || v != "" || n != 0 {
		t.Errorf("backtick string: v=%q n=%d ok=%v, want v=%q n=0 ok=false (real go.mod syntax has no raw-string form)", v, n, ok, "")
	}
	if v, n, ok := leadingQuotedString(`"unterminated`); ok || v != "" || n != 0 {
		t.Errorf("unterminated double-quoted string: v=%q n=%d ok=%v, want v=%q n=0 ok=false", v, n, ok, "")
	}
	if v, n, ok := leadingQuotedString("\"trailing\\"); ok || v != "" || n != 0 {
		t.Errorf("double-quoted string ending in a trailing backslash: v=%q n=%d ok=%v, want v=%q n=0 ok=false", v, n, ok, "")
	}
}

// TestParseGoMod_WholeLineCommentInBlockNoLeadingSpace pins the `i >=
// 0` boundary in stripComment (found LIVED by mutation testing, run
// #127: same shape of bug as run #125's goproxycheck fix and run
// #126's goprivaudit stripComment fix — a require-block line that's
// entirely a comment, with no leading whitespace before "//", must
// still be stripped to a now-empty line and skipped, not parsed as a
// fake requirement whose "module path" is the literal "//" token).
func TestParseGoMod_WholeLineCommentInBlockNoLeadingSpace(t *testing.T) {
	content := "module example.com/foo\n\n" +
		"require (\n" +
		"// github.com/some/commented-out v1.0.0\n" +
		"\tgithub.com/pkg/errors v0.9.1\n" +
		")\n"
	reqs, _, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != "github.com/pkg/errors" {
		t.Fatalf("expected the whole-line comment to be skipped, leaving only the real requirement, got %+v", reqs)
	}
}

// TestGoWorkReplaces* and TestMergeReplaces* cover the go.work workspace
// gap described in goWorkReplaces' doc comment: a workspace's go.work can
// replace a dependency a member's own go.mod never mentions, and modslop
// (like goprivaudit before it) previously only ever read the one go.mod
// passed on the command line.

func TestGoWorkReplacesEmptyGowork(t *testing.T) {
	if got := goWorkReplaces(""); got != nil {
		t.Errorf("expected nil for empty gowork path, got %v", got)
	}
}

func TestGoWorkReplacesOff(t *testing.T) {
	if got := goWorkReplaces("off"); got != nil {
		t.Errorf(`expected nil for gowork = "off", got %v`, got)
	}
}

func TestGoWorkReplacesMissingFile(t *testing.T) {
	if got := goWorkReplaces(filepath.Join(t.TempDir(), "no-such.work")); got != nil {
		t.Errorf("expected nil for an unreadable go.work path, got %v", got)
	}
}

func TestGoWorkReplacesParsesReplaceBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.work")
	content := "go 1.24\n\n" +
		"use (\n\t./app\n\t./fork\n)\n\n" +
		"replace github.com/foo/bar => git.internal.example.com/mirror/bar v0.0.0\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got := goWorkReplaces(path)
	want := []Replacement{{Old: "github.com/foo/bar", New: "git.internal.example.com/mirror/bar", NewVersion: "v0.0.0"}}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestMergeReplacesOverlayWinsOnConflict(t *testing.T) {
	base := []Replacement{
		{Old: "example.com/shared", New: "example.com/from-gomod"},
		{Old: "example.com/gomod-only", New: "../local"},
	}
	overlay := []Replacement{
		{Old: "example.com/shared", New: "example.com/from-gowork"},
		{Old: "example.com/gowork-only", New: "example.com/added-by-gowork"},
	}
	got := mergeReplaces(base, overlay)

	byOld := make(map[string]Replacement, len(got))
	for _, r := range got {
		byOld[r.Old] = r
	}
	if len(byOld) != 3 {
		t.Fatalf("got %+v, want 3 distinct Old paths", got)
	}
	if byOld["example.com/shared"].New != "example.com/from-gowork" {
		t.Errorf("expected go.work's replace to win on conflict, got %+v", byOld["example.com/shared"])
	}
	if byOld["example.com/gomod-only"].New != "../local" {
		t.Errorf("expected the go.mod-only replace to survive unchanged, got %+v", byOld["example.com/gomod-only"])
	}
	if byOld["example.com/gowork-only"].New != "example.com/added-by-gowork" {
		t.Errorf("expected the go.work-only replace to be added, got %+v", byOld["example.com/gowork-only"])
	}
}

func TestMergeReplacesNilOverlayReturnsBaseUnchanged(t *testing.T) {
	base := []Replacement{{Old: "example.com/x", New: "example.com/y"}}
	got := mergeReplaces(base, nil)
	if len(got) != 1 || got[0] != base[0] {
		t.Errorf("got %+v, want %+v", got, base)
	}
}

// TestMergeReplaces_VersionSpecificOverlayDoesNotShadowUnrelatedBaseEntry
// pins the precedence bug found by live-testing against the real go
// toolchain: a go.work replace that's specific to one version must only
// shadow a go.mod-level entry for that *same* version, not every
// go.mod-level entry for the module. Live repro (four scratch-workspace
// scenarios, `go list -m all`/`go run` inside the member):
//
//  1. go.mod: `replace example.com/foo v1.0.0 => ../v1fork` (matches the
//     required v1.0.0). go.work: `replace example.com/foo v1.5.0 =>
//     ./v2fork` (a different, non-required version). Real go resolves to
//     v1fork — go.work's entry never applies to v1.0.0 at all, so it
//     doesn't touch go.mod's matching replace.
//  2. Same, but go.mod's replace is version-agnostic (`replace
//     example.com/foo => ../v1fork`) instead of version-specific. Real go
//     still resolves to v1fork for the same reason.
//
// The pre-fix mergeReplaces treated *any* go.work entry for a path as
// grounds to drop every go.mod-level entry for that path, so both
// scenarios above would have gone unreplaced and modslop would have sent
// example.com/foo to the public proxy — a false "not-found" on a
// dependency the real toolchain resolves locally.
func TestMergeReplaces_VersionSpecificOverlayDoesNotShadowUnrelatedBaseEntry(t *testing.T) {
	overlay := []Replacement{{Old: "example.com/foo", OldVersion: "v1.5.0", New: "../v2fork"}}

	t.Run("go.mod version-specific match survives", func(t *testing.T) {
		base := []Replacement{{Old: "example.com/foo", OldVersion: "v1.0.0", New: "../v1fork"}}
		merged := mergeReplaces(base, overlay)
		got, ok := selectReplace(merged, "v1.0.0")
		if !ok || got.New != "../v1fork" {
			t.Errorf("selectReplace(v1.0.0) = %+v, %v; want ../v1fork, true (real go still uses the go.mod replace here)", got, ok)
		}
	})

	t.Run("go.mod general replace survives", func(t *testing.T) {
		base := []Replacement{{Old: "example.com/foo", New: "../v1fork"}}
		merged := mergeReplaces(base, overlay)
		got, ok := selectReplace(merged, "v1.0.0")
		if !ok || got.New != "../v1fork" {
			t.Errorf("selectReplace(v1.0.0) = %+v, %v; want ../v1fork, true (real go still uses the go.mod replace here)", got, ok)
		}
	})
}

// TestMergeReplaces_OverlayGeneralOverridesBaseSpecific pins the other
// live-verified half of the same precedence rule: a version-agnostic
// go.work replace wins outright, even over a go.mod-level replace that
// exactly matches the required version (confirmed live: `go list -m
// all` resolved to the go.work fork in this exact shape).
func TestMergeReplaces_OverlayGeneralOverridesBaseSpecific(t *testing.T) {
	base := []Replacement{{Old: "example.com/foo", OldVersion: "v1.0.0", New: "../v1fork"}}
	overlay := []Replacement{{Old: "example.com/foo", New: "../v2fork"}}
	merged := mergeReplaces(base, overlay)
	got, ok := selectReplace(merged, "v1.0.0")
	if !ok || got.New != "../v2fork" {
		t.Errorf("selectReplace(v1.0.0) = %+v, %v; want ../v2fork, true (go.work's general replace wins)", got, ok)
	}
}

// TestMergeReplaces_OverlaySpecificWinsExactVersionTie pins the case
// where both sides replace the exact same version: go.work wins
// (confirmed live: `go list -m all` resolved to the go.work fork).
func TestMergeReplaces_OverlaySpecificWinsExactVersionTie(t *testing.T) {
	base := []Replacement{{Old: "example.com/foo", OldVersion: "v1.0.0", New: "../v1fork"}}
	overlay := []Replacement{{Old: "example.com/foo", OldVersion: "v1.0.0", New: "../v2fork"}}
	merged := mergeReplaces(base, overlay)
	got, ok := selectReplace(merged, "v1.0.0")
	if !ok || got.New != "../v2fork" {
		t.Errorf("selectReplace(v1.0.0) = %+v, %v; want ../v2fork, true (go.work wins an exact-version tie)", got, ok)
	}
}
