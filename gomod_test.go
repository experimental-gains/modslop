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
	reqs, reps, _, err := ParseGoMod(content)
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
	reqs, reps, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0] != (Requirement{Path: "github.com/gin-gonic/gin", Version: "v1.9.1"}) {
		t.Errorf("got reqs %+v, want one gin requirement", reqs)
	}
	if len(reps) != 1 || reps[0] != (Replacement{Old: "github.com/gin-gonic/gin", New: "github.com/local/gin"}) {
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
	_, reps, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []Replacement{
		{Old: "micron-parser-go", New: "github.com/real-org/micron-parser-go"},
		{Old: "github.com/local/thing", New: "./third_party/thing"},
		{Old: "github.com/pinned/thing", New: "github.com/pinned/thing"},
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
	_, reps, _, err := ParseGoMod(content)
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

func TestParseGoModReplaceBacktickQuotedPath(t *testing.T) {
	content := "module example.com/foo\n\n" +
		"require github.com/pkg/errors v0.9.1\n\n" +
		"replace github.com/pkg/errors => `../my mod`\n"
	_, reps, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 || reps[0].New != "../my mod" || !reps[0].IsLocal() {
		t.Fatalf("got %+v", reps)
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
	_, reps, _, err := ParseGoMod(content)
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

// TestParseGoModReplaceQuotedPathWithEscapedQuoteAndComment exercises
// stripComment's backslash-skip branch together with a trailing comment:
// a backslash-escaped quote inside the path must be consumed as string
// content, not mistaken for the closing quote, so scanning continues and
// the real "//" comment marker after the actual close quote is found.
func TestParseGoModReplaceQuotedPathWithEscapedQuoteAndComment(t *testing.T) {
	content := "module example.com/foo\n\n" +
		"require github.com/pkg/errors v0.9.1\n\n" +
		"replace github.com/pkg/errors => \"../a\\\"b\" // comment\n"
	_, reps, _, err := ParseGoMod(content)
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
	_, _, tools, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0] != "golang.org/x/tools/cmd/stringer" {
		t.Errorf("got tools %+v, want one stringer tool path", tools)
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
	_, _, tools, err := ParseGoMod(content)
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
	_, _, tools, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0] != "some path with spaces" {
		t.Errorf("got tools %+v, want one quoted tool path", tools)
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

	reqs, _, _, err := LoadGoMod(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != "github.com/pkg/errors" {
		t.Errorf("got %+v", reqs)
	}

	if _, _, _, err := LoadGoMod(filepath.Join(dir, "missing.mod")); err == nil {
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

// TestLeadingQuotedString_EdgeCases pins three edges in
// leadingQuotedString found LIVED by mutation testing, run #127: an
// empty backtick-quoted string (gomod.go:198, i can legitimately be 0
// here, unlike the IndexFunc call in firstField where TrimSpace
// already rules i==0 out), the exact consumed-byte count for a
// non-empty backtick string with trailing content (gomod.go:199, the
// content slice was already indirectly verified by
// TestParseGoModReplaceBacktickQuotedPath but the consumed count
// wasn't), and an unterminated double-quoted string / one ending in a
// trailing backslash (gomod.go:204/206 — must return ok=false without
// panicking, not just "eventually" avoid a crash).
func TestLeadingQuotedString_EdgeCases(t *testing.T) {
	if v, n, ok := leadingQuotedString("``rest"); !ok || v != "" || n != 2 {
		t.Errorf("empty backtick string: v=%q n=%d ok=%v, want v=%q n=2 ok=true", v, n, ok, "")
	}
	if v, n, ok := leadingQuotedString("`../my mod` extra"); !ok || v != "../my mod" || n != 11 {
		t.Errorf("backtick string consumed count: v=%q n=%d ok=%v, want v=%q n=11 ok=true", v, n, ok, "../my mod")
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
	reqs, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != "github.com/pkg/errors" {
		t.Fatalf("expected the whole-line comment to be skipped, leaving only the real requirement, got %+v", reqs)
	}
}
