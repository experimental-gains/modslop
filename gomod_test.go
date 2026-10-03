package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
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
	reqs, reps, _, _, _, _, _, err := ParseGoMod(content)
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
	reqs, reps, _, _, _, _, _, err := ParseGoMod(content)
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
	_, reps, _, _, _, _, _, err := ParseGoMod(content)
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

	got, ok := selectReplace([]Replacement{general, specific}, "example.com/foo", "v1.0.0", nil)
	if !ok || got != specific {
		t.Errorf("matching version: got %+v, %v; want %+v, true", got, ok, specific)
	}
	got, ok = selectReplace([]Replacement{specific, general}, "example.com/foo", "v1.0.0", nil)
	if !ok || got != specific {
		t.Errorf("matching version (reversed order): got %+v, %v; want %+v, true", got, ok, specific)
	}

	got, ok = selectReplace([]Replacement{general, specific}, "example.com/foo", "v2.0.0", nil)
	if !ok || got != general {
		t.Errorf("non-matching version: got %+v, %v; want %+v, true", got, ok, general)
	}
	got, ok = selectReplace([]Replacement{specific, general}, "example.com/foo", "v2.0.0", nil)
	if !ok || got != general {
		t.Errorf("non-matching version (reversed order): got %+v, %v; want %+v, true", got, ok, general)
	}

	_, ok = selectReplace([]Replacement{specific}, "example.com/foo", "v2.0.0", nil)
	if ok {
		t.Errorf("non-matching version with no general fallback: expected no replace to apply, got one")
	}

	_, ok = selectReplace(nil, "example.com/foo", "v1.0.0", nil)
	if ok {
		t.Errorf("no entries: expected no replace to apply, got one")
	}
}

// TestSelectReplace_OldVersionIsUnresolvedQuery is the live-verified
// regression (see selectReplace's own doc comment): a specific replace
// entry's OldVersion can be an abbreviated-prefix or comparison-query
// version, not already a literal tag, and still match the exact required
// version once resolved through the proxy — exactly like a require or
// exclude directive's own version field already does.
func TestSelectReplace_OldVersionIsUnresolvedQuery(t *testing.T) {
	// fakeResolver resolves "v0.9" to "v0.9.1" and "v1.0" to "v2.0.0",
	// mimicking the real proxy.golang.org's own abbreviated-prefix
	// resolution (confirmed live: .../@v/v0.9.info returns
	// {"Version":"v0.9.1",...}).
	resolutions := map[string]string{"v0.9": "v0.9.1", "v1.0": "v2.0.0", "v0.9.1": "v0.9.1", "v2.0.0": "v2.0.0"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := strings.TrimSuffix(path.Base(r.URL.Path), ".info")
		resolved, ok := resolutions[v]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2020-01-01T00:00:00Z"}`, resolved)
	}))
	defer srv.Close()
	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	queryGeneral := Replacement{Old: "example.com/foo", New: "github.com/general/fork"}
	queryExclusiveMiss := Replacement{Old: "example.com/foo", OldVersion: "v1.0", New: "github.com/wrong/fork"}
	querySpecific := Replacement{Old: "example.com/foo", OldVersion: "v0.9", New: "github.com/real/fork"}

	got, ok := selectReplace([]Replacement{querySpecific}, "example.com/foo", "v0.9.1", proxy)
	if !ok || got != querySpecific {
		t.Errorf("unresolved-query specific match: got %+v, %v; want %+v, true", got, ok, querySpecific)
	}

	// querySpecific ("v0.9" -> v0.9.1) still wins over a general entry even
	// though neither is a literal-string match for "v0.9.1" — matching
	// precedence for a resolved match must be identical to a literal one.
	got, ok = selectReplace([]Replacement{queryGeneral, querySpecific}, "example.com/foo", "v0.9.1", proxy)
	if !ok || got != querySpecific {
		t.Errorf("unresolved-query specific beats general: got %+v, %v; want %+v, true", got, ok, querySpecific)
	}

	// A specific entry whose query resolves to a *different* real version
	// than the one actually required must not match, same as a literal
	// mismatch wouldn't.
	got, ok = selectReplace([]Replacement{queryExclusiveMiss, queryGeneral}, "example.com/foo", "v0.9.1", proxy)
	if !ok || got != queryGeneral {
		t.Errorf("unresolved-query non-match falls back to general: got %+v, %v; want %+v, true", got, ok, queryGeneral)
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

func TestReplacementIsLocalWindowsDriveLetter(t *testing.T) {
	// Verified against the real go toolchain, go1.24.4, GOPROXY=off: a
	// go.mod requiring github.com/pkg/errors v0.9.1 with `replace
	// github.com/pkg/errors => C:/Users/foo/local/errors` (no version)
	// parses with zero error — `go list -m all` Fatals only later, at
	// module-resolution time, with "reading
	// C:/Users/foo/local/errors/go.mod: ... no such file or directory", a
	// missing-directory error, never a go.mod defect, and never touches
	// the network. golang.org/x/mod/modfile.IsDirectoryPath recognizes
	// any "<letter>:..." new-side target as a directory path for exactly
	// this reason (a drive-letter path spelled with forward slashes has
	// no backslash, so the separate "Windows path on a non-windows
	// system" parse Fatal never fires). Before this was fixed, IsLocal()
	// returned false for every one of these forms, so CheckAll's
	// require+replace loop sent the literal drive-letter string to the
	// module proxy as if it were a real dependency (a guaranteed
	// "not-found" false positive) and checkReplaceMissingVersion
	// separately flagged the same line as "replace-missing-version" — a
	// second false positive, since the real go command accepts this
	// exact line with no version and no Fatal at all.
	for _, p := range []string{"C:/Users/foo/local/errors", "c:/local/fork", "C:local/fork", "Z:/x"} {
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
	_, reps, _, _, _, _, _, err := ParseGoMod(content)
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
// containing “ replace github.com/pkg/errors => `../my mod` “ makes `go
// build`/`go list -m all` fail immediately with "invalid quoted string:
// unquoted string cannot contain quote" — this go.mod can never be built,
// under any go version tested.
//
// Originally, ParseGoMod treated the backtick-quoted token exactly like a
// double-quoted one, extracting New="../my mod" with IsLocal()==true — so
// CheckAll silently skipped this replace as "purely local, nothing to
// check." A first fix stopped unquoting the backtick run but still parsed
// the line as an ordinary (garbage) Replacement with New="`../my mod`",
// which this test originally pinned via the two assertions below — an
// improvement (no longer silently "local"), but still not what real go
// does: that garbage New value got checked against the live module proxy
// and reported as a misleading "not-found" hallucination, for a go.mod
// that never had any chance of building in the first place. A later fix
// (lineHasInvalidQuotedToken, see its own doc comment) closed that
// remaining gap by rejecting the whole line outright, the same way a
// missing "=>" arrow or a missing version already is — see
// TestParseGoModInvalidQuotedTokenIsMalformed for the current-behavior
// test; this test now only pins that no Replacement is produced at all.
func TestParseGoModReplaceBacktickQuotedPathIsNotLocal(t *testing.T) {
	content := "module example.com/foo\n\n" +
		"require github.com/pkg/errors v0.9.1\n\n" +
		"replace github.com/pkg/errors => `../my mod`\n"
	_, reps, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 0 {
		t.Fatalf("got %+v, want no replace entry at all — a go.mod shaped like this can never build under the real go toolchain", reps)
	}
	// The reported token is the first whitespace-delimited chunk containing
	// the backtick ("`../my", not the full "`../my mod`" — a backtick
	// doesn't make the rest of the line atomic the way a leading '"' does,
	// matching real go's own lexer, which only tokenizes a quoted run
	// starting with '"' specially) — still unambiguously flags the line.
	want := []MalformedDirective{{Directive: "invalid-quoted-token", Path: "`../my"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Fatalf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModReplaceArrowRequiresWhitespace pins a real divergence from
// the go toolchain found via real-world testing (2026-09): golang.org/x/mod/
// modfile's lexer has no dedicated "=>" token at all, so an arrow glued to
// an adjacent path or version with no separating space is swallowed into
// that field's own identifier token instead of standing alone — the
// semantic layer then requires the literal, standalone token "=>" and
// refuses to parse anything else. Confirmed live, 2026-09 (go1.24.4): a
// go.mod with `replace example.com/a=>example.com/b v1.0.0` (no space on
// either side of the arrow) makes `go build`/`go list -m all` fail
// immediately with "usage: replace module/path [v1.2.3] => other/module
// v1.4 ...", a parse error before any network call; missing the space on
// only one side fails identically, while spacing both sides is accepted.
// Before this fix, parseReplaceLine used strings.SplitN(s, "=>", 2), which
// matches that substring regardless of adjacent whitespace, so this exact
// unbuildable line was parsed as an ordinary, valid replacement and
// silently checked against the proxy under the substituted path.
func TestParseGoModReplaceArrowRequiresWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
	}{
		{"no space either side", "example.com/a=>example.com/b v1.0.0"},
		{"no space before", "example.com/a =>example.com/b v1.0.0"},
		{"no space after", "example.com/a=> example.com/b v1.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := "module example.com/foo\n\nrequire example.com/a v0.1.0\n\nreplace " + tc.line + "\n"
			_, reps, _, _, _, _, _, err := ParseGoMod(content)
			if err != nil {
				t.Fatal(err)
			}
			if len(reps) != 0 {
				t.Fatalf("replace %q: got %+v, want no replacement recognized (real go refuses to parse this go.mod at all)", tc.line, reps)
			}
		})
	}

	// The properly-spaced form must still parse, confirming the fix didn't
	// just make every replace line fail.
	content := "module example.com/foo\n\nrequire example.com/a v0.1.0\n\nreplace example.com/a => example.com/b v1.0.0\n"
	_, reps, _, _, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := Replacement{Old: "example.com/a", New: "example.com/b", NewVersion: "v1.0.0"}
	if len(reps) != 1 || reps[0] != want {
		t.Fatalf("got %+v, want exactly %+v", reps, want)
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
	_, reps, _, _, _, _, _, err := ParseGoMod(content)
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
	reqs, _, _, _, _, _, _, err := ParseGoMod(content)
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
	_, reps, _, _, _, _, _, err := ParseGoMod(content)
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
	_, _, tools, _, _, _, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0] != "golang.org/x/tools/cmd/stringer" {
		t.Errorf("got tools %+v, want one stringer tool path", tools)
	}
}

// TestParseGoModToolExtraArgumentIsMalformed covers the other half of the
// same "tool takes exactly one argument" grammar: a trailing field left
// over after the path (e.g. a copy-pasted or hand-edited stray word).
// Confirmed live the identical Fatal fires for this shape too. Before
// this fix, parseToolLine silently discarded the extra field via
// `path, _ := firstField(s)` and accepted the line as an ordinary, valid
// tool directive naming only its first field.
func TestParseGoModToolExtraArgumentIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

tool golang.org/x/tools/cmd/stringer extra
`
	_, _, tools, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 0 {
		t.Errorf("got tools %+v, want none (the line is malformed, not a valid tool directive)", tools)
	}
	want := []MalformedDirective{{Directive: "tool", Path: "golang.org/x/tools/cmd/stringer"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModToolBlockExtraArgumentIsMalformed covers the block form of
// the same gap.
func TestParseGoModToolBlockExtraArgumentIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

tool (
	golang.org/x/tools/cmd/stringer extra
)
`
	_, _, tools, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 0 {
		t.Errorf("got tools %+v, want none (the line is malformed, not a valid tool directive)", tools)
	}
	want := []MalformedDirective{{Directive: "tool", Path: "golang.org/x/tools/cmd/stringer"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModModuleExtraArgumentIsMalformed covers the `module`
// directive's identical one-argument grammar (golang.org/x/mod/modfile's
// rule.go Fatals with "usage: module module/path" under the same
// zero-or-more-than-one-field condition as `tool`, just a differently
// worded message — see malformedDirectiveUsage). Confirmed live,
// go1.24.4: `module example.com/foo extra` Fatals `go list -m all`
// immediately, before resolving anything.
func TestParseGoModModuleExtraArgumentIsMalformed(t *testing.T) {
	content := `module example.com/foo extra

go 1.24

require github.com/pkg/errors v0.9.1
`
	_, _, _, _, modulePath, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if modulePath != "" {
		t.Errorf("got modulePath %q, want \"\" (the line is malformed)", modulePath)
	}
	want := []MalformedDirective{{Directive: "module", Path: "example.com/foo"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
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
	_, _, _, _, modulePath, _, _, err := ParseGoMod(content)
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
	_, _, tools, _, modulePath, _, _, err := ParseGoMod(content)
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

// TestParseGoModRepeatedModuleDirectiveIsMalformed is the regression test
// for this run's fix: a second, individually well-formed `module`
// directive anywhere in the file makes real go Fatal with "repeated
// module statement" (golang.org/x/mod/modfile's rule.go) before
// resolving anything — confirmed live, go1.24.4, GOPROXY=off, against
// this exact content. Before this fix, ParseGoMod's "last one wins"
// handling silently overwrote modulePath with the second module's path
// and surfaced no finding at all for a go.mod the real go command
// refuses to build under any circumstances.
func TestParseGoModRepeatedModuleDirectiveIsMalformed(t *testing.T) {
	content := `module example.com/foo

module example.com/bar

go 1.24

require github.com/pkg/errors v0.9.1
`
	_, _, _, _, modulePath, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	// modulePath keeps the *first* module directive's value — see
	// ParseGoMod's own doc comment for why: it's the best-effort guess at
	// the author's real intent, and keeps a `tool` directive legitimately
	// inside that first module from being misclassified as an external,
	// unresolved dependency.
	if modulePath != "example.com/foo" {
		t.Errorf("got modulePath %q, want %q (the first module directive)", modulePath, "example.com/foo")
	}
	want := []MalformedDirective{{Directive: "module-repeated", Path: "example.com/bar"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModRepeatedModuleDirectiveBlockForm covers the same Fatal
// reached via a mix of block and single-line `module` forms — real go's
// Fatal fires regardless of which syntax either occurrence uses (both
// resolve through the same rule.go switch case), confirmed live.
func TestParseGoModRepeatedModuleDirectiveBlockForm(t *testing.T) {
	content := `module example.com/foo

module (
	example.com/bar
)

go 1.24

tool example.com/foo/cmd/gen
`
	_, _, tools, _, modulePath, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if modulePath != "example.com/foo" {
		t.Errorf("got modulePath %q, want %q (the first module directive)", modulePath, "example.com/foo")
	}
	if len(tools) != 1 || tools[0] != "example.com/foo/cmd/gen" {
		t.Errorf("got tools %+v, want one gen tool path", tools)
	}
	want := []MalformedDirective{{Directive: "module-repeated", Path: "example.com/bar"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModRepeatedGoDirectiveIsMalformed is the regression test for
// this run's fix: ParseGoMod never recognized the `go` keyword at all, so a
// go.mod with two `go` lines silently reported "nothing flagged" even
// though real go (golang.org/x/mod/modfile's rule.go) Fatals immediately
// with "repeated go statement" — confirmed live, go1.24.4, GOPROXY=off,
// against this exact content (identical versions Fatal the same way as
// differing ones; this isn't a version-conflict heuristic, it's a flat ban
// on a second occurrence).
func TestParseGoModRepeatedGoDirectiveIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.22
go 1.23

require github.com/pkg/errors v0.9.1
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []MalformedDirective{{Directive: "go-repeated", Path: "1.23"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModRepeatedToolchainDirectiveIsMalformed covers the identical
// shape for `toolchain` — confirmed live, go1.24.4, GOPROXY=off: a second
// `toolchain` line Fatals with "repeated toolchain statement".
func TestParseGoModRepeatedToolchainDirectiveIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.22
toolchain go1.22.1
toolchain go1.22.2

require github.com/pkg/errors v0.9.1
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []MalformedDirective{{Directive: "toolchain-repeated", Path: "go1.22.2"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModBareGoKeywordIsMalformed and
// TestParseGoModBareToolchainKeywordIsMalformed cover the other Fatal shape
// `go`/`toolchain` share with `tool`/`module`: a line with zero (or more
// than one) argument. Confirmed live, go1.24.4: a bare `go` or `toolchain`
// line Fatals with "go/toolchain directive expects exactly one argument".
func TestParseGoModBareGoKeywordIsMalformed(t *testing.T) {
	content := `module example.com/foo

go

require github.com/pkg/errors v0.9.1
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []MalformedDirective{{Directive: "go", Path: ""}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

func TestParseGoModBareToolchainKeywordIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.22
toolchain

require github.com/pkg/errors v0.9.1
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []MalformedDirective{{Directive: "toolchain", Path: ""}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModSingleGoAndToolchainDirectivesAreNotMalformed is the
// mirror-image correctness check: a normal, single `go`/`toolchain` go.mod
// must not be flagged at all.
func TestParseGoModSingleGoAndToolchainDirectivesAreNotMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.22

toolchain go1.22.1

require github.com/pkg/errors v0.9.1
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(malformed) != 0 {
		t.Errorf("got malformed %+v, want none", malformed)
	}
}

// TestParseGoModGodebugSingleLine covers the plain, single-line `godebug
// key=value` form, which ParseGoMod never recognized at all before this
// fix (every godebug line, well-formed or not, fell through to the same
// silent drop an ordinary unrecognized line gets).
func TestParseGoModGodebugSingleLine(t *testing.T) {
	content := `module example.com/foo

go 1.22

godebug http2client=0
`
	_, _, _, _, _, _, godebugs, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []Godebug{{Key: "http2client", Value: "0"}}
	if len(godebugs) != len(want) || godebugs[0] != want[0] {
		t.Errorf("got godebugs %+v, want %+v", godebugs, want)
	}
}

// TestParseGoModGodebugBlock covers the `godebug ( ... )` block form,
// which real go.mod syntax allows exactly like require/replace/tool/
// exclude/module — golang.org/x/mod/modfile's rule.go dispatches the
// identical "godebug" case for both a bare line and a block entry.
func TestParseGoModGodebugBlock(t *testing.T) {
	content := `module example.com/foo

go 1.22

godebug (
	http2client=0
	panicnil=1
)
`
	_, _, _, _, _, _, godebugs, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []Godebug{{Key: "http2client", Value: "0"}, {Key: "panicnil", Value: "1"}}
	if len(godebugs) != len(want) || godebugs[0] != want[0] || godebugs[1] != want[1] {
		t.Errorf("got godebugs %+v, want %+v", godebugs, want)
	}
}

// TestParseGoModGodebugMalformedLineIsDropped documents the deliberate
// scope boundary noted on parseGodebugLine: a malformed godebug line
// (here, one missing the required "=") isn't turned into a
// MalformedDirective yet, so it's silently dropped exactly like it was
// before godebug parsing existed at all — not a regression, just not a
// newly-covered case.
func TestParseGoModGodebugMalformedLineIsDropped(t *testing.T) {
	content := `module example.com/foo

go 1.22

godebug http2client

require github.com/pkg/errors v0.9.1
`
	reqs, _, _, _, _, malformed, godebugs, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(godebugs) != 0 {
		t.Errorf("got godebugs %+v, want none (malformed line, no \"=\")", godebugs)
	}
	if len(malformed) != 0 {
		t.Errorf("got malformed %+v, want none (not yet modeled, see parseGodebugLine)", malformed)
	}
	if len(reqs) != 1 || reqs[0].Path != "github.com/pkg/errors" {
		t.Errorf("got reqs %+v, want the one require line after the malformed godebug line", reqs)
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
	_, _, tools, _, _, _, _, err := ParseGoMod(content)
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
	_, _, tools, _, _, _, _, err := ParseGoMod(content)
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
	reqs, _, _, excludes, _, _, _, err := ParseGoMod(content)
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
	_, _, _, excludes, _, _, _, err := ParseGoMod(content)
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

// TestParseGoModRequireMissingVersionIsMalformed pins ParseGoMod's sixth
// return value: a require directive naming a module path but no version
// makes real go Fatal at go.mod parse time (confirmed live, 2026-09,
// go1.24.4, GOPROXY=off: "usage: require module/path v1.2.3", before any
// network call) — before this return value existed, the line was silently
// dropped on the floor with no trace at all (see check.go's
// checkMalformedDirectives doc comment for the full rationale).
func TestParseGoModRequireMissingVersionIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors
`
	reqs, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Errorf("got reqs %+v, want none (the line is malformed, not a valid requirement)", reqs)
	}
	want := []MalformedDirective{{Directive: "require", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModRequireBlockMissingVersionIsMalformed covers the block
// form of the same gap — real go Fatals identically for a block entry
// missing its version (confirmed live, 2026-09: go.mod:6:2: usage: require
// module/path v1.2.3).
func TestParseGoModRequireBlockMissingVersionIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require (
	github.com/pkg/errors
)
`
	reqs, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Errorf("got reqs %+v, want none", reqs)
	}
	want := []MalformedDirective{{Directive: "require", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModExcludeMissingVersionIsMalformed covers exclude's
// identical grammar (confirmed live, 2026-09: "usage: exclude module/path
// v1.2.3", same Fatal-at-parse-time shape as require).
func TestParseGoModExcludeMissingVersionIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

exclude github.com/pkg/errors
`
	_, _, _, excludes, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(excludes) != 0 {
		t.Errorf("got excludes %+v, want none", excludes)
	}
	want := []MalformedDirective{{Directive: "exclude", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModRequireExtraArgumentIsMalformed covers the mirror-image gap
// from TestParseGoModRequireMissingVersionIsMalformed: a require line with
// a stray trailing word *after* the version is just as grammatically
// invalid to real go as one missing its version entirely — confirmed live,
// 2026-10 (go1.24.4, GOPROXY=off): `require github.com/pkg/errors v0.9.1
// extra` Fatals `go build`/`go list -m all` immediately with "usage:
// require module/path v1.2.3", the identical message the missing-version
// shape produces. Before this fix, parseRequireLine silently discarded
// the trailing "extra" token via `version, _ := firstField(rest)` and
// accepted the line as an ordinary, valid two-field requirement.
func TestParseGoModRequireExtraArgumentIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1 extra
`
	reqs, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Errorf("got reqs %+v, want none (the line is malformed, not a valid requirement)", reqs)
	}
	want := []MalformedDirective{{Directive: "require", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModRequireBlockExtraArgumentIsMalformed covers the block form
// of the same gap — confirmed live that a block entry carrying a trailing
// extra token Fatals identically to its single-line form.
func TestParseGoModRequireBlockExtraArgumentIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require (
	github.com/pkg/errors v0.9.1 extra
)
`
	reqs, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Errorf("got reqs %+v, want none", reqs)
	}
	want := []MalformedDirective{{Directive: "require", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModExcludeExtraArgumentIsMalformed covers exclude's identical
// grammar — confirmed live, 2026-10: `exclude github.com/pkg/errors v0.8.0
// extra` Fatals with "usage: exclude module/path v1.2.3", same shape as
// require.
func TestParseGoModExcludeExtraArgumentIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

exclude github.com/pkg/errors v0.8.0 extra
`
	_, _, _, excludes, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(excludes) != 0 {
		t.Errorf("got excludes %+v, want none", excludes)
	}
	want := []MalformedDirective{{Directive: "exclude", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseRequireLineTrailingCommentStillAccepted pins that a genuine
// trailing "//"-comment — even one that isn't the canonical "// indirect"
// marker, matching TestParseRequireLineIndirectCommentVariants above — is
// still tolerated and must NOT be mistaken for the extra-field shape the
// two tests above cover: a real line comment is never a third grammar
// field to the real parser, only a non-comment trailing token is.
func TestParseRequireLineTrailingCommentStillAccepted(t *testing.T) {
	want := Requirement{Path: "github.com/foo/bar", Version: "v1.0.0"}
	cases := []string{
		"github.com/foo/bar v1.0.0 // direct",
		"github.com/foo/bar v1.0.0 //not indirect at all",
	}
	for _, line := range cases {
		r, ok := parseRequireLine(line)
		if !ok {
			t.Errorf("parseRequireLine(%q): expected ok=true", line)
			continue
		}
		if r != want {
			t.Errorf("parseRequireLine(%q) = %+v, want %+v", line, r, want)
		}
	}
}

// TestParseRequireLineExtraFieldRejected is a direct unit-test mirror of
// TestParseGoModRequireExtraArgumentIsMalformed, pinning parseRequireLine's
// own contract in isolation.
func TestParseRequireLineExtraFieldRejected(t *testing.T) {
	if _, ok := parseRequireLine("github.com/pkg/errors v0.9.1 extra"); ok {
		t.Error("expected ok=false for a trailing non-comment extra field")
	}
	if _, ok := parseRequireLine("github.com/pkg/errors v0.9.1 extra // indirect"); ok {
		t.Error("expected ok=false: a real extra field followed by a comment is still a real extra field")
	}
}

// TestParseGoModRequireBareKeywordIsMalformed covers the deeper half of
// this run's cutKeyword fix: a `require` directive with *nothing at all*
// after the keyword (not even a path guess to recover) — a plainer
// mistake than TestParseGoModRequireMissingVersionIsMalformed's "path but
// no version" shape. Before the fix, cutKeyword's own rest=="" check
// rejected this as if "require" hadn't matched the keyword at all, so
// ParseGoMod's dispatch fell through to the unconditional `continue` at
// the bottom of the blockKind=="" branch — the line never reached
// parseRequireLine's own ok=false path, so it produced no
// MalformedDirective whatsoever, not even one with Path=="". Confirmed
// live, go1.24.4, GOPROXY=off: a bare `require` line Fatals `go list -m
// all` immediately with "usage: require module/path v1.2.3", before
// resolving the otherwise-real, otherwise-clean require line below it.
func TestParseGoModRequireBareKeywordIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

require
`
	reqs, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != "github.com/pkg/errors" {
		t.Errorf("got reqs %+v, want only the well-formed require line", reqs)
	}
	want := []MalformedDirective{{Directive: "require", Path: ""}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModExcludeBareKeywordIsMalformed is exclude's version of the
// same gap — confirmed live that a bare `exclude` Fatals identically
// ("usage: exclude module/path v1.2.3").
func TestParseGoModExcludeBareKeywordIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

exclude
`
	_, _, _, excludes, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(excludes) != 0 {
		t.Errorf("got excludes %+v, want none", excludes)
	}
	want := []MalformedDirective{{Directive: "exclude", Path: ""}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModToolBareKeywordIsMalformed is the tool-directive version.
// Confirmed live: a bare `tool` Fatals with "tool directive expects
// exactly one argument".
func TestParseGoModToolBareKeywordIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

tool
`
	_, _, tools, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 0 {
		t.Errorf("got tools %+v, want none", tools)
	}
	want := []MalformedDirective{{Directive: "tool", Path: ""}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModReplaceNoArrowIsMalformed covers real-world-testing's find
// for this run: a `replace` directive with no "=>" arrow at all was the
// one directive family parseReplaceLine already rejected but ParseGoMod
// silently dropped on the floor instead of recording as malformed, unlike
// every sibling directive above. Confirmed live, go1.24.4, GOPROXY=off: a
// bare `replace github.com/pkg/errors` Fatals `go list -m all` immediately
// with "usage: replace module/path [v1.2.3] => other/module v1.4 ...".
func TestParseGoModReplaceNoArrowIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

replace github.com/pkg/errors
`
	_, reps, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 0 {
		t.Errorf("got reps %+v, want none (the line is malformed, not a valid replace)", reps)
	}
	want := []MalformedDirective{{Directive: "replace", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModReplaceBlockNoArrowIsMalformed covers the block form of
// the same gap — confirmed live, go1.24.4: go.mod:8:2: usage: replace
// module/path [v1.2.3] => other/module v1.4 ...
func TestParseGoModReplaceBlockNoArrowIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

replace (
	github.com/pkg/errors
)
`
	_, reps, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 0 {
		t.Errorf("got reps %+v, want none", reps)
	}
	want := []MalformedDirective{{Directive: "replace", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModReplaceArrowWithNoNewSideIsMalformed covers the sibling
// shape where the arrow is present but nothing follows it — parseReplaceLine
// rejects this via its own newFields-empty check, and real go Fatals
// identically (confirmed live): `replace github.com/pkg/errors =>` produces
// the same "usage: replace ..." message as the no-arrow case.
func TestParseGoModReplaceArrowWithNoNewSideIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

replace github.com/pkg/errors =>
`
	_, reps, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 0 {
		t.Errorf("got reps %+v, want none", reps)
	}
	want := []MalformedDirective{{Directive: "replace", Path: "github.com/pkg/errors"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModReplaceWellFormedIsNotMalformed confirms the sibling
// correct-behavior case (an ordinary, well-formed replace directive) isn't
// disturbed by this fix — no spurious malformed finding for the common
// case this entire parser exists to handle.
func TestParseGoModReplaceWellFormedIsNotMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1

replace github.com/pkg/errors => github.com/pkg/errors v0.9.1
`
	_, reps, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 {
		t.Errorf("got reps %+v, want exactly one well-formed replace", reps)
	}
	if len(malformed) != 0 {
		t.Errorf("got malformed %+v, want none", malformed)
	}
}

// TestParseGoModIgnoreExtraArgumentIsMalformed covers `ignore`'s identical
// one-argument grammar to `tool`/`module` (golang.org/x/mod/modfile's
// rule.go Fatals with "ignore directive expects exactly one argument"
// under the same zero-or-more-than-one-field condition). Confirmed live,
// 2026-10-03, go1.26.8 (the toolchain that actually recognizes `ignore`):
// `ignore ./a ./b` Fatals `go list -m all` immediately, before resolving
// anything. Before this fix, ParseGoMod didn't recognize `ignore` as a
// keyword at all, so this line was silently dropped with no trace, the
// same "unrecognized line" fate a genuinely unrecognized directive gets.
func TestParseGoModIgnoreExtraArgumentIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.26

require github.com/pkg/errors v0.9.1

ignore ./a ./b
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []MalformedDirective{{Directive: "ignore", Path: "./a"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModIgnoreBlockExtraArgumentIsMalformed covers the block form
// of the same gap. Confirmed live, 2026-10-03, go1.26.8: an `ignore (\n\t./a
// ./b\n)` block entry carrying two tokens Fatals identically.
func TestParseGoModIgnoreBlockExtraArgumentIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.26

ignore (
	./a ./b
)
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []MalformedDirective{{Directive: "ignore", Path: "./a"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModIgnoreBareKeywordIsMalformed covers a bare `ignore` line
// with no argument at all — confirmed live, 2026-10-03, go1.26.8, Fatals
// with the identical "ignore directive expects exactly one argument".
func TestParseGoModIgnoreBareKeywordIsMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.26

ignore
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []MalformedDirective{{Directive: "ignore", Path: ""}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
}

// TestParseGoModIgnoreWellFormedIsNotMalformed covers both the fact that a
// well-formed `ignore` directive (single-line or a well-formed block
// entry) isn't flagged, and that — unlike `module`/`go`/`toolchain` —
// real go.mod syntax allows more than one `ignore` directive with no
// "repeated" Fatal at all (confirmed live, 2026-10-03, go1.26.8: `ignore
// ./a` followed by a separate `ignore ./b` line builds and resolves
// clean), so ParseGoMod must not synthesize an "ignore-repeated"
// MalformedDirective the way it does for module/go/toolchain.
func TestParseGoModIgnoreWellFormedIsNotMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.26

ignore ./a

ignore (
	./b
)
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(malformed) != 0 {
		t.Errorf("got malformed %+v, want none", malformed)
	}
}

// TestParseGoModLeadingBOMIsMalformed covers a go.mod whose first bytes are
// a UTF-8 byte order mark — real go Fatals parsing the whole file
// ("go.mod:1: unexpected input character '\ufeff'") before evaluating a
// single directive (confirmed live, 2026-10-02). Built via string
// concatenation, not embedded directly in a backtick literal, so the BOM
// rune appears exactly once, at byte offset 0, with no ambiguity about
// where a literal BOM character in the test source itself might land.
func TestParseGoModLeadingBOMIsMalformed(t *testing.T) {
	content := "\uFEFF" + `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1
`
	reqs, _, _, _, modulePath, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	want := []MalformedDirective{{Directive: "bom"}}
	if len(malformed) != len(want) || malformed[0] != want[0] {
		t.Errorf("got malformed %+v, want %+v", malformed, want)
	}
	// The BOM is stripped before scanning, so every directive after it —
	// including the module line on the very same first line — still
	// parses normally, on top of (not instead of) the malformed finding.
	if modulePath != "example.com/foo" {
		t.Errorf("got modulePath %q, want example.com/foo (BOM should be stripped, not just detected)", modulePath)
	}
	if len(reqs) != 1 || reqs[0] != (Requirement{Path: "github.com/pkg/errors", Version: "v0.9.1"}) {
		t.Errorf("got reqs %+v, want the one well-formed requirement after the BOM", reqs)
	}
}

// TestParseGoModNoBOMIsNotMalformed confirms the sibling correct-behavior
// case (an ordinary go.mod with no BOM) isn't disturbed by this fix.
func TestParseGoModNoBOMIsNotMalformed(t *testing.T) {
	content := `module example.com/foo

go 1.24

require github.com/pkg/errors v0.9.1
`
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(malformed) != 0 {
		t.Errorf("got malformed %+v, want none", malformed)
	}
}

// TestLineHasInvalidQuotedToken covers lineHasInvalidQuotedToken directly
// — see its own doc comment in gomod.go for the live-verification detail
// (go1.24.4/go1.26.8, GOPROXY=off) behind each case.
func TestLineHasInvalidQuotedToken(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		wantToken string
		wantBad   bool
	}{
		{name: "fine: ordinary require argument", s: "github.com/pkg/errors v0.9.1"},
		{name: "fine: properly double-quoted path with a space", s: `"../my mod" v1.0.0`},
		{name: "fine: double-quoted path containing a literal backtick", s: "\"github.com/pkg/err`ors\" v0.9.1"},
		{
			name:      "backtick-wrapped token",
			s:         "`github.com/pkg/errors` v0.9.1",
			wantToken: "`github.com/pkg/errors`",
			wantBad:   true,
		},
		{
			name:      "backtick-wrapped local replace target",
			s:         "`../local`",
			wantToken: "`../local`",
			wantBad:   true,
		},
		{
			name:      "single-quote-wrapped token",
			s:         "'github.com/pkg/errors' v0.9.1",
			wantToken: "'github.com/pkg/errors'",
			wantBad:   true,
		},
		{
			name:      "stray trailing backtick glued onto an otherwise-ordinary token",
			s:         "github.com/pkg/errors` v0.9.1",
			wantToken: "github.com/pkg/errors`",
			wantBad:   true,
		},
		{
			name: "unterminated double-quoted token: a different real Fatal, not this check's job",
			s:    `"github.com/pkg/errors v0.9.1`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, bad := lineHasInvalidQuotedToken(tt.s)
			if bad != tt.wantBad || (bad && tok != tt.wantToken) {
				t.Errorf("lineHasInvalidQuotedToken(%q) = (%q, %v), want (%q, %v)", tt.s, tok, bad, tt.wantToken, tt.wantBad)
			}
		})
	}
}

// TestParseGoModInvalidQuotedTokenIsMalformed is the regression test for a
// real bug: ParseGoMod's firstField/leadingQuotedString already knew a
// leading backtick isn't a valid go.mod quote-opener (see firstField's own
// doc comment), but nothing ever turned that knowledge into a rejected
// line — a backtick- or single-quote-wrapped (or glued-on) directive
// argument was instead extracted as an ordinary, if garbage, bare word and
// treated as well-formed. Live-verified (go1.24.4, go1.26.8, GOPROXY=off):
// every one of these shapes makes real `go build`/`go list -m all` Fatal
// immediately with "invalid quoted string: unquoted string cannot contain
// quote", before resolving a single requirement.
func TestParseGoModInvalidQuotedTokenIsMalformed(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantToken string
	}{
		{
			name:      "require argument backtick-wrapped",
			content:   "module example.com/myapp\n\ngo 1.21\n\nrequire `github.com/pkg/errors` v0.9.1\n",
			wantToken: "`github.com/pkg/errors`",
		},
		{
			name:      "require block entry backtick-wrapped",
			content:   "module example.com/myapp\n\ngo 1.21\n\nrequire (\n\t`github.com/pkg/errors` v0.9.1\n)\n",
			wantToken: "`github.com/pkg/errors`",
		},
		{
			name:      "module directive backtick-wrapped",
			content:   "module `example.com/foo`\n\ngo 1.21\n",
			wantToken: "`example.com/foo`",
		},
		{
			name:      "replace new side backtick-wrapped local path",
			content:   "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n\nreplace github.com/pkg/errors => `../local`\n",
			wantToken: "`../local`",
		},
		{
			name:      "tool directive backtick-wrapped",
			content:   "module example.com/myapp\n\ngo 1.24\n\ntool `golang.org/x/tools/cmd/stringer`\n\nrequire golang.org/x/tools v0.26.0\n",
			wantToken: "`golang.org/x/tools/cmd/stringer`",
		},
		{
			name:      "require argument single-quote-wrapped",
			content:   "module example.com/myapp\n\ngo 1.21\n\nrequire 'github.com/pkg/errors' v0.9.1\n",
			wantToken: "'github.com/pkg/errors'",
		},
		{
			name:      "stray trailing backtick glued onto an otherwise-ordinary require path",
			content:   "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/pkg/errors` v0.9.1\n",
			wantToken: "github.com/pkg/errors`",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqs, reps, tools, _, _, malformed, _, err := ParseGoMod(tt.content)
			if err != nil {
				t.Fatal(err)
			}
			want := []MalformedDirective{{Directive: "invalid-quoted-token", Path: tt.wantToken}}
			if len(malformed) != len(want) || malformed[0] != want[0] {
				t.Fatalf("got malformed %+v, want %+v", malformed, want)
			}
			// The malformed line must never also surface as an ordinary
			// (garbage) Requirement/Replacement/tool entry — that's the
			// whole point of catching it before parseRequireLine/
			// parseReplaceLine/parseToolLine get a chance to "succeed" on
			// the mangled token.
			for _, r := range reqs {
				if r.Path == tt.wantToken {
					t.Errorf("got the malformed token %q as an ordinary requirement too: %+v", tt.wantToken, reqs)
				}
			}
			for _, r := range reps {
				if r.New == tt.wantToken || r.Old == tt.wantToken {
					t.Errorf("got the malformed token %q as an ordinary replacement too: %+v", tt.wantToken, reps)
				}
			}
			for _, tl := range tools {
				if tl == tt.wantToken {
					t.Errorf("got the malformed token %q as an ordinary tool entry too: %+v", tt.wantToken, tools)
				}
			}
		})
	}
}

// TestParseGoModDoubleQuotedBacktickIsNotMalformed is the negative control
// for TestParseGoModInvalidQuotedTokenIsMalformed: a properly
// double-quoted token may legitimately contain a literal backtick
// character anywhere inside it (go.mod's double-quoted strings go through
// ordinary Go string unquoting, which has no special meaning for
// backtick) — confirmed live that real go parses this go.mod's directive
// fine (it only rejects the resulting module *path* later, at a different,
// unrelated validation stage this test doesn't exercise).
func TestParseGoModDoubleQuotedBacktickIsNotMalformed(t *testing.T) {
	content := "module example.com/myapp\n\ngo 1.21\n\nrequire \"github.com/pkg/err`ors\" v0.9.1\n"
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(malformed) != 0 {
		t.Errorf("got malformed %+v, want none", malformed)
	}
}

// TestParseGoModGluedBacktickOnVerbIsNotDoubleReported confirms a
// malformed-keyword-position backtick (no whitespace separating the
// directive keyword from the backtick at all) is left to the existing,
// more accurate goModUnknownDirective/checkGoModUnknownDirective check
// (real go reports "unknown directive: require`github.com/pkg/errors`"
// for this exact shape, confirmed live, since cutKeyword's own separator
// requirement means the line never matches the "require" keyword in the
// first place) — lineHasInvalidQuotedToken must not also fire here, which
// would misreport the wrong real-go error text alongside the correct one.
func TestParseGoModGluedBacktickOnVerbIsNotDoubleReported(t *testing.T) {
	content := "module example.com/myapp\n\ngo 1.21\n\nrequire`github.com/pkg/errors` v0.9.1\n"
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(malformed) != 0 {
		t.Errorf("got malformed %+v, want none (this shape is goModUnknownDirective's job, not ParseGoMod's)", malformed)
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

// TestParseRequireLineIndirectSubstringFalsePositive is the regression case
// for the fuzz-oracle false positive FuzzParseGoModRequire surfaced
// (STRATEGY.md run #679's go.work fix, left out of scope at the time): a
// module path that legitimately contains "indirect" as an ordinary
// substring, with no "// indirect" comment anywhere on the line, must come
// through untouched — not stripped, not reclassified — exactly like any
// other path would. module.CheckPath imposes no rule against the word
// "indirect" appearing in a path segment.
func TestParseRequireLineIndirectSubstringFalsePositive(t *testing.T) {
	r, ok := parseRequireLine("github.com/foo/0.0indirect v1.0.0")
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := Requirement{Path: "github.com/foo/0.0indirect", Version: "v1.0.0"}
	if r != want {
		t.Errorf("got %+v, want %+v", r, want)
	}
}

// TestParseRequireLineIndirectCommentVariants covers the real "// indirect"
// marker alongside two lines that must NOT be mistaken for it: the same
// comment with extra interior whitespace, and a different trailing comment
// entirely ("// direct"). All three must parse down to the identical bare
// path+version — the comment's exact text never leaks into either field,
// but a line that isn't the canonical "// indirect" marker also isn't
// specially recognized as one.
func TestParseRequireLineIndirectCommentVariants(t *testing.T) {
	want := Requirement{Path: "github.com/foo/bar", Version: "v1.0.0"}
	cases := []string{
		"github.com/foo/bar v1.0.0 // indirect",
		"github.com/foo/bar v1.0.0 //    indirect",
		"github.com/foo/bar v1.0.0 // direct",
	}
	for _, line := range cases {
		r, ok := parseRequireLine(line)
		if !ok {
			t.Errorf("parseRequireLine(%q): expected ok=true", line)
			continue
		}
		if r != want {
			t.Errorf("parseRequireLine(%q) = %+v, want %+v", line, r, want)
		}
	}
}

func TestLoadGoMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	content := "module example.com/foo\n\nrequire github.com/pkg/errors v0.9.1\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	reqs, _, _, _, _, _, _, err := LoadGoMod(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != "github.com/pkg/errors" {
		t.Errorf("got %+v", reqs)
	}

	if _, _, _, _, _, _, _, err := LoadGoMod(filepath.Join(dir, "missing.mod")); err == nil {
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
//
// The bare-keyword case ("require" with nothing after it at all) wants
// ok=true with an empty rest, not ok=false — see cutKeyword's own doc
// comment for why treating rest=="" as a non-match (this test's own
// expectation before this fix) is itself the bug: it made ParseGoMod
// silently drop a bare `require`/`exclude`/`tool`/`module` directive as
// an unrecognized line, with no MalformedDirective trace at all, even
// though real go Fatals on exactly this shape at go.mod parse time
// (confirmed live, go1.24.4, GOPROXY=off).
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
		{"require", "require", true, ""},
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
	reqs, _, _, _, _, _, _, err := ParseGoMod(content)
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

// TestGoWorkReplacesSkipsUnknownDirective is the regression test for a
// real bug (run #672): goWorkReplaces trusted every replace directive it
// found in a go.work file unconditionally, even when the same file also
// carried a directive go.work's own grammar doesn't support at all (see
// goWorkUnknownDirective's own doc comment for the live-verified real-go
// Fatal this reproduces — "unknown directive: <verb>", before resolving a
// single module in the workspace, including any replace directive
// sitting right next to it). Before this fix, this go.work's replace
// directive was returned as if it genuinely applied.
func TestGoWorkReplacesSkipsUnknownDirective(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.work")
	content := "go 1.24\n\n" +
		"use ./a\n\n" +
		"require example.com/bogus v1.0.0\n\n" +
		"replace example.com/bogus => ./b\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := goWorkReplaces(path); got != nil {
		t.Errorf("goWorkReplaces(%q) = %+v, want nil (go.work's 'require' directive makes real go Fatal before resolving any replace)", path, got)
	}
}

// TestGoWorkUnknownDirective covers goWorkUnknownDirective directly —
// see its own doc comment in gomod.go for the live-verification detail.
func TestGoWorkUnknownDirective(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantVerb string
		wantOK   bool
	}{
		{
			name:    "fine: ordinary use+replace go.work",
			content: "go 1.24\n\nuse ./a\n\nreplace example.com/dep => ./fork\n",
		},
		{
			name:     "require is not valid go.work grammar",
			content:  "go 1.24\n\nrequire example.com/bogus v1.0.0\n",
			wantVerb: "require",
			wantOK:   true,
		},
		{
			name:     "module is not valid go.work grammar",
			content:  "go 1.24\n\nmodule example.com/oops\n",
			wantVerb: "module",
			wantOK:   true,
		},
		{
			name:     "exclude is not valid go.work grammar",
			content:  "go 1.24\n\nexclude example.com/bogus v1.0.0\n",
			wantVerb: "exclude",
			wantOK:   true,
		},
		{
			name:     "tool is not valid go.work grammar",
			content:  "go 1.24\n\ntool example.com/bogus/cmd/x\n",
			wantVerb: "tool",
			wantOK:   true,
		},
		{
			name:     "ignore is never valid go.work grammar",
			content:  "go 1.26\n\nignore \"testdata\"\n",
			wantVerb: "ignore",
			wantOK:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verb, ok := goWorkUnknownDirective(tt.content)
			if ok != tt.wantOK || (ok && verb != tt.wantVerb) {
				t.Errorf("goWorkUnknownDirective(%q) = (%q, %v), want (%q, %v)", tt.content, verb, ok, tt.wantVerb, tt.wantOK)
			}
		})
	}
}

// TestGoWorkHasInvalidQuotedToken covers goWorkHasInvalidQuotedToken
// directly — see its own doc comment in gomod.go for the live-
// verification detail.
func TestGoWorkHasInvalidQuotedToken(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantToken string
		wantOK    bool
	}{
		{
			name:    "fine: ordinary use+replace go.work",
			content: "go 1.24\n\nuse ./a\n\nreplace example.com/dep => ./fork\n",
		},
		{
			name:      "backtick-wrapped local replace target",
			content:   "go 1.24\n\nuse ./a\n\nreplace example.com/dep => `./local`\n",
			wantToken: "`./local`",
			wantOK:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, ok := goWorkHasInvalidQuotedToken(tt.content)
			if ok != tt.wantOK || (ok && tok != tt.wantToken) {
				t.Errorf("goWorkHasInvalidQuotedToken(%q) = (%q, %v), want (%q, %v)", tt.content, tok, ok, tt.wantToken, tt.wantOK)
			}
		})
	}
}

// TestGoWorkReplacesFailsClosedOnInvalidQuotedToken confirms goWorkReplaces
// itself (not just the detector) refuses to trust any replace directive
// once this condition is found anywhere in the go.work — matching real
// go's refusal to resolve anything in a workspace whose go.work can't
// parse at all.
func TestGoWorkReplacesFailsClosedOnInvalidQuotedToken(t *testing.T) {
	dir := t.TempDir()
	gowork := filepath.Join(dir, "go.work")
	content := "go 1.24\n\nuse ./a\n\nreplace example.com/dep => `./local`\n"
	if err := os.WriteFile(gowork, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if reps := goWorkReplaces(gowork); reps != nil {
		t.Errorf("goWorkReplaces(%q) = %+v, want nil (the go.work can't parse at all)", gowork, reps)
	}
}

// TestGoModUnknownDirective covers goModUnknownDirective directly — see
// its own doc comment in gomod.go for the live-verification detail.
func TestGoModUnknownDirective(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantVerb  string
		wantBlock bool
		wantOK    bool
	}{
		{
			name:    "fine: ordinary go.mod",
			content: "module example.com/foo\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
		},
		{
			name:    "fine: legitimate retract directive",
			content: "module example.com/foo\n\ngo 1.21\n\nretract v1.0.0\n",
		},
		{
			name:    "fine: require( with no space before the paren",
			content: "module example.com/foo\n\ngo 1.21\n\nrequire(\n\tgithub.com/pkg/errors v0.9.1\n)\n",
		},
		{
			name:     "bogus single-line verb",
			content:  "module example.com/foo\n\ngo 1.21\n\nbogusverb oops\n",
			wantVerb: "bogusverb",
			wantOK:   true,
		},
		{
			name:     "wrong-case known verb is still unknown (case-sensitive)",
			content:  "Require github.com/pkg/errors v0.9.1\n",
			wantVerb: "Require",
			wantOK:   true,
		},
		{
			name:      "bogus verb opening a block",
			content:   "module example.com/foo\n\ngo 1.21\n\nbogusverb (\n\tfoo bar\n)\n",
			wantVerb:  "bogusverb",
			wantBlock: true,
			wantOK:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verb, block, ok := goModUnknownDirective(tt.content)
			if ok != tt.wantOK || (ok && (verb != tt.wantVerb || block != tt.wantBlock)) {
				t.Errorf("goModUnknownDirective(%q) = (%q, %v, %v), want (%q, %v, %v)", tt.content, verb, block, ok, tt.wantVerb, tt.wantBlock, tt.wantOK)
			}
		})
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
		got, ok := selectReplace(merged, "example.com/foo", "v1.0.0", nil)
		if !ok || got.New != "../v1fork" {
			t.Errorf("selectReplace(v1.0.0) = %+v, %v; want ../v1fork, true (real go still uses the go.mod replace here)", got, ok)
		}
	})

	t.Run("go.mod general replace survives", func(t *testing.T) {
		base := []Replacement{{Old: "example.com/foo", New: "../v1fork"}}
		merged := mergeReplaces(base, overlay)
		got, ok := selectReplace(merged, "example.com/foo", "v1.0.0", nil)
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
	got, ok := selectReplace(merged, "example.com/foo", "v1.0.0", nil)
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
	got, ok := selectReplace(merged, "example.com/foo", "v1.0.0", nil)
	if !ok || got.New != "../v2fork" {
		t.Errorf("selectReplace(v1.0.0) = %+v, %v; want ../v2fork, true (go.work wins an exact-version tie)", got, ok)
	}
}

// TestHasIgnoreDirective covers both the presence/absence cases and the
// one false-positive risk its own doc comment names: a line that happens
// to read "ignore ..." only because it's an entry inside some *other*
// directive's block, not a top-level `ignore` directive at all.
func TestHasIgnoreDirective(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"absent", "module example.com/foo\n\ngo 1.26\n", false},
		{"single line", "module example.com/foo\n\ngo 1.26\n\nignore ./testdata\n", true},
		{"block form", "module example.com/foo\n\ngo 1.26\n\nignore (\n\t./a\n\t./b\n)\n", true},
		{"no space before paren", "module example.com/foo\n\ngo 1.26\n\nignore(\n\t./a\n)\n", true},
		{
			"entry inside unrelated block isn't mistaken for top-level ignore",
			"module example.com/foo\n\ngo 1.26\n\nrequire (\n\tignore v1.0.0\n)\n",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasIgnoreDirective(tt.content); got != tt.want {
				t.Errorf("hasIgnoreDirective(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

// TestGoDirectiveVersion covers the version-extraction helper
// checkIgnoreDirectiveTooOld relies on: present, absent, and the "go ("
// shape real go.mod syntax doesn't actually support (confirmed live
// elsewhere in this file — ParseGoMod's own "go" dispatch — to Fatal with
// "unknown block type: go" rather than opening a block), which must not
// be misread as the literal version string "(".
func TestGoDirectiveVersion(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"present", "module example.com/foo\n\ngo 1.26.8\n", "1.26.8"},
		{"absent", "module example.com/foo\n", ""},
		{"godebug not mistaken for go", "module example.com/foo\n\ngodebug http2client=0\n", ""},
		{"go block form skipped, not read as \"(\"", "module example.com/foo\n\ngo (\n\t1.26\n)\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := goDirectiveVersion(tt.content); got != tt.want {
				t.Errorf("goDirectiveVersion(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}

// TestGoVersionAtLeast pins the exact go1.25 boundary
// checkIgnoreDirectiveTooOld compares against, plus the fail-closed
// convention for an empty or unparsable version.
func TestGoVersionAtLeast(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"", false},
		{"1.24.4", false},
		{"go1.24.4", false},
		{"1.24", false},
		{"1.25", true},
		{"go1.25.14", true},
		{"1.26.0", true},
		{"1.27.1", true},
		{"2.0", true},
		{"bogus", false},
	}
	for _, tt := range tests {
		if got := goVersionAtLeast(tt.version, 1, 25); got != tt.want {
			t.Errorf("goVersionAtLeast(%q, 1, 25) = %v, want %v", tt.version, got, tt.want)
		}
	}
}
