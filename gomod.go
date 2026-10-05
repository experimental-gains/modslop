package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// Requirement is one entry from a go.mod require block.
type Requirement struct {
	Path    string
	Version string
}

// Replacement is one entry from a go.mod replace directive.
type Replacement struct {
	Old        string // module path being replaced
	OldVersion string // version on the old side, or "" if the replace has none (applies to every version of Old)
	New        string // another module path, or a local filesystem path
	NewVersion string // version on the new side, or "" for a local filesystem path (see IsLocal)
}

// Godebug is one key=value entry from a go.mod `godebug` directive (single
// line or block form). Only well-formed "key=value" entries are recorded
// here — see parseGodebugLine's own doc comment for why a malformed
// godebug line isn't surfaced as a MalformedDirective yet, unlike every
// other directive family ParseGoMod recognizes.
type Godebug struct {
	Key   string
	Value string
}

// MalformedDirective is a require, exclude, tool, module, or replace
// directive line ParseGoMod recognized the keyword for but couldn't parse a
// well-formed argument list out of — see ParseGoMod's sixth return value
// and checkMalformedDirectives (check.go) for why this is worth its own
// finding rather than being silently dropped the way an ordinary
// unrecognized line is. For require/exclude that's a line missing its
// version field entirely; for tool/module (see parseToolLine's own doc
// comment) it's a line with zero or more than one argument; for replace
// (see parseReplaceLine) it's a line with no "=>" arrow at all, or with the
// wrong number of fields on either side of it — every one of these real
// go.mod directive families golang.org/x/mod/modfile's rule.go Fatals on
// immediately at parse time, just with a different field-count rule per
// family (require/exclude take exactly two fields, tool/module take
// exactly one, replace's grammar is the arrow-separated shape documented
// on parseReplaceLine). A sixth, distinct shape — Directive ==
// "module-repeated" — covers a *second*, individually well-formed
// `module` directive anywhere in the file: not a per-line argument-count
// problem at all, but a file-level Fatal (golang.org/x/mod/modfile's
// rule.go: "repeated module statement") that only exists once a second
// occurrence appears; see ParseGoMod's doc comment on modulePath/
// moduleSeen for why this can't be folded into the ordinary "module" case
// above it.
type MalformedDirective struct {
	Directive string // "require", "exclude", "tool", "module", "module-repeated", "go", "go-repeated", "toolchain", "toolchain-repeated", "replace", "ignore", "ignore-too-old", "retract", "bom", "block-comment", "unterminated-block", "invalid-quoted-token", "unterminated-quoted-string", or "toolchain-unterminated-quoted-string"
	// Path is a best-effort guess at the module path the author was
	// naming — the line's own leading field, e.g. "github.com/pkg/errors"
	// for a require line missing its version entirely, or the first
	// (extraneous-trailing-content) field of a malformed tool/module/
	// replace line. For "module-repeated" it's the repeated directive's
	// own (well-formed) path. For "invalid-quoted-token" it's the actual
	// malformed token itself (e.g. "`github.com/pkg/errors`"), not a
	// directive argument guess — see lineHasInvalidQuotedToken. For
	// "unterminated-quoted-string" it's everything from the unterminated
	// opening quote to the end of the line (e.g. `"github.com/pkg/errors
	// v0.9.1`) — see lineHasUnterminatedQuotedString. For
	// "unterminated-block" it's the block's own directive keyword (e.g.
	// "require"), not a module path at all — see ParseGoMod's own doc
	// comment on blockKind. "" when the line has no leading field to
	// recover at all (e.g. a bare "require" or "tool" with nothing after
	// it but whitespace, or a "bom" entry — see ParseGoMod's own doc
	// comment — which names no module at all, being a whole-file encoding
	// problem rather than a single directive line).
	Path string
}

// newMalformedDirective builds a MalformedDirective from a require/exclude/
// replace line's raw argument text (everything after the directive
// keyword, already rejected by the caller's own parser) by taking its own
// leading field as the best-effort Path guess — the same token
// parseRequireLine/parseReplaceLine itself would have tried to use as the
// module path.
func newMalformedDirective(directive, rest string) MalformedDirective {
	path, _ := firstField(rest)
	return MalformedDirective{Directive: directive, Path: path}
}

// IsLocal reports whether the replacement points at a local filesystem
// path rather than a fetchable module. Per golang.org/x/mod/modfile's
// IsDirectoryPath (rule.go) — the real go tool's own grammar (verified
// live: `replace foo => ..` builds and `go list -m all` resolves it
// straight off disk, no network call) — that's true when the target is
// exactly "." or "..", begins with "./", "../", "/", or "\", or starts
// with a drive letter followed by ":" (e.g. "C:..."). An earlier version
// of this function stopped at the bare "." / ".." forms plus "./" /
// "../" / absolute-Unix-path, on the theory that the remaining
// Windows-style forms (".\", "..\", bare "\", a drive letter) can't
// matter because "a go.mod containing one fails to parse at all on a
// non-Windows host" — true for every form that contains a backslash
// (real go's parseReplace Fatals with "replacement directory appears to
// be Windows path (on a non-windows system)" the instant
// filepath.Separator is '/' and the new side contains a `\`, regardless
// of what IsDirectoryPath itself says), but NOT true for a drive-letter
// path spelled with forward slashes, e.g. "C:/local/fork": that shape has
// no backslash at all, so the Windows-path Fatal never fires, and real
// go's own IsDirectoryPath recognizes it as a directory path requiring no
// version. Verified live, go1.24.4, GOPROXY=off: a go.mod requiring
// github.com/pkg/errors v0.9.1 with `replace github.com/pkg/errors =>
// C:/Users/foo/local/errors` (no version) builds the go.mod with zero
// parse error — `go list -m all` Fatals only later, at module-resolution
// time, with "reading C:/Users/foo/local/errors/go.mod: ... no such file
// or directory" (a missing-directory error, not a go.mod defect), and
// never touches the network. Before this fix, IsLocal() returned false
// for that path, so CheckAll's require+replace resolution loop didn't
// skip it as local and instead checked the literal string
// "C:/Users/foo/local/errors" against the module proxy as if it were a
// real dependency (a guaranteed "not-found" false positive), and
// checkReplaceMissingVersion separately flagged the same line as
// "replace-missing-version" — a second false positive, since the real go
// command accepts this exact line with no version and no Fatal at all.
func (r Replacement) IsLocal() bool {
	return r.New == "." || strings.HasPrefix(r.New, "./") || strings.HasPrefix(r.New, `.\`) ||
		r.New == ".." || strings.HasPrefix(r.New, "../") || strings.HasPrefix(r.New, `..\`) ||
		strings.HasPrefix(r.New, "/") || strings.HasPrefix(r.New, `\`) ||
		len(r.New) >= 2 && ('A' <= r.New[0] && r.New[0] <= 'Z' || 'a' <= r.New[0] && r.New[0] <= 'z') && r.New[1] == ':' ||
		filepath.IsAbs(r.New)
}

// ParseGoMod extracts require, replace, and tool entries from a go.mod
// file's content. It handles both single-line ("require foo/bar v1.0.0")
// and block ("require (\n\tfoo/bar v1.0.0\n)") forms for each directive.
// It deliberately does not depend on golang.org/x/mod so this tool has
// zero external dependencies.
//
// The third return value is the list of package import paths named by
// `tool` directives, in file order (not deduped — that's the check
// layer's job, since what counts as a duplicate can depend on how paths
// get resolved to modules). `tool` is a Go 1.24+ directive that records
// a tool dependency (e.g. `tool golang.org/x/tools/cmd/stringer`, added
// by `go get -tool`); critically, the package path it names isn't
// guaranteed to be covered by any `require` entry the rest of this
// parser already extracts — a hand-written or AI-generated go.mod can
// have a `tool` line with no matching `require` at all, which is exactly
// the gap this return value exists to let the check layer close.
//
// The fourth return value is the list of module+version pairs named by
// `exclude` directives, in file order. `exclude`'s grammar
// (go.dev/ref/mod#go-mod-file-exclude) is exactly "path version" — no
// "// indirect" suffix, no arrow — so it reuses Requirement and
// parseRequireLine rather than a dedicated type/parser. This exists to
// let the check layer catch a self-contradictory go.mod: `go` refuses to
// build at all when a `require` directive's exact version is also named
// by an `exclude` directive in the same go.mod, and it does so as a pure
// local go.mod-authoring error — no network call involved. Confirmed
// live: `require github.com/pkg/errors v0.9.1` + `exclude
// github.com/pkg/errors v0.9.1` in the same go.mod makes `go build`/`go
// list -m all` fail immediately with "go: ignoring requirement on
// excluded version github.com/pkg/errors v0.9.1" / "go: updates to
// go.mod needed" — reproduced with GOPROXY=off too, confirming it's
// fully local. Before this return value existed, ParseGoMod silently
// dropped every `exclude` directive on the floor, so modslop had no way
// to see this — an AI-generated go.mod that excludes the very version it
// requires (e.g. from misunderstanding how to "pin away" a vulnerable
// version) reported "nothing flagged" despite being a go.mod the real
// go command cannot use at all.
//
// The fifth return value is the module's own path, from its `module`
// directive — "" if the file has none (malformed) or ParseGoMod is being
// used on a go.work file via goWorkReplaces (go.work has no `module`
// directive at all; a go.work's own `module`-shaped line, if any ever
// appeared, would just be ignored the same way an unrecognized directive
// already is). This exists so the check layer can recognize a `tool`
// directive naming a package inside the main module itself (see
// CheckTools) as needing no proxy lookup at all — confirmed live: a
// go.mod with `module example.com/mymodule` and `tool example.com/
// mymodule/cmd/gen` (a local internal tool, no require line for it
// anywhere, and no external module involved) builds, vets, and runs `go
// tool gen` cleanly with GOPROXY=off, and `go mod tidy` leaves the tool
// line untouched — entirely local, exactly like a local filesystem
// replace target. Before this return value existed, ParseGoMod had no
// way to tell CheckTools such a tool path was the main module's own
// code rather than an external dependency.
//
// A *second* well-formed `module` directive anywhere in the file (a
// second single-line directive, a second block-form entry, or one of
// each) does not overwrite modulePath — golang.org/x/mod/modfile's own
// rule.go Fatals immediately with "repeated module statement" the
// instant a second one appears, before resolving a single requirement.
// Confirmed live, 2026-10-02 (go1.24.4, GOPROXY=off): a go.mod with two
// `module` lines (e.g. one accidentally left behind while editing, or an
// AI-generated go.mod that re-declares the module after a merge/rewrite)
// fails to build this way regardless of whether every requirement in it
// is real. modulePath keeps the *first* module directive's value — the
// best-effort guess at which path the author actually intended, and the
// one that keeps a `tool` directive legitimately inside that first
// module from being misclassified as an external, unresolved dependency
// (see CheckTools) — while every subsequent `module` directive is
// recorded in the sixth return value as its own "module-repeated"
// MalformedDirective instead of being silently dropped or allowed to
// clobber modulePath. Before this fix, modulePath held whichever
// `module` directive was parsed *last*, so a go.mod this broken reported
// "nothing flagged" instead of surfacing its one real, unconditional
// problem, and could additionally misreport a `tool` directive inside
// the *first* module's own path as a hallucinated external import, since
// modulePath no longer matched it.
//
// `module`, like require/replace/tool/exclude, *does* have a
// parenthesized block form — golang.org/x/mod/modfile's own lexer
// (read.go's parseStmt) builds a LineBlock for any verb immediately
// followed by "(", with no per-verb exception, and modfile.Parse's own
// semantic layer (rule.go, the switch on x.Token[0] inside the
// *LineBlock case) explicitly lists "module" alongside "require"/
// "replace"/"exclude"/"tool" as an allowed block verb — go.dev/ref/
// mod#go-mod-file-module's prose only shows the single-line form, but
// doesn't say the block form is disallowed either. Confirmed live,
// 2026-09: a go.mod written as
//
//	module (
//		example.com/foo/mymodule
//	)
//
//	go 1.24
//
//	tool example.com/foo/mymodule/cmd/gen
//
// builds, `go list -m` reports the correct module path, and `go tool
// gen` runs cleanly with GOPROXY=off — `go mod tidy` even rewrites it to
// the canonical single-line form, confirming this is accepted, if
// unusual, syntax rather than a lax-mode-only tolerance. Before this
// fix, ParseGoMod's `module` handling never checked whether its rest was
// "(" (unlike every other directive's block-form check just above it in
// this same function) and fed the literal string "(" straight into
// parseToolLine, so modulePath ended up as the bogus value "(" instead
// of the real module path — and the block's actual path line
// ("example.com/foo/mymodule") was left dangling at top level, matching
// no keyword, silently dropped. CheckTools could then never recognize
// the `tool` directive above as covered by the main module, and reported
// a spurious high-severity "not-found" against
// example.com/foo/mymodule/cmd/gen — a false positive on a go.mod real
// go builds and runs with zero network access, purely because of an
// unusual (if real, AI-plausibly-generated) module-directive style.
//
// The sixth return value collects every require/exclude directive line
// ParseGoMod recognized the keyword for but couldn't parse an argument out
// of — in practice, today, that's exactly a require or exclude line naming
// a module path with no version field at all (see parseRequireLine).
// go.mod's own grammar (golang.org/x/mod/modfile's rule.go) requires
// exactly two fields for both directives, and real cmd/go Fatals
// immediately at go.mod PARSE time on anything else — confirmed live,
// 2026-09 (go1.24.4, GOPROXY=off to rule out any network dependency): a
// go.mod with a bare `require github.com/pkg/errors` (no version) or
// `exclude github.com/pkg/errors` (same) makes `go build`/`go list -m all`
// fail immediately with "usage: require module/path v1.2.3" ("usage:
// exclude module/path v1.2.3" for exclude), before contacting the network
// or resolving a single dependency — the identical "self-contradictory,
// unbuildable go.mod, not a heuristic" class checkDuplicateRequires,
// checkExcludedRequirements, checkAmbiguousComparisonQueries, and
// checkReplaceMissingVersion already exist to catch for other shapes.
// Before this return value existed, parseRequireLine's own ok=false for
// this shape (see its doc comment) meant every one of this function's four
// require/exclude call sites (single-line and block, for both directives)
// silently dropped the line on the floor with no trace at all — a go.mod
// written this way (a plausible mistake: adding a dependency and
// forgetting its version, or deleting a version while editing without
// removing the whole line — both equally easy for a human or an AI
// assistant to produce) reported "checked N requirement(s), nothing
// flagged" despite being a go.mod the real go command refuses to build
// under any circumstances. See checkMalformedDirectives in check.go for
// the finding this return value now feeds.
//
// It also collects a `tool` or `module` directive line recognized by
// keyword but carrying the wrong number of arguments (zero, or more than
// one) — see parseToolLine's own doc comment for the confirmed-live
// Fatal this produces in real go. That's a different field-count rule
// than require/exclude's (tool/module take exactly one argument, not
// two), but the identical "recognized the keyword, couldn't parse a
// valid directive out of it, don't drop it silently" shape, so it's
// folded into the same sixth return value and the same
// checkMalformedDirectives finding family rather than a separate one.
//
// It also collects a `replace` directive line recognized by keyword but
// rejected by parseReplaceLine — no "=>" arrow at all, or the wrong number
// of fields on either side of it. Before this fix, both of ParseGoMod's
// replace call sites (single-line and block form) simply discarded such a
// line (unlike every other directive family, which already fed its own
// unparseable lines into this return value) — the one gap
// checkReplaceMissingVersion's own existence doesn't cover, since that
// check only ever sees replace directives parseReplaceLine already
// accepted as well-formed. Confirmed live, 2026-09-30 (go1.24.4,
// GOPROXY=off): a go.mod with a bare `replace github.com/pkg/errors` (no
// arrow at all) or `replace github.com/pkg/errors =>` (arrow, nothing
// after it) both make `go build`/`go list -m all` fail immediately with
// "usage: replace module/path [v1.2.3] => other/module v1.4 ...", before
// contacting the network — reproduced for both the single-line and
// block (`replace (\n\tgithub.com/pkg/errors\n)`) forms. A go.mod written
// this way (a plausible mistake: starting a replace line, then abandoning
// or incompletely editing it) reported "checked N requirement(s), nothing
// flagged" despite being a go.mod the real go command refuses to build
// under any circumstances.
//
// It also collects a `retract` directive line (single-line or block form)
// recognized by keyword but rejected by parseRetractLine — a bare
// `retract` with no version/interval at all, an interval missing its
// comma or closing bracket, or a version/interval followed by a stray
// trailing field. Unlike every other directive family above, the retract
// directive's own well-formed value is never kept in any return value
// here — no existing check needs the AUDITED go.mod's own retract data,
// only whether a malformed one was written; see parseRetractLine's own
// doc comment for the five distinct confirmed-live Fatal wordings this
// one shape can produce, and goModKnownVerbs for why "retract" was
// already treated as a recognized verb (correctly) well before this
// parser learned to look at what follows it.
func ParseGoMod(content string) ([]Requirement, []Replacement, []string, []Requirement, string, []MalformedDirective, []Godebug, error) {
	var reqs []Requirement
	var reps []Replacement
	var tools []string
	var excludes []Requirement
	var modulePath string
	var moduleSeen bool
	var goSeen bool
	var toolchainSeen bool
	var malformed []MalformedDirective
	var godebugs []Godebug
	// A leading UTF-8 byte order mark makes the *entire* file unparseable
	// to the real go toolchain — confirmed live, 2026-10-02 (go1.24.4): a
	// go.mod whose first three bytes are the UTF-8 BOM (EF BB BF, i.e. the
	// single rune U+FEFF) makes both `go build` and `go list -m all` fail
	// immediately with "go: errors parsing go.mod: go.mod:1: unexpected
	// input character '\ufeff'", before a single directive is evaluated —
	// a real, if rare, way for a go.mod to end up broken: Windows tooling
	// commonly writes UTF-8-with-BOM by default (pre-6 PowerShell's
	// `Set-Content -Encoding UTF8`, Notepad's "UTF-8" option, some
	// Windows-hosted editors/IDEs), so a hand-edited or AI-assisted go.mod
	// saved that way on Windows is a plausible, not contrived, real-world
	// shape. Before this fix, cutKeyword's HasPrefix match on the first
	// line silently failed (the line reads "\ufeffmodule ..." with the BOM
	// still glued onto the front of "module"), so the line fell straight
	// through every keyword check to the same silent, zero-trace drop any
	// unrecognized line gets — modulePath ended up "", but every ordinary
	// require line later in the file still parsed and checked fine,
	// reporting "checked N requirement(s), nothing flagged" for a go.mod
	// the real go command refuses to load at all, the identical
	// "self-contradictory/unbuildable, not a heuristic" blind spot
	// checkDuplicateRequires/checkExcludedRequirements/
	// checkAmbiguousComparisonQueries/checkReplaceMissingVersion/
	// checkMalformedDirectives already exist to close for other go.mod
	// shapes. The BOM is stripped here (rather than left in place) so
	// every directive after it — including, often, the `module` line
	// itself — still parses normally and gets checked like any other
	// go.mod, on top of (not instead of) the dedicated finding this
	// produces via checkMalformedDirectives.
	if rest, ok := strings.CutPrefix(content, "\uFEFF"); ok {
		malformed = append(malformed, MalformedDirective{Directive: "bom"})
		content = rest
	}
	// A "/* ... */" block comment \u2014 unlike a "//" line comment \u2014 is not
	// valid go.mod/go.work syntax at all; see stripBlockComments's own doc
	// comment for the live-confirmed real-go Fatal this produces and why
	// its contents are still blanked out (rather than left for the main
	// scan below to misparse as live directives) despite real go never
	// actually resuming parsing past one.
	if rest, ok := stripBlockComments(content); ok {
		malformed = append(malformed, MalformedDirective{Directive: "block-comment"})
		content = rest
	}
	scanner := bufio.NewScanner(strings.NewReader(content))
	blockKind := "" // "", "require", "replace", "tool", "exclude", "module", "godebug", "ignore", or "retract"

	for scanner.Scan() {
		line := stripComment(scanner.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if blockKind == "" {
			if rest, ok := cutKeyword(trimmed, "require"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					blockKind = "require"
					continue
				}
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if r, ok := parseRequireLine(rest); ok {
					reqs = append(reqs, r)
				} else {
					malformed = append(malformed, newMalformedDirective("require", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "replace"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					blockKind = "replace"
					continue
				}
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if r, ok := parseReplaceLine(rest); ok {
					reps = append(reps, r)
				} else {
					malformed = append(malformed, newMalformedDirective("replace", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "tool"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					blockKind = "tool"
					continue
				}
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if t, ok := parseToolLine(rest); ok {
					tools = append(tools, t)
				} else {
					malformed = append(malformed, newMalformedDirective("tool", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "exclude"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					blockKind = "exclude"
					continue
				}
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if r, ok := parseRequireLine(rest); ok {
					excludes = append(excludes, r)
				} else {
					malformed = append(malformed, newMalformedDirective("exclude", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "module"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					blockKind = "module"
					continue
				}
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if m, ok := parseToolLine(rest); ok {
					if moduleSeen {
						malformed = append(malformed, MalformedDirective{Directive: "module-repeated", Path: m})
					} else {
						modulePath = m
						moduleSeen = true
					}
				} else {
					malformed = append(malformed, newMalformedDirective("module", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "go"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					// Real go has no block form for `go` ("unknown block
					// type: go") — not modeled as its own MalformedDirective
					// yet, so this line is left unrecognized rather than
					// risking parseToolLine misreading the bare "(" as a
					// version.
					continue
				}
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if v, ok := parseToolLine(rest); ok {
					if goSeen {
						malformed = append(malformed, MalformedDirective{Directive: "go-repeated", Path: v})
					} else {
						goSeen = true
					}
				} else {
					malformed = append(malformed, newMalformedDirective("go", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "toolchain"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					// Same "no block form" reasoning as `go` above —
					// real go Fatals with "unknown block type: toolchain".
					continue
				}
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					// Not the generic "unterminated-quoted-string" directive
					// used by every other directive family below — see
					// checkMalformedDirectives' own dedicated
					// "toolchain-unterminated-quoted-string" branch for why
					// `toolchain` specifically needs its own wording here.
					malformed = append(malformed, MalformedDirective{Directive: "toolchain-unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if v, ok := parseToolLine(rest); ok {
					if toolchainSeen {
						malformed = append(malformed, MalformedDirective{Directive: "toolchain-repeated", Path: v})
					} else {
						toolchainSeen = true
					}
				} else {
					malformed = append(malformed, newMalformedDirective("toolchain", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "ignore"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					blockKind = "ignore"
					continue
				}
				// `ignore` takes exactly one argument, the same fixed-count
				// grammar as `tool`/`module` (see parseToolLine's own doc
				// comment and the "ignore" entry in malformedDirectiveUsage) —
				// golang.org/x/mod/modfile's rule.go gives it the identical
				// `if len(args) != 1 { errorf("ignore directive expects
				// exactly one argument") }` shape. Confirmed live, 2026-10-03
				// (go1.26.8, GOPROXY=off): a bare `ignore` and `ignore ./a
				// ./b` both Fatal `go list -m all`/`go build` immediately with
				// that exact message, before resolving a single dependency.
				// The valid single argument itself isn't kept anywhere — no
				// existing check needs the list of ignored paths, only
				// whether a malformed one was written.
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if _, ok := parseToolLine(rest); !ok {
					malformed = append(malformed, newMalformedDirective("ignore", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "retract"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					blockKind = "retract"
					continue
				}
				// See parseRetractLine's own doc comment for the five
				// distinct confirmed-live Fatal wordings a malformed
				// retract argument can produce — all five are detected
				// here as a single "malformed" shape, the same
				// one-finding-per-line granularity checkMalformedDirectives
				// already uses for every other directive family. The
				// parsed version/interval itself isn't kept anywhere — no
				// existing check needs the audited go.mod's OWN retract
				// data (retract.go's retraction() only ever looks at a
				// dependency's upstream go.mod, fetched from the proxy and
				// parsed with golang.org/x/mod/modfile directly) — only
				// whether a malformed one was written.
				if tok, bad := lineHasUnterminatedQuotedString(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				} else if tok, bad := lineHasInvalidQuotedToken(rest); bad {
					malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				} else if !parseRetractLine(rest) {
					malformed = append(malformed, newMalformedDirective("retract", rest))
				}
				continue
			}
			if rest, ok := cutKeyword(trimmed, "godebug"); ok {
				rest = strings.TrimSpace(rest)
				if rest == "(" {
					blockKind = "godebug"
					continue
				}
				if g, ok := parseGodebugLine(rest); ok {
					godebugs = append(godebugs, g)
				}
				// A malformed godebug line isn't recorded as a
				// MalformedDirective yet — see Godebug's own doc comment —
				// so it falls through to the same silent drop an ordinary
				// unrecognized line gets, unchanged from before this
				// directive was recognized at all.
				continue
			}
			continue
		}

		if trimmed == ")" {
			blockKind = ""
			continue
		}
		// A block entry's own content can carry the same invalid-quoted-
		// token shape the single-line dispatch above already checks for
		// (confirmed live: a `require (\n\t`github.com/pkg/errors` v0.9.1\n)`
		// block Fatals identically to its single-line form) — checked once
		// here, ahead of the per-blockKind switch, rather than duplicated
		// into every case below, since it applies uniformly regardless of
		// which directive's block is open (godebug deliberately excepted,
		// matching parseGodebugLine's own not-yet-tracked malformed state —
		// see its doc comment).
		if blockKind != "godebug" {
			if tok, bad := lineHasUnterminatedQuotedString(trimmed); bad {
				malformed = append(malformed, MalformedDirective{Directive: "unterminated-quoted-string", Path: tok})
				continue
			}
			if tok, bad := lineHasInvalidQuotedToken(trimmed); bad {
				malformed = append(malformed, MalformedDirective{Directive: "invalid-quoted-token", Path: tok})
				continue
			}
		}
		switch blockKind {
		case "require":
			if r, ok := parseRequireLine(trimmed); ok {
				reqs = append(reqs, r)
			} else {
				malformed = append(malformed, newMalformedDirective("require", trimmed))
			}
		case "replace":
			if r, ok := parseReplaceLine(trimmed); ok {
				reps = append(reps, r)
			} else {
				malformed = append(malformed, newMalformedDirective("replace", trimmed))
			}
		case "tool":
			if t, ok := parseToolLine(trimmed); ok {
				tools = append(tools, t)
			} else {
				malformed = append(malformed, newMalformedDirective("tool", trimmed))
			}
		case "exclude":
			if r, ok := parseRequireLine(trimmed); ok {
				excludes = append(excludes, r)
			} else {
				malformed = append(malformed, newMalformedDirective("exclude", trimmed))
			}
		case "retract":
			// Same single-version-or-bracketed-interval grammar as the
			// single-line case above, confirmed live for the block-entry
			// form too, 2026-10-04 (go1.24.4): a `retract (\n\tv1.0.0
			// extra\n)` block whose entry carries a stray trailing token
			// Fatals identically to its single-line form ("unexpected
			// token after version: ..."), while a well-formed
			// one-version/interval-per-line block parses and resolves
			// cleanly.
			if !parseRetractLine(trimmed) {
				malformed = append(malformed, newMalformedDirective("retract", trimmed))
			}
		case "godebug":
			if g, ok := parseGodebugLine(trimmed); ok {
				godebugs = append(godebugs, g)
			}
		case "ignore":
			// Same one-argument grammar as the single-line case above,
			// confirmed live for the block-entry form too, 2026-10-03
			// (go1.26.8): an `ignore (\n\t./a ./b\n)` block whose entry
			// carries two tokens Fatals identically ("ignore directive
			// expects exactly one argument"), while a well-formed
			// single-path-per-line block parses and resolves cleanly.
			if _, ok := parseToolLine(trimmed); !ok {
				malformed = append(malformed, newMalformedDirective("ignore", trimmed))
			}
		case "module":
			// A real go.mod's block form only permits a single line here
			// (modfile.Parse errors with "repeated module statement" on a
			// second one) — see the moduleSeen handling below, shared with
			// the single-line "module" case above, for why a second module
			// path (whether from a second block entry or a second
			// single-line directive elsewhere in the file) is recorded as
			// its own "module-repeated" MalformedDirective instead of
			// silently overwriting modulePath.
			if m, ok := parseToolLine(trimmed); ok {
				if moduleSeen {
					malformed = append(malformed, MalformedDirective{Directive: "module-repeated", Path: m})
				} else {
					modulePath = m
					moduleSeen = true
				}
			} else {
				malformed = append(malformed, newMalformedDirective("module", trimmed))
			}
		}
	}
	// A block directive (`require (`, `replace (`, `tool (`, `exclude (`,
	// `module (`, `godebug (`, `ignore (`, or `retract (`) that's still
	// open when the file ends — no matching ")" line was ever seen — is a
	// file-level Fatal to the real go toolchain, not a per-line one.
	// Confirmed live, 2026-10-04 (go1.24.4, GOPROXY=off): a go.mod reading
	//
	//	module example.com/foo
	//
	//	go 1.24
	//
	//	require (
	//		github.com/pkg/errors v0.9.1
	//
	// (no closing ")") makes `go build`/`go list -m all` Fatal immediately
	// with "go.mod:7: syntax error (unterminated block started at
	// go.mod:5:1)", before a single requirement resolves — reproduced
	// identically for replace/tool/exclude/module/godebug/ignore/retract
	// blocks too, since golang.org/x/mod/modfile's own line scanner
	// (read.go) tracks exactly one open-block state file-wide and Fatals
	// on EOF the same way regardless of which keyword opened it. A
	// plausible real-world cause: a merge conflict, a truncated copy-
	// paste, or an interrupted `go mod edit` leaving a block's closing
	// line missing from an otherwise huge, otherwise-valid go.mod.
	//
	// Before this fix, ParseGoMod's own scanner loop just exits when
	// bufio.Scanner runs out of lines, with blockKind still set to
	// whatever block was open — every entry collected inside it is kept
	// exactly as if the file had closed the block properly, and nothing
	// records that the file never did. A go.mod broken this way reported
	// "checked N requirement(s)" (or worse, individual findings about
	// those entries) instead of the one finding that actually matters:
	// the file the real go command refuses to parse at all, the
	// identical "self-contradictory, unbuildable go.mod, not a
	// heuristic" class checkMalformedDirectives and its siblings already
	// exist to catch for every other shape of this problem. Path carries
	// the block's own directive keyword (e.g. "require"), not a module
	// path guess — there may be several, or zero, recoverable entries
	// inside an unterminated block, the same "doesn't name a module at
	// all" reasoning the "bom" and "block-comment" cases already use Path
	// for.
	if blockKind != "" {
		malformed = append(malformed, MalformedDirective{Directive: "unterminated-block", Path: blockKind})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, nil, "", nil, nil, err
	}
	return reqs, reps, tools, excludes, modulePath, malformed, godebugs, nil
}

// parseRequireLine parses one "module/path v1.2.3" require or exclude
// entry. golang.org/x/mod/modfile's rule.go gives require and exclude the
// identical grammar — exactly two fields, module path and version — and
// Fatals with "usage: require module/path v1.2.3" (or the exclude
// equivalent) whenever a line carries more than two, not just when it
// carries fewer than two. Confirmed live, 2026-10 (go1.24.4, GOPROXY=off):
// a go.mod with `require github.com/pkg/errors v0.9.1 extra` (a stray
// trailing word — a plausible hand-edit or merge-conflict artifact) Fatals
// `go build`/`go list -m all` immediately with that exact message, for
// both the single-line and block forms, and for exclude too. Before this
// fix, the trailing field beyond the version was silently discarded —
// `version, _ := firstField(rest)` — so a require/exclude line like this
// was accepted as an ordinary, valid two-field entry naming only its first
// two tokens, the same "go itself would Fatal before anything relevant
// could happen" gap already closed for the sibling `tool`/`module`
// directives (see parseToolLine's own doc comment) and for a missing
// version on this same directive family, just one field position later.
//
// A trailing "//"-prefixed comment is still tolerated and discarded here,
// not treated as an extra field — this function is called both after
// ParseGoMod's own stripComment pass (where a trailing comment is already
// gone) and directly by its own unit/fuzz tests with an un-stripped
// comment still attached, and a real trailing line comment is never an
// extra grammar field to the real parser either way.
func parseRequireLine(s string) (Requirement, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(s, "// indirect"))
	path, rest := firstField(s)
	if path == "" || rest == "" {
		return Requirement{}, false
	}
	version, trailing := firstField(rest)
	if version == "" {
		return Requirement{}, false
	}
	if trailing != "" && !strings.HasPrefix(trailing, "//") {
		return Requirement{}, false
	}
	return Requirement{Path: path, Version: version}, true
}

// parseReplaceLine parses one "old [version] => new [version]" entry. The
// old side's version is kept (OldVersion, "" if absent) because CheckAll
// needs it to pick the right entry when a go.mod carries both a version-
// specific and a version-agnostic replace for the same module — see
// selectReplace. The new side's version is kept too (NewVersion) — per
// go.dev/ref/mod#go-mod-file-replace, "if the path on the right side of the
// arrow is not a filesystem path, it must be a valid module path, and a
// specific version must be provided in that case," so a remote-module
// replace always pins an exact version of the replacement, which is what
// actually gets fetched and built and is what a version-specific check
// (the retraction check in retract.go) needs to look at — not the
// original, unreplaced requirement's version, which names a version of a
// different module entirely once replaced. Left "" for a local filesystem
// target, which never carries a version at all.
//
// "=>" must appear as its own whitespace-delimited field, not merely as a
// substring somewhere in the line. golang.org/x/mod/modfile's own lexer
// (read.go's nextToken) has no special-cased arrow token at all — "=>" is
// just two ordinary identifier characters, swallowed into whichever
// unbroken run of non-space, non-bracket runes it's adjacent to, exactly
// like any other punctuation a bare module path or version could contain.
// The semantic layer (rule.go's parseReplace) then requires args[arrow] to
// be the exact, standalone token "=>". Confirmed live, 2026-09 (go1.24.4):
// a go.mod with `replace example.com/a=>example.com/b v1.0.0` (no space on
// either side of the arrow — an easy AI-generated or hand-edited go.mod
// formatting slip) makes `go build`/`go list -m all` fail immediately with
// "usage: replace module/path [v1.2.3] => other/module v1.4 ...", a parse
// error before any network call; missing the space on only one side
// (`a=> b` or `a =>b`) fails identically, while `a => b` (both sides
// spaced) is accepted. Before this fix, parseReplaceLine used
// strings.SplitN(s, "=>", 2), which finds that substring regardless of
// adjacent whitespace — so a malformed, unbuildable replace line like this
// was parsed as an ordinary, valid replacement (Old="example.com/a",
// New="example.com/b", NewVersion="v1.0.0") and silently checked against
// the proxy under the substituted "new" path, exactly the "go itself would
// Fatal before anything relevant could happen" gap already fixed for other
// go.mod shapes elsewhere in this tool (see checkDuplicateRequires,
// checkExcludedRequirements, checkAmbiguousComparisonQueries). Splitting
// into whitespace-delimited fields first and matching "=>" as an exact
// field — the same boundary golang.org/x/mod/modfile's own args slice
// uses — makes a mis-spaced arrow fail to parse here too, the same way
// firstField already stops at whitespace field boundaries. When no
// replacement is recognized, ParseGoMod simply drops the line (see its own
// callers), leaving any covering require line to be checked under its own,
// original, unreplaced path — never silently swapped for an unvalidated
// substitute the real go command would never have resolved to either.
func parseReplaceLine(s string) (Replacement, bool) {
	var fields []string
	for rest := s; rest != ""; {
		var f string
		f, rest = firstField(rest)
		if f == "" {
			break
		}
		fields = append(fields, f)
	}
	arrow := -1
	for i, f := range fields {
		if f == "=>" {
			arrow = i
			break
		}
	}
	if arrow < 0 {
		return Replacement{}, false
	}
	oldFields, newFields := fields[:arrow], fields[arrow+1:]
	if len(oldFields) == 0 || len(oldFields) > 2 || len(newFields) == 0 || len(newFields) > 2 {
		return Replacement{}, false
	}
	r := Replacement{Old: oldFields[0], New: newFields[0]}
	if len(oldFields) == 2 {
		r.OldVersion = oldFields[1]
	}
	if len(newFields) == 2 {
		r.NewVersion = newFields[1]
	}
	return r, true
}

// parseToolLine parses one `tool` (or `module`) directive entry: a single
// bare (or quoted) path, with no version and no "// indirect" suffix
// (those only apply to require entries) — go.mod's own grammar for both
// `tool` and `module` is exactly one argument, full stop
// (golang.org/x/mod/modfile's rule.go: the `tool` case Fatals with "tool
// directive expects exactly one argument" when len(args) != 1, and the
// `module` case Fatals with "usage: module module/path" under the
// identical condition). Reuses firstField so a quoted path with a space
// is unquoted the same way a require or replace path is.
//
// ok is false whenever s doesn't name exactly one field — either no field
// at all (a bare "tool"/"module" with nothing but whitespace after it), or
// trailing content left over after the first one (e.g. "tool golang.org/x/
// tools/cmd/stringer extra", a plausible copy-paste or hand-editing slip).
// Confirmed live, 2026-09 (go1.24.4, GOPROXY=off to rule out any network
// dependency): both shapes make `go build`/`go list -m all` Fatal
// immediately at go.mod PARSE time — "tool directive expects exactly one
// argument" / "usage: module module/path" — before resolving a single
// require line, identical in kind to require/exclude's own "usage: ...
// v1.2.3" Fatal for a missing version field (see checkMalformedDirectives).
// Before this fix, this function used `path, _ := firstField(s)` and
// simply discarded any leftover rest, so a `tool` line with an extra
// trailing field was silently accepted as an ordinary, valid tool
// directive naming only its first field — and a bare `tool`/`module` with
// no argument at all was already rejected (path == ""), but ParseGoMod's
// callers dropped that case on the floor with no trace, the identical gap
// checkMalformedDirectives now closes for require/exclude's own missing-
// argument shape. A go.mod carrying either mistake reported "nothing
// flagged" despite being one the real go command refuses to build under
// any circumstances.
func parseToolLine(s string) (string, bool) {
	path, rest := firstField(s)
	if path == "" || rest != "" {
		return "", false
	}
	return path, true
}

// parseGodebugLine parses one `godebug` directive entry: a single bare
// "key=value" token. golang.org/x/mod/modfile's rule.go Fatals with
// "usage: godebug key=value" when the line doesn't name exactly one
// argument, when that argument contains a quote/backtick/comma, or when
// it contains no "=" at all — confirmed live, 2026-10 (go1.24.4,
// GOPROXY=off): a bare `godebug`, `godebug http2client` (no "="), and
// `godebug http2client=0 extra` (a trailing field) all make `go build`/
// `go list -m all` fail immediately at go.mod parse time, before
// resolving a single requirement. This function only recognizes the
// well-formed shape (ok is false for any of the above) — unlike every
// other directive ParseGoMod dispatches on, a malformed godebug line
// isn't turned into a MalformedDirective yet, since the far more
// consequential gap (modslop not parsing `godebug` at all, so a
// duplicate key silently shadowed the real go toolchain's own
// last-one-wins behavior with no finding at all — see
// checkDuplicateGodebug) is worth closing on its own first; full
// malformed-godebug parity is a smaller follow-on, not folded in here to
// keep this change reviewable.
func parseGodebugLine(s string) (Godebug, bool) {
	field, rest := firstField(s)
	if field == "" || rest != "" {
		return Godebug{}, false
	}
	key, value, ok := strings.Cut(field, "=")
	if !ok || key == "" {
		return Godebug{}, false
	}
	return Godebug{Key: key, Value: value}, true
}

// retractTokens splits a retract directive's argument text (the "rest"
// after the "retract" keyword, or one line inside an already-open retract
// block) into the same tokens golang.org/x/mod/modfile's own lexer
// (read.go's isIdent) would produce: '(', ')', '[', ']', '{', '}', ',' and
// any space character are never swept into a surrounding identifier
// token, no matter how tightly they're glued to adjacent, non-space
// characters — each is its own single-character token on its own.
// Confirmed live, 2026-10-04 (go1.24.4, GOPROXY=off): `retract
// [v0.1.0,v0.2.0]` (no spaces anywhere around the bracket or comma) is
// accepted by real go exactly like the fully-spaced `retract [v0.1.0,
// v0.2.0]`, and `retract (v0.1.0)` (parens used by mistake where the
// grammar wants brackets) Fatals the same "expected '[' or version" a bare
// `retract` with no argument at all does — both confirm the real lexer
// peels '(' / ')' off as their own tokens too, not just '[' / ']' / ','.
// This is why this function can't reuse firstField/strings.Fields, both of
// which only split on whitespace and would wrongly swallow a glued
// "[v0.1.0,v0.2.0]" (or "(v0.1.0)") into one opaque token, hiding the
// grammar violation parseRetractLine needs to see.
//
// A leading '"' still opens a double-quoted Go string literal exactly like
// firstField's own handling (leadingQuotedString) — `retract "v1.0.0"`
// parses as a well-formed, if unusually styled, single-version retract
// directive in real go. An unterminated quoted token is left for the
// caller's own lineHasInvalidQuotedToken check (already run ahead of
// parseRetractLine at every one of ParseGoMod's call sites, same as every
// sibling directive) rather than handled twice.
func retractTokens(s string) []string {
	const delims = "()[]{},"
	var toks []string
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return toks
		}
		if s[0] == '"' {
			if tok, n, ok := leadingQuotedString(s); ok {
				toks = append(toks, tok)
				s = s[n:]
				continue
			}
		}
		if strings.IndexByte(delims, s[0]) >= 0 {
			toks = append(toks, s[:1])
			s = s[1:]
			continue
		}
		i := strings.IndexFunc(s, func(r rune) bool {
			return unicode.IsSpace(r) || (r < 128 && strings.IndexByte(delims, byte(r)) >= 0)
		})
		if i < 0 {
			toks = append(toks, s)
			return toks
		}
		toks = append(toks, s[:i])
		s = s[i:]
	}
}

// parseRetractLine reports whether s is a well-formed `retract` directive
// argument. golang.org/x/mod/modfile's own parseVersionInterval (rule.go),
// shared by every `retract` directive, accepts exactly two shapes: a
// single bare version token, or a bracketed interval "[" version ","
// version "]" (a trailing "// rationale" line comment is already gone by
// the time this function is called — see ParseGoMod's own stripComment
// pass, run before every call site).
//
// This only checks the token-level SHAPE, not whether the version text
// itself is a real, valid semver — the identical scope every other *Line
// parser in this file already keeps (parseRequireLine/parseReplaceLine/
// parseToolLine never validate their own version fields are real semver
// either), because a textually-invalid version is a different, value-level
// real-go Fatal (e.g. a version string that isn't valid semver at all, or
// — per isMajorVersionSuffix — one whose major doesn't match the module's
// own path) from a structurally malformed one, which is this check's only
// job, matching checkMalformedDirectives' own scope for every other
// directive family it covers.
//
// Confirmed live, 2026-10-04 (go1.24.4, GOPROXY=off): a bare `retract`
// line (no argument at all) Fatals `go build`/`go list -m all` immediately
// with "expected '[' or version"; `retract v1.0.0 extra` (a stray trailing
// field) Fatals `unexpected token after version: "extra"`; `retract
// [v1.0.0, v2.0.0` (no closing bracket) Fatals "expected ']' after
// version"; `retract [v0.1.0 v0.2.0]` (missing comma) Fatals "expected ','
// after version"; and `retract [` / `retract [v0.1.0,` (nothing after the
// bracket/comma) Fatal "expected version after '['" / "expected version
// after ','" respectively — five distinct wordings for five distinct
// violations of the same two-shape grammar, all equally fatal at go.mod
// PARSE time, before a single requirement resolves. A well-formed interval
// with no surrounding whitespace at all (`retract [v0.1.0,v0.2.0]`) is
// accepted identically to the fully-spaced form — see retractTokens' own
// doc comment — so this function tokenizes with it rather than a bare
// whitespace split.
//
// Before this function (and its ParseGoMod call sites) existed, a
// malformed retract directive in the AUDITED go.mod itself fell through
// to the same silent, zero-trace drop any genuinely unrecognized line
// gets: retraction() (retract.go) only ever reads a *dependency's* latest
// go.mod under the proxy, via golang.org/x/mod/modfile directly, and
// goModKnownVerbs/checkGoModUnknownDirective already treat "retract" as a
// known, legitimate verb (correctly — it is one), so neither of those
// existing retract-aware code paths had any way to notice a malformed
// ARGUMENT on an otherwise-recognized retract line in the file modslop was
// actually asked to check. A go.mod with a bare `retract` (a plausible
// mistake: starting to mark a bad release retracted, then abandoning the
// line, or deleting its version while editing without removing the
// directive) reported "checked N requirement(s), nothing flagged" despite
// being a go.mod the real go command refuses to build under any
// circumstances — the identical "self-contradictory, unbuildable go.mod,
// not a heuristic" class checkMalformedDirectives already exists to catch
// for require/exclude/tool/module/replace/ignore's own missing-or-extra-
// argument shapes, just one directive family those checks never covered.
func parseRetractLine(s string) bool {
	toks := retractTokens(s)
	if len(toks) == 0 || toks[0] == "(" {
		return false
	}
	if toks[0] != "[" {
		return len(toks) == 1
	}
	return len(toks) == 5 && toks[2] == "," && toks[4] == "]"
}

// firstField returns the leading field of s and everything after it: for a
// require entry that's the module path (rest starts with the version); for
// a replace side it's the whole path. go.mod's real lexer
// (golang.org/x/mod/modfile) allows a token to be written as a double-quoted
// Go string literal instead of a bare word — `go mod edit` does this itself
// for a local replace path containing a space (e.g. replace foo => "../my
// mod"), which `go build` accepts fine. A naive whitespace split truncates
// that at the space and leaves a stray quote character, so a quoted token is
// unquoted first.
//
// Only a leading '"' is treated as a quote start — not '`' — even though the
// real lexer (read.go's readToken) tokenizes a backtick-delimited run
// exactly like a double-quoted one at the character level. See
// leadingQuotedString's own doc comment for why the semantic layer rejects
// backtick outright.
func firstField(s string) (field, rest string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if s[0] == '"' {
		if tok, n, ok := leadingQuotedString(s); ok {
			return tok, strings.TrimSpace(s[n:])
		}
	}
	if i := strings.IndexFunc(s, unicode.IsSpace); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// leadingQuotedString parses a double-quoted Go string literal at the start
// of s and returns its unquoted value plus the number of bytes of s it
// consumed (including both quote characters).
//
// A leading backtick is deliberately NOT treated as a quote here, even
// though it looks like it should be. go.mod's lexer (golang.org/x/mod/
// modfile's read.go, readToken) does tokenize a backtick-delimited run
// exactly like a double-quoted string at the character level — both become
// a single _STRING token — but the semantic layer that turns a token into a
// path (modfile/rule.go's parseString) only ever unquotes a token whose text
// starts with '"'; anything else containing a quote character (including a
// whole backtick-quoted token, since its text starts and ends with '`')
// falls into parseString's "unquoted string cannot contain quote" error
// path instead. Confirmed live, 2026-09, on both go1.24.4 and go1.26.8: a
// go.mod containing “ replace github.com/pkg/errors => `../my mod` “
// (or the identical shape in a `require`/`exclude`/`tool`/`module`
// directive) makes `go build`/`go list -m all` fail immediately with "go:
// errors parsing go.mod: ...: invalid quoted string: unquoted string cannot
// contain quote" — go.mod syntax has no raw-string form at all, unlike Go
// source code's own backtick literals, despite the lexer accepting the
// character. Before this fix, this function treated a backtick run
// identically to a double-quoted string, so e.g. a backtick-quoted local
// replace path containing a space was parsed as an ordinary, valid local
// filesystem replace and silently skipped from every check via
// Replacement.IsLocal() (see CheckAll) — treating a go.mod that cannot be
// built at all as a clean, unremarkable local-vendor override, exactly the
// kind of mistake a plausible AI-generated go.mod could make by assuming Go
// source code's backtick-string convention also applies here.
//
// Double-quoted strings go through strconv.Unquote — the same function
// golang.org/x/mod/modfile's own parseString uses (rule.go) — rather than a
// hand-rolled "copy the byte after a backslash literally" unescaper (this
// function's shape before an earlier fix). That naive approach is only
// correct for the two escapes whose decoded byte equals the character
// following the backslash (\\ and \"); every other Go string escape decodes
// to something else entirely — \t is a tab (0x09), not the letter 't';
// \xHH/\uHHHH/\UHHHHHHHH and octal \NNN decode a hex/unicode/octal-coded
// byte or rune, not a copy of their own digits. Confirmed live, 2026-09: a
// go.mod with `require "github\x2ecom/pkg/errors" v0.9.1` (a real, existing
// dependency, its module path's literal "." hex-escaped for no reason other
// than an AI-generated or hand-written go.mod's unusual styling) is accepted
// by `go mod tidy`/`go build`, which rewrite it to the plain, unquoted
// `require github.com/pkg/errors v0.9.1` — confirming the real go toolchain
// decodes \x2e as "." and resolves the intended, real module. Before that
// fix, ParseGoMod's old byte-literal unescaper turned the same line into
// Requirement{Path: "githubx2ecom/pkg/errors"} (the 'x' from \x kept
// literally, "2e" copied as plain digits) — a path that doesn't exist on
// any proxy, so modslop reported a false high-severity "not-found" finding
// (hallucinated-import) on a completely legitimate, real dependency purely
// because of how its require line happened to be quoted. The escape only
// changes the decoded *value*; the boundary-finding scan below (skip one
// byte after any backslash, stop at an unescaped quote) already finds the
// same closing-quote position real go's lexer does regardless of which
// multi-byte escape appears — confirmed by the fuzz suite's Old/New byte
// lengths matching the modfile.Parse oracle throughout — so only the value
// needed fixing, not the token boundary.
func leadingQuotedString(s string) (value string, consumed int, ok bool) {
	if s[0] != '"' {
		return "", 0, false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if c == '"' {
			v, err := strconv.Unquote(s[:i+1])
			if err != nil {
				return "", 0, false
			}
			return v, i + 1, true
		}
	}
	return "", 0, false
}

// lineHasInvalidQuotedToken reports whether s — a single already
// comment-stripped (see stripComment) go.mod/go.work directive argument
// string, e.g. the "rest" after a recognized keyword, or one line inside
// an already-open block — contains a token real go's semantic parser
// rejects outright, even though leadingQuotedString/firstField's own
// lenient field-splitting would otherwise happily extract a (garbage)
// field from it and let ParseGoMod's callers treat the line as
// well-formed.
//
// golang.org/x/mod/modfile's own parseString (rule.go) only ever unquotes
// a token whose raw text starts with '"'; any OTHER token containing a
// '"', '\”, or '`' ANYWHERE in it — not just one that's wholly wrapped in
// one of those characters — falls into parseString's "invalid quoted
// string: unquoted string cannot contain quote" Fatal instead, per that
// function's own comment ("Other quotes are reserved both for possible
// future expansion and to avoid confusion"). This mirrors goprivaudit's
// own goModHasInvalidQuotedToken (this project's real-world-testing
// technique #147, itself generalizing goproxycheck's narrower
// backtick-at-token-start fix, technique #126) — both found and fixed in
// those tools' own independent go.mod-reading code first; modslop's own
// hand-rolled parser (firstField/leadingQuotedString, used by
// parseRequireLine/parseReplaceLine/parseToolLine/the inline module/go/
// toolchain/ignore dispatch in ParseGoMod) never received the equivalent
// fix at all, despite firstField's own doc comment already explaining in
// detail why a LEADING backtick isn't treated as a quote-opener — that
// comment stops at "so a backtick-wrapped token is rejected by real go,"
// without ever adding a check that actually rejects it; a backtick-
// wrapped (or glued-on, or single-quote-wrapped) token was instead left
// to be silently treated as an ordinary, if garbage, bare word.
//
// Confirmed live, 2026-10 (go1.24.4 and go1.26.8, GOPROXY=off to rule out
// any network dependency): a go.mod whose `require`/`module`/`replace`/
// `tool` argument is backtick-quoted (“ require `github.com/pkg/errors`
// v0.9.1 “), single-quote-wrapped ('github.com/pkg/errors'), or merely
// has a stray backtick glued onto an otherwise-ordinary token
// (`github.com/pkg/errors\x60`, no closing backtick needed — the lexer's
// isIdent sweeps it into the same identifier token regardless) all make
// `go build`/`go list -m all` Fatal immediately with "go.mod:N: invalid
// quoted string: unquoted string cannot contain quote" — identical
// whether the token sits in a single-line directive or inside that
// directive's parenthesized block form, and before resolving a single
// requirement. Before this fix, modslop instead extracted the mangled
// token as an ordinary module path/replace target/tool path and checked
// it against the live proxy — reporting an actively misleading
// high-severity "not-found"/hallucinated-import finding for a go.mod that
// can never build at all, for a completely unrelated reason, exactly the
// "go itself would Fatal first, self-contradictory go.mod, not a
// heuristic" family this file has already closed for a dozen other
// shapes (malformed-bom, repeated-module, conflicting-replace, etc.).
//
// Deliberately narrower than a full lexer port in two ways, both
// confirmed live and left alone rather than guessed at:
//
//   - A token that opens with '"' but has no matching closing '"' on the
//     same line (go.mod strings can't span a physical line) is a
//     DIFFERENT real Fatal shape ("go.mod:N:C: unexpected newline in
//     string", not "invalid quoted string: ..."), so this function simply
//     stops scanning and reports no finding for that line rather than
//     misquoting the wrong error text — a smaller, separate gap left for
//     a future pass, the same "don't force an unverified shape into a
//     confirmed fix" discipline as technique #159's unreleased-`go`-
//     version note.
//   - A line whose FIRST token (the directive keyword position itself)
//     carries the invalid character — e.g. “ require`github.com/foo`
//     v1.0.0 “ with no separating whitespace at all — is already
//     correctly caught by the *existing*, more accurate
//     goModUnknownDirective/checkGoModUnknownDirective check (real go
//     reports "unknown directive: require`github.com/foo`" for that exact
//     shape, confirmed live, since cutKeyword's own separator requirement
//     means such a line never matches any known keyword in the first
//     place). This function is therefore only ever consulted on a
//     directive's ARGUMENT text (the "rest" after a keyword already
//     matched by cutKeyword, or a line already inside a recognized
//     block), never on a raw, not-yet-classified line — see ParseGoMod's
//     call sites.
func lineHasInvalidQuotedToken(s string) (badToken string, bad bool) {
	for s != "" {
		if s[0] == '"' {
			_, n, ok := leadingQuotedString(s)
			if !ok {
				// Unterminated double-quoted token: a real, but different
				// Fatal shape — see this function's own doc comment. Not
				// this check's job; see lineHasUnterminatedQuotedString for
				// the dedicated check that covers it instead.
				return "", false
			}
			s = strings.TrimSpace(s[n:])
			continue
		}
		var tok string
		if i := strings.IndexFunc(s, unicode.IsSpace); i >= 0 {
			tok, s = s[:i], strings.TrimSpace(s[i+1:])
		} else {
			tok, s = s, ""
		}
		if strings.ContainsAny(tok, "\"'`") {
			return tok, true
		}
	}
	return "", false
}

// lineHasUnterminatedQuotedString reports whether s — a single already
// comment-stripped go.mod directive argument string (the same "rest" or
// block-entry text lineHasInvalidQuotedToken's own call sites pass it),
// contains a token that opens with '"' but has no matching closing '"'
// anywhere later on the same physical line. go.mod strings can't span a
// line break (golang.org/x/mod/modfile's own lexer, read.go, Fatals the
// instant it hits a newline while still inside a string), so this is a
// different real Fatal shape than lineHasInvalidQuotedToken's own
// "contains a stray quote/backtick outside a valid string" — that
// function's own doc comment explicitly declines to cover this case
// ("Unterminated double-quoted token: a real, but different ... Fatal
// shape ... Not this check's job"), leaving it unclosed until now.
//
// Confirmed live, 2026-10-05 (go1.24.4, GOPROXY=off to rule out any
// network dependency): a go.mod whose require/replace/module/tool/
// exclude argument opens a double-quoted string with no closing quote
// before the end of the line (e.g. `require "github.com/pkg/errors
// v0.9.1`, or the identical shape inside that directive's block form, or
// on a `module`/`replace` line) makes `go build`/`go list -m all` Fatal
// immediately with "go.mod:N:C: unexpected newline in string", before
// resolving a single requirement — a different message, and a different
// (whole-rest-of-line) badToken shape, than lineHasInvalidQuotedToken's
// own "unquoted string cannot contain quote" case.
//
// Before this fix, ParseGoMod's call sites never checked for this shape
// at all: lineHasInvalidQuotedToken's early return left it to
// firstField/leadingQuotedString's own lenient fallback, which mis-split
// the unterminated token as an ordinary (if garbage, quote-glued-on) bare
// word — e.g. parsing `require "github.com/pkg/errors v0.9.1` as
// Requirement{Path: `"github.com/pkg/errors`, Version: "v0.9.1"} — and
// then checked that garbage path against the live proxy, reporting an
// actively misleading high-severity "not-found"/hallucinated-import
// finding for a go.mod that can never build at all, for a completely
// unrelated reason. For a `replace` target this was worse than a plain
// false positive: a quote glued onto an otherwise-local path (e.g.
// `"../local`) defeats Replacement.IsLocal()'s prefix check too, so the
// replace's local-filesystem target got queried against the proxy as if
// it were a remote module.
func lineHasUnterminatedQuotedString(s string) (openSpan string, bad bool) {
	for s != "" {
		if s[0] == '"' {
			_, n, ok := leadingQuotedString(s)
			if !ok {
				return s, true
			}
			s = strings.TrimSpace(s[n:])
			continue
		}
		if i := strings.IndexFunc(s, unicode.IsSpace); i >= 0 {
			s = strings.TrimSpace(s[i+1:])
		} else {
			s = ""
		}
	}
	return "", false
}

// cutKeyword strips a go.mod block keyword (e.g. "require", "replace")
// from the start of s and returns what follows, unparsed. It requires
// the keyword be followed by whitespace or "(" so it doesn't match a
// module path that happens to start with the same letters. go.mod's own
// lexer (golang.org/x/mod/modfile) treats "require(", "require\t(", and
// "require  (" identically to the gofmt-canonical "require (" — there's
// no space requirement — so callers must not rely on an exact-string
// match against "require (".
//
// A line that is *exactly* the keyword, with nothing after it at all
// (rest == "", not even a separator byte to check), is still a match —
// not the ambiguous case the separator check above exists to guard
// against. s always arrives here already whitespace-trimmed (ParseGoMod's
// own strings.TrimSpace(scanner.Text()) runs before any cutKeyword call),
// so a line most naturally written as a bare `require`/`tool`/`module`/
// `exclude` with a trailing space and nothing else — the single most
// obvious way to forget a directive's argument entirely — collapses to
// precisely this shape by the time it reaches here. There's no ambiguity
// to resolve either way: strings.HasPrefix(s, kw) plus rest == "" means s
// equals kw exactly, character for character, so this can never be some
// other, longer identifier that merely starts with the same letters (that
// case always leaves a non-empty rest, still gated by the separator check
// below). Confirmed live, 2026-09, go1.24.4 (GOPROXY=off to rule out any
// network dependency): a go.mod with a bare `require` (or `exclude`,
// `tool`, or `module`) line carrying no argument at all makes `go build`/
// `go list -m all` Fatal immediately with each directive's own "usage: ...
// "/"... expects exactly one argument" message (see
// malformedDirectiveUsage in check.go), before resolving a single
// dependency — the identical unbuildable-go.mod class ParseGoMod's sixth
// return value and checkMalformedDirectives already exist to catch for a
// require/exclude line that names a path but omits only the version, or a
// tool/module line carrying more than one argument (see parseToolLine's
// own doc comment). Before this fix, this function rejected rest == ""
// outright as if the keyword hadn't matched at all, so ParseGoMod's own
// per-keyword dispatch never even recognized the line as a require/
// exclude/tool/module directive in the first place — it fell straight
// through to the final, unconditional `continue` at the bottom of the
// blockKind == "" dispatch, the same silent-drop-with-zero-trace fate as
// any genuinely unrecognized line (a stray comment-only line, "go 1.24",
// etc.), never reaching parseRequireLine/parseToolLine's own ok=false path
// and therefore never generating a MalformedDirective at all — a strictly
// worse blind spot than the "keyword plus a path with no version" shape
// those two functions already handle, since this is the *plainer* mistake
// (forgetting the argument entirely, not just one field of it) and it
// produced no trace whatsoever rather than a merely-dropped Requirement.
func cutKeyword(s, kw string) (rest string, ok bool) {
	if !strings.HasPrefix(s, kw) {
		return "", false
	}
	rest = s[len(kw):]
	if rest == "" {
		return "", true
	}
	if c := rest[0]; c != ' ' && c != '\t' && c != '(' {
		return "", false
	}
	return rest, true
}

// stripComment removes a trailing "//" comment from a go.mod line, the
// way golang.org/x/mod/modfile's own lexer does (readToken in read.go):
// "//" only starts a comment outside any quoted string token. A naive
// strings.Index(line, "//") instead truncates mid-string the moment a
// quoted token contains a literal "//" — e.g. a local replace path like
// "../vendor//bar", real go.mod syntax that go build resolves correctly
// (doubled slashes collapse in filesystem paths) — leaving a stray
// leading quote that breaks downstream parsing.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		switch c := line[i]; c {
		case '"':
			i++
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) {
					i++
				}
				i++
			}
		case '`':
			i++
			for i < len(line) && line[i] != '`' {
				i++
			}
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return line[:i]
			}
		}
	}
	return line
}

// stripBlockComments removes every "/* ... */" span from content, blanking
// each byte inside a found span to a space (a literal '\n' is preserved as
// '\n', so line structure — and therefore every downstream line-oriented
// scan in this file — is undisturbed) and reporting whether any span was
// found at all.
//
// go.mod/go.work syntax has no block-comment form at all, unlike Go source
// code itself: golang.org/x/mod/modfile's own lexer (read.go's readToken)
// Fatals unconditionally, immediately, the instant it sees "/*" while
// skipping whitespace or scanning an identifier — "mod files must use //
// comments (not /* */ comments)" — regardless of whether a matching "*/"
// ever appears later in the file; real go never "skips past" a /* */ span
// and resumes parsing after it, the way it does for an ordinary "//" line
// comment. Confirmed live, 2026-10-04 (go1.24.4, go1.26.8, GOPROXY=off, on
// both go.mod and an identically-shaped go.work): a file reading
//
//	/*
//	require bogus.example.com/definitely-not-a-real-module v1.0.0
//	*/
//
//	require github.com/pkg/errors v0.9.1
//
// Fatals `go build`/`go list -m all` immediately at the "/*" line with
// that exact message, before resolving a single requirement — including
// the real, well-formed one sitting right after the (would-be) comment.
//
// Despite real go never actually treating a /* */ span as skippable
// content, this function still blanks exactly the span between a "/*" and
// its nearest following "*/" — rather than leaving it, or the rest of the
// file, untouched — because that span is, in every realistic case, text
// its own author intended as a disabled, commented-out block (the
// C-style comment syntax most languages, including Go source itself, do
// support), not a second, independently well-formed directive that merely
// happens to sit past an unrelated Fatal. Before this function existed,
// ParseGoMod had no model of "/*" at all: a require/replace/tool/etc. line
// physically inside such a (would-be) comment span was extracted and
// checked exactly like an ordinary, live directive — so the deliberately
// disabled "bogus.example.com" name in the example above was reported as
// a high-severity "not-found"/hallucinated-import finding, worse than the
// "self-contradictory go.mod, not a heuristic" findings this file's other
// checks already produce for a Fatal-class defect, since it fabricates a
// dependency out of text the file's own author never intended to be live
// at all. If no matching "*/" is found before EOF, the remainder of the
// file is blanked too (there's no well-defined inner span to a comment
// that never closes, and the Fatal condition itself — reported by the
// MalformedDirective this produces — already covers it regardless).
//
// A "/*"/"*/" occurring inside an already-open quoted string (double- or
// backtick-quoted) is left untouched, mirroring stripComment's own
// quote-skipping above — go.mod strings can't span a physical line, so a
// quote left open at end-of-line is treated as closed there, the same
// fail-safe boundary lineHasInvalidQuotedToken's own scan uses.
//
// A "//" line comment is recognized here too, ahead of "/*" — not because
// this function means to interpret line comments (stripComment, run later
// per line, already owns that), but because real go.mod's own lexer
// (read.go's readToken) checks for "//" before ever considering "/*" at
// the very same scan position: once it sees "//" it consumes the rest of
// the physical line unconditionally, so a "/*" appearing later in that
// same line (e.g. a trailing comment reading "//*0000000" — two slashes
// with no space before the asterisk, or "// /* note */") is just ordinary
// comment text to it, never a block-comment opener. Confirmed live,
// 2026-10-04 (go1.24.4, GOPROXY=off): a go.mod with `require
// github.com/pkg/errors v0.9.1 //*0000000` followed by a second, separate
// `require` line resolves both requirements fine under `go list -m all`.
// Before this fix, stripBlockComments scanned raw content with no model of
// "//" at all: it walked past the line comment's own first "/" (next char
// "/", not "*", so no match), then matched "/*" at the comment's second
// "/" plus its "*" — misdetecting a same-line, glued-on "//*" as a block
// comment with no closing "*/" anywhere in the rest of the file, and
// therefore blanking everything from there to EOF, including every
// subsequent require line. A go.mod where only the FIRST of several real
// dependencies carries a trailing comment shaped like this reported zero
// requirements at all — a false all-clear on every dependency in the
// file, not merely a corrupted version string on the one line that
// triggered it.
func stripBlockComments(content string) (result string, found bool) {
	var b strings.Builder
	for i := 0; i < len(content); {
		switch c := content[i]; c {
		case '"', '`':
			j := i + 1
			for j < len(content) && content[j] != c && content[j] != '\n' {
				if content[j] == '\\' && c == '"' && j+1 < len(content) {
					j++
				}
				j++
			}
			if j < len(content) && content[j] == c {
				j++
			}
			b.WriteString(content[i:j])
			i = j
		case '/':
			if i+1 < len(content) && content[i+1] == '/' {
				j := strings.IndexByte(content[i:], '\n')
				if j < 0 {
					b.WriteString(content[i:])
					i = len(content)
				} else {
					b.WriteString(content[i : i+j])
					i += j
				}
				continue
			}
			if i+1 < len(content) && content[i+1] == '*' {
				found = true
				end := strings.Index(content[i+2:], "*/")
				span := content[i:]
				if end >= 0 {
					span = content[i : i+2+end+2]
				}
				for _, r := range span {
					if r == '\n' {
						b.WriteByte('\n')
					} else {
						b.WriteByte(' ')
					}
				}
				i += len(span)
				continue
			}
			b.WriteByte(c)
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), found
}

// hasTopLevelDirective reports whether content's go.mod contains a
// top-level directive named verb at all (single-line or parenthesized
// block form), well-formed or not. Shared by hasIgnoreDirective,
// hasToolDirective, and hasGodebugDirective (check.go's
// checkIgnoreDirectiveTooOld/checkToolDirectiveTooOld/
// checkGodebugDirectiveTooOld), each of which needs its own one verb's
// presence in isolation — whether the directive itself is malformed is a
// separate, later-stage question ParseGoMod's own per-verb handling and
// checkMalformedDirectives already cover — before it's worth comparing any
// go-directive version at all.
//
// Block state here is tracked generically (any top-level verb immediately
// followed by "(" opens a block, matching cutKeyword's own documented
// separator rule), not specific to any one verb — so a block entry that
// happens to read e.g. "ignore" inside some unrelated directive's block
// (a pathological `require (\n\tignore v1.0.0\n)`, where "ignore" is just
// an unusual module path) is correctly not mistaken for a top-level ignore
// directive. This mirrors goprivaudit's own goModHasIgnoreDirective, which
// closed the identical gap in that tool's independent go.mod-reading code
// first (this project's testing-practice techniques #90/#116).
func hasTopLevelDirective(content, verb string) bool {
	// A bare verb appearing only inside a "/* ... */" span (never valid
	// go.mod syntax at all — see stripBlockComments's own doc comment) is
	// not a live top-level directive the real go command would ever reach;
	// blanking it first keeps this function's answer consistent with
	// ParseGoMod's own now-identical treatment of the same content.
	content, _ = stripBlockComments(content)
	inBlock := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		trimmed := strings.TrimSpace(stripComment(scanner.Text()))
		if trimmed == "" {
			continue
		}
		if inBlock {
			if trimmed == ")" {
				inBlock = false
			}
			continue
		}
		i := 0
		for i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' && trimmed[i] != '(' {
			i++
		}
		v := trimmed[:i]
		if v == verb {
			return true
		}
		if strings.TrimSpace(trimmed[i:]) == "(" {
			inBlock = true
		}
	}
	return false
}

func hasIgnoreDirective(content string) bool { return hasTopLevelDirective(content, "ignore") }

// hasToolDirective reports whether content's go.mod contains a top-level
// `tool` directive at all, well-formed or not. Used only by
// checkToolDirectiveTooOld (check.go) — see hasTopLevelDirective's own doc
// comment for the shared scanning logic and false-positive guard.
func hasToolDirective(content string) bool { return hasTopLevelDirective(content, "tool") }

// hasGodebugDirective reports whether content's go.mod contains a
// top-level `godebug` directive at all, well-formed or not. Used only by
// checkGodebugDirectiveTooOld (check.go) — see hasTopLevelDirective's own
// doc comment for the shared scanning logic and false-positive guard.
func hasGodebugDirective(content string) bool { return hasTopLevelDirective(content, "godebug") }

// goDirectiveVersion extracts a go.mod's own top-level `go` directive
// version string (e.g. "1.26.8" or "1.21"), or "" if the file has none —
// used only by checkIgnoreDirectiveTooOld, which needs to compare it
// against 1.25 (the version `ignore` support was added in) independently
// of ParseGoMod's own goSeen bookkeeping, which only tracks *whether* a
// `go` directive was seen, not its value. Reuses cutKeyword so "godebug"
// (which also starts with "go") is correctly rejected the same way
// ParseGoMod's own "go" dispatch already rejects it — confirmed by
// cutKeyword's own separator check, which requires the matched keyword be
// followed by whitespace or "(", not an arbitrary continuation like "go"
// immediately followed by "debug". `go` has no block form in real go.mod
// syntax (confirmed live and already noted in ParseGoMod's own "go"
// dispatch), so a `go (` line is simply skipped here rather than treated
// as a version.
func goDirectiveVersion(content string) string {
	// Same reasoning as hasIgnoreDirective's identical call just above —
	// a `go` line sitting only inside a "/* ... */" span was never a real
	// top-level directive to begin with.
	content, _ = stripBlockComments(content)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		trimmed := strings.TrimSpace(stripComment(scanner.Text()))
		rest, ok := cutKeyword(trimmed, "go")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if rest == "(" {
			continue
		}
		return rest
	}
	return ""
}

// goVersionAtLeast reports whether a go version string (e.g. "1.26.8" or
// "go1.21" — any leading "go" prefix is stripped first) is at least
// major.minor. Returns false for an empty or unparsable version, matching
// the fail-closed convention goprivaudit's identical helper already
// established for this exact comparison.
func goVersionAtLeast(version string, major, minor int) bool {
	version = strings.TrimPrefix(strings.TrimSpace(version), "go")
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return false
	}
	vMajor, err1 := strconv.Atoi(parts[0])
	vMinor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	if vMajor != major {
		return vMajor > major
	}
	return vMinor >= minor
}

// selectReplace picks which Replacement (if any) applies to a required
// module at the given version, matching the real go toolchain's
// precedence: a version-specific replace (OldVersion equal to the
// required version) wins over a version-agnostic one (OldVersion == "",
// applying to every version of that module) regardless of which is
// written first in the go.mod — verified live against the real go
// toolchain (`go list -m all` with both a specific and a general replace
// for the same module present: the specific one always won, in both file
// orderings; and when only a version-specific replace exists and it
// doesn't match, no replace applies at all — go fetches the untouched
// module over the network instead of falling back to it). A go.mod can
// legally carry both at once; a naive map[string]Replacement keyed only
// by Old (this tool's shape before this function existed) can only ever
// keep one of the two, and — being filled in file order — picked
// whichever replace happened to be written last, not whichever the go
// tool actually applies.
//
// A specific entry's OldVersion doesn't have to already be a literal,
// canonical tag to match version, any more than a require/exclude
// directive's own version field does (see ResolveVersion's doc comment) —
// go.mod's replace grammar resolves the old side's version through the
// identical abbreviated-prefix/comparison-query mechanism before matching
// it against whatever's actually in the build list. Confirmed live,
// 2026-10 (go1.24.4, real proxy.golang.org): a go.mod requiring
// github.com/pkg/errors v0.9.1 alongside `replace github.com/pkg/errors
// v0.9 => github.com/pkg/errors v0.8.1` (old-side version "v0.9", not the
// literal required "v0.9.1") makes `go list -m all` apply the replace
// anyway — "github.com/pkg/errors v0.9.1 => github.com/pkg/errors
// v0.8.1" — because the proxy resolves "v0.9" to the very same v0.9.1 the
// require line names; `go mod tidy` rewrites the replace's own old-side
// version to the canonical "v0.9.1" in place, confirming it's real
// resolution, not a coincidental literal match. Before this fix,
// selectReplace only ever compared OldVersion to version with ==, so a
// replace written this way was invisible to CheckAll entirely: its Old
// path is still covered by the ordinary require line (declared[rep.Old]
// is true regardless of version), so orphanReplacementTargets doesn't
// pick it up either — the New side, the module a real build actually
// fetches and runs, exactly as hallucinatable/typosquattable as any other
// replace target, was never checked against the proxy at all, while the
// untouched, perfectly legitimate Old module kept getting checked (and
// passing) in its place. Only attempted when every literal-string
// comparison above already failed and there's an actual version to
// resolve (version != "", proxy != nil — a synthetic Requirement built
// from an orphan replace target never has one, see CheckAll's own
// comment, and every test that doesn't care about this resolution passes
// a nil proxy deliberately): bounded by how many specific entries a
// go.mod names for the same Old path, the same "rare in practice, don't
// cost every ordinary lookup a round trip" precedent
// checkExcludedRequirements's own version-query fallback already
// established. A general entry never needs this — it already matches
// every version unconditionally.
func selectReplace(entries []Replacement, modPath, version string, proxy *ProxyClient) (Replacement, bool) {
	var general *Replacement
	for i := range entries {
		if entries[i].OldVersion == "" {
			r := entries[i]
			general = &r
			continue
		}
		if entries[i].OldVersion == version {
			return entries[i], true
		}
	}
	if version != "" && proxy != nil {
		var resolvedVersion string
		var resolvedOK bool
		for i := range entries {
			if entries[i].OldVersion == "" || entries[i].OldVersion == version {
				continue // "" is general, handled below; exact literal match already handled above
			}
			if !resolvedOK {
				resolvedVersion, resolvedOK = proxy.ResolveVersion(modPath, version)
				if !resolvedOK {
					break // nothing to compare a resolved OldVersion against
				}
			}
			if rv, ok := proxy.ResolveVersion(modPath, entries[i].OldVersion); ok && rv == resolvedVersion {
				return entries[i], true
			}
		}
	}
	if general != nil {
		return *general, true
	}
	return Replacement{}, false
}

// LoadGoMod reads and parses a go.mod file from disk.
func LoadGoMod(path string) ([]Requirement, []Replacement, []string, []Requirement, string, []MalformedDirective, []Godebug, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, nil, "", nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseGoMod(string(b))
}

// goWorkReplaces reads a go.work file's replace directives. go.work uses
// the same "go"/"toolchain"/"use"/"replace" directive grammar as go.mod,
// and its replace syntax is byte-for-byte identical to go.mod's — verified
// live against `go build`/`go list -m all` on a scratch workspace — so
// ParseGoMod's existing block/line parser handles it unmodified; its
// `use (...)` lines don't start with "require"/"replace"/"tool" and are
// silently skipped, exactly like an unrecognized go.mod directive would
// be. gowork is the path from `go env GOWORK` (or a test override): empty
// when the module isn't part of a workspace, or "off" when workspace mode
// is explicitly disabled (GOWORK=off) — both return nil, same as a
// go.work that can't be read (e.g. a stale GOWORK pointing at a file that
// no longer exists, treated as "no workspace" rather than an error).
//
// This exists because a workspace's go.work can replace a dependency that
// a member module's own go.mod never mentions at all — confirmed live:
// `go list -m all` run inside a workspace member resolves a require to
// its go.work replacement target even though that module's go.mod shows
// only the plain, unreplaced require (repro: a go.mod requiring
// golang.org/x/mod with no replace, a sibling go.work with `use` plus
// `replace golang.org/x/mod => ./localfork` — `go list -m all` inside the
// member resolves to ./localfork; the same go.mod audited with GOWORK=off
// tries to fetch the real public module instead). Before this, modslop
// only ever read the single go.mod passed on the command line, so a
// go.work replace pointing a plausible-but-nonexistent-on-the-proxy
// require at a local workspace member (a normal way to develop an
// in-progress internal package alongside its consumer) made modslop flag
// a legitimate, locally-satisfied dependency as `not-found` — a false
// positive on the tool's core signal, the same severity class as the
// name-collision/freshness false positives fixed in earlier runs, just
// from a config surface outside go.mod entirely (goprivaudit closed the
// identical gap in its own independent go.mod parser first; this ports
// that fix here).
func goWorkReplaces(gowork string) []Replacement {
	if gowork == "" || gowork == "off" {
		return nil
	}
	data, err := os.ReadFile(gowork)
	if err != nil {
		return nil
	}
	content := string(data)
	if _, ok := goWorkUnknownDirective(content); ok {
		// See goWorkUnknownDirective's own doc comment: a go.work carrying
		// one of these verbs makes real go Fatal before resolving a single
		// module, including every replace directive the file also
		// contains — so trusting those replace entries here would be
		// resolving something the real toolchain never actually reaches.
		// Same fail-closed shape as the err != nil case just below.
		return nil
	}
	if _, ok := goWorkHasInvalidQuotedToken(content); ok {
		// Same fail-closed reasoning, one check over: see
		// goWorkHasInvalidQuotedToken's own doc comment — a go.work
		// carrying this shape anywhere (not necessarily inside the
		// `replace` directive this function cares about) Fatals the whole
		// file before resolving anything, so none of its replace entries
		// can be trusted here either.
		return nil
	}
	if _, _, ok := goWorkHasUnterminatedQuotedString(content); ok {
		// Same fail-closed reasoning as the invalid-quoted-token case just
		// above, for the other real Fatal shape — see
		// goWorkHasUnterminatedQuotedString's own doc comment.
		return nil
	}
	_, reps, _, _, _, _, _, err := ParseGoMod(content)
	if err != nil {
		return nil
	}
	return reps
}

// goWorkHasInvalidQuotedToken reports whether a go.work file's content
// contains the same invalid-quoted-token shape lineHasInvalidQuotedToken
// (via ParseGoMod's own malformed collection) already catches for go.mod
// — go.work's `go`/`toolchain`/`replace` directives share byte-identical
// argument grammar with go.mod's (see goWorkReplaces's own doc comment),
// so the identical real-go Fatal ("invalid quoted string: unquoted
// string cannot contain quote") applies unchanged. Confirmed live,
// 2026-10 (go1.24.4, go1.26.8, GOPROXY=off): a go.work with `replace
// example.com/dep => `./local“ (backtick-wrapped local target) Fatals
// `go build`/`go list -m all`, run from inside any workspace member,
// before resolving a single module — identical in kind to go.mod's own
// version of this bug. badToken is the first such token found, for use
// as a best-effort display value in the resulting finding (see
// checkGoWorkInvalidQuotedToken).
func goWorkHasInvalidQuotedToken(content string) (badToken string, ok bool) {
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		return "", false
	}
	for _, m := range malformed {
		if m.Directive == "invalid-quoted-token" {
			return m.Path, true
		}
	}
	return "", false
}

// goWorkHasUnterminatedQuotedString is goWorkHasInvalidQuotedToken's
// sibling for the other real Fatal shape lineHasUnterminatedQuotedString
// (gomod.go) closes for go.mod: a double-quoted string that opens with '"'
// but is never closed before the end of the line. go.work's `go`/
// `toolchain`/`replace` directives share byte-identical argument grammar
// with go.mod's (see goWorkReplaces's own doc comment), so the identical
// real Fatal applies unchanged. Confirmed live, 2026-10-05 (go1.24.4,
// GOPROXY=off): a real two-module workspace whose go.work carries
// `replace example.com/dep => "../local v0.1.0` (unterminated quote on the
// new side) makes `go build`/`go list -m all`, run from inside a
// workspace member, Fatal with "errors parsing go.work: go.work:N:C:
// unexpected newline in string" — before resolving a single module —
// while pre-fix modslop (this function didn't exist yet) reported
// "checked 0 requirement(s), nothing flagged" for that exact member's
// go.mod, since goWorkReplaces extracted and trusted the mangled replace
// entry instead of recognizing the whole workspace as unbuildable.
//
// isToolchain distinguishes the `toolchain`-specific case, which needs
// its own, differently-worded finding — see
// checkGoWorkUnterminatedQuotedString's own doc comment for why, mirroring
// checkMalformedDirectives' identical go.mod-side split.
func goWorkHasUnterminatedQuotedString(content string) (span string, isToolchain, ok bool) {
	_, _, _, _, _, malformed, _, err := ParseGoMod(content)
	if err != nil {
		return "", false, false
	}
	for _, m := range malformed {
		switch m.Directive {
		case "unterminated-quoted-string":
			return m.Path, false, true
		case "toolchain-unterminated-quoted-string":
			return m.Path, true, true
		}
	}
	return "", false, false
}

// goWorkUnknownDirective reports the first go.mod-only top-level directive
// verb — "module", "require", "exclude", "tool", or "ignore" — found in a
// go.work file's content, if any. golang.org/x/mod/modfile's WorkFile.add
// (rule.go, the parser real `cmd/go` itself uses for go.work) only
// recognizes "go", "toolchain", "godebug", "use", and "replace" as valid
// go.work verbs; anything else — including every one of go.mod's own
// module-declaration/dependency/ignore directives — falls into its
// `default: errorf("unknown directive: %s", verb)` branch. go.work's
// grammar is a strict *subset* of go.mod's, but ParseGoMod (reused
// verbatim for go.work content elsewhere in this file, since "replace"
// syntax is byte-identical between the two — see goWorkReplaces's own doc
// comment) has no model of that restriction at all: fed a go.work
// containing e.g. a `require` line, it happily parses it as an ordinary
// go.mod requirement, with no error and no MalformedDirective, because
// `require` genuinely is well-formed go.mod grammar.
//
// Live-verified against real go1.24.4 and go1.26.8 (GOPROXY=off, so
// nothing below depends on network access): a two-module workspace
// (`use ./a`, a `replace` redirecting an otherwise-unresolvable
// requirement to a local directory) with one extra top-level `require`
// line added to go.work itself makes `go build`/`go list -m all`, run
// from inside the workspace member, Fatal immediately with "errors
// parsing go.work: go.work:N: unknown directive: require" — before
// resolving a single module, including the replace directive sitting
// right next to it in the same file. The identical Fatal reproduces for
// `module`/`exclude`/`tool` substituted in place of `require`, and for
// `ignore` specifically on a toolchain new enough to recognize it inside
// an ordinary go.mod (ignore is *never* valid in go.work, on any
// toolchain version — unlike in go.mod, where technique #148's fix
// already gates it on the Go 1.25 cutoff; WorkFile.add's switch has no
// "ignore" case at all, so this one needs no version check). Before this
// function existed, goWorkReplaces extracted and trusted that same
// replace directive regardless, so modslop reported the workspace's
// requirement as resolved/local when the real go command can't resolve
// anything in that workspace at all — the same "go itself would Fatal
// first" family already closed for go.mod's own grammar (techniques
// #119/#127/#131/#135/#139/#143/#148), just one file type over: go.work
// was never checked against its *own*, narrower grammar at all.
//
// `retract` is deliberately not checked here: ParseGoMod doesn't
// recognize `retract` as a top-level keyword in the audited file at all
// (it's parsed elsewhere, only for a dependency's own go.mod under the
// proxy — see technique #135's own note), so a go.work `retract` line
// already falls through to the same silent-skip every genuinely
// unrecognized line gets, independent of file type; closing that is a
// separate, pre-existing gap this function doesn't attempt to fix.
func goWorkUnknownDirective(content string) (verb string, ok bool) {
	reqs, _, tools, excludes, modulePath, _, _, err := ParseGoMod(content)
	if err != nil {
		return "", false
	}
	switch {
	case modulePath != "":
		return "module", true
	case len(reqs) > 0:
		return "require", true
	case len(excludes) > 0:
		return "exclude", true
	case len(tools) > 0:
		return "tool", true
	case hasIgnoreDirective(content):
		return "ignore", true
	}
	return "", false
}

// goModKnownVerbs is the complete set of top-level go.mod directive verbs
// ever recognized by any supported Go toolchain version:
// golang.org/x/mod/modfile's rule.go Parse dispatches on exactly these ten
// — module, go, toolchain, require, exclude, replace, retract, tool
// (go1.24+), godebug (go1.21+), and ignore (go1.25+, gated separately and
// more precisely by checkIgnoreDirectiveTooOld, so by the time this set is
// consulted "ignore" is already known to be either absent or worth its own,
// more specific finding). A verb outside this set was never valid go.mod
// syntax on any Go version at all, so — unlike tool/godebug/ignore, whose
// recognition genuinely depends on which toolchain runs the file —
// flagging it doesn't need its own version check: it's an unconditional
// Fatal on every version. Ported from goproxycheck's identical
// goModKnownVerbs (v0.1.90), which found and fixed this exact gap in its
// own, narrower go.mod-reading path first.
//
// `retract` is included even though ParseGoMod only recognizes it as a
// top-level keyword for the audited file's own malformed-directive
// detection (see parseRetractLine) — unlike require/replace/tool/exclude/
// module, a well-formed retract directive's actual version/interval value
// is never kept anywhere, since no existing check needs the audited
// go.mod's OWN retract data; that's parsed elsewhere entirely, only for a
// dependency's own upstream go.mod under the proxy (retract.go), via
// golang.org/x/mod/modfile directly rather than this hand-rolled parser.
// It's genuinely valid go.mod grammar real go accepts without complaint
// either way; omitting it here would misreport an entirely ordinary
// top-level retract directive as unknown.
var goModKnownVerbs = map[string]bool{
	"module":    true,
	"go":        true,
	"toolchain": true,
	"require":   true,
	"exclude":   true,
	"replace":   true,
	"retract":   true,
	"tool":      true,
	"godebug":   true,
	"ignore":    true,
}

// goModUnknownDirective reports the first top-level line in a go.mod's raw
// content whose leading token isn't one of goModKnownVerbs, plus whether
// that line opens a parenthesized block — real go's Fatal wording differs
// between the two shapes (see checkGoModUnknownDirective). Lines inside an
// already-open *known* block are skipped entirely (they're argument
// values, like a require block's module/version entries, not directives
// of their own); a block opened by an *unknown* verb is reported
// immediately, on its own opening line, without trying to track where it
// closes — matching real go, which Fatals on the unrecognized opening line
// itself and never reads any further.
//
// ParseGoMod (above) can't answer this question itself: its scan silently
// drops any line that doesn't match one of its own cutKeyword checks (see
// the final bare `continue` ending its blockKind == "" branch), with no
// return value recording that a line was skipped at all — correct for
// ParseGoMod's own purpose of extracting the directives it knows how to
// use, but it means a go.mod carrying a genuinely unrecognized verb (a
// typo like `requrie`, a leftover word from a merge conflict, or a
// wrong-case known verb like `Require`) parses "cleanly," with every
// ordinary require/replace/etc. line on either side of it still extracted
// and checked normally.
//
// Live-verified against real go1.24.4 and go1.26.8 (GOPROXY=off, zero
// network access): a go.mod reading only `module example.com/foo` / `go
// 1.21` / one ordinary `require` line, plus one extra top-level line
// `bogusverb oops`, makes `go list -m all`/`go build` Fatal immediately
// with `go.mod:N: unknown directive: bogusverb` — before resolving a
// single requirement, including the well-formed one sitting right next to
// it in the same file. The identical Fatal reproduces for a bare unknown
// verb with no arguments at all, and for a wrong-case known verb
// (`Require ...` -> `unknown directive: Require`; go.mod verbs are
// case-sensitive). An unknown verb that opens a parenthesized block
// instead (`bogusverb (` ... `)`, or even `bogusverb(` with no space —
// confirmed real go accepts a block-opening "(" with no preceding
// whitespace for a *known* verb like `require(`, so the same token
// boundary applies to an unknown one) Fatals with a different, real
// wording: `go.mod:N: unknown block type: bogusverb`. Also confirmed the
// ordering: a go.mod with both an invalid module path (line 1) and an
// unknown directive (line 5) Fatals on the unknown directive alone — the
// module path's own semantic validity is never even reached, since that
// check only runs after the whole file's syntax has already parsed clean.
//
// Before this function existed, a go.mod broken this way reported "checked
// N requirement(s), nothing flagged" (every ordinary requirement still
// resolved and checked normally) for a go.mod the real go command refuses
// to parse at all — the same "self-contradictory, unbuildable file, not a
// heuristic" blind spot already closed, for other shapes, by
// checkMalformedDirectives/checkIgnoreDirectiveTooOld/
// checkGoWorkUnknownDirective (the last of which solved the identical
// problem one file type over, for go.work's own narrower grammar, but was
// never generalized back to go.mod's own file-level scan this function
// adds).
func goModUnknownDirective(content string) (verb string, block bool, ok bool) {
	content, _ = strings.CutPrefix(content, "\uFEFF")
	// A line consisting only of "/*" (or any other line whose only content
	// sits inside a "/* ... */" span) is not an unknown top-level verb at
	// all \u2014 it's a different, more specific real Fatal with its own
	// wording (see stripBlockComments's own doc comment and
	// checkGoModBlockComment), which already reports it; blanking the span
	// here keeps this function from also reporting it, under a different
	// and misleading message, as if "/*" itself were an ordinary (if
	// unrecognized) directive verb.
	content, _ = stripBlockComments(content)
	inBlock := false
	for _, raw := range strings.Split(content, "\n") {
		if inBlock {
			if strings.TrimSpace(stripComment(raw)) == ")" {
				inBlock = false
			}
			continue
		}
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		field := line
		rest := ""
		if i := strings.IndexAny(line, " \t("); i >= 0 {
			field, rest = line[:i], strings.TrimSpace(line[i:])
		}
		if rest == "(" {
			if !goModKnownVerbs[field] {
				return field, true, true
			}
			inBlock = true
			continue
		}
		if !goModKnownVerbs[field] {
			return field, false, true
		}
	}
	return "", false, false
}

// mergeReplaces overlays a workspace's go.work replace directives on top
// of a module's own go.mod replaces. `go help work` says "If a module is
// replaced in both the workspace's go.work file and in the workspace
// module's go.mod file, the replacement in the go.work file is used," but
// that statement is about the *module*, not blindly about the old path —
// verified live against the real go toolchain (`go list -m all`/`go run`
// in a scratch workspace, four scenarios) that the actual precedence is
// per-version, same shape as selectReplace's own general-vs-specific
// rule, just applied across the go.work/go.mod boundary:
//
//   - go.work has a version-agnostic (general) replace for the path: it
//     wins outright, even over a go.mod replace that exactly matches the
//     required version — every go.mod-level entry for that path is
//     dropped.
//   - go.work only has version-specific replace(s) for the path: each one
//     only shadows a go.mod-level entry for that *exact* version; a
//     go.mod-level general replace, or a go.mod-level specific replace
//     for a version go.work doesn't mention, still applies untouched.
//
// A naive "go.work mentions this path at all, so drop every go.mod entry
// for it" rule (this function's shape before this comment) is wrong in
// the second case: a go.work replace pinned to one version (e.g. an
// in-progress fork of only the version currently required by a sibling
// workspace member) would incorrectly blank out an unrelated go.mod-level
// replace for the same module, sending a legitimate local dependency to
// the public proxy instead.
//
// Implementation: put overlay's entries first so selectReplace's
// first-specific-match-wins scan (see its own doc comment) prefers an
// exact-version tie in go.work's favor, matching the live-verified
// "both replace the same version" case; only drop base's entries for a
// path when overlay carries a general (OldVersion == "") entry for it,
// since only a general entry is guaranteed to apply regardless of which
// version ends up being looked up.
func mergeReplaces(base, overlay []Replacement) []Replacement {
	if len(overlay) == 0 {
		return base
	}
	generalInOverlay := make(map[string]bool, len(overlay))
	for _, r := range overlay {
		if r.OldVersion == "" {
			generalInOverlay[r.Old] = true
		}
	}
	merged := make([]Replacement, 0, len(base)+len(overlay))
	merged = append(merged, overlay...)
	for _, r := range base {
		if generalInOverlay[r.Old] {
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// BaseName returns the last path segment of a module path, e.g.
// "gin" for "github.com/gin-gonic/gin" or "v9" for
// "github.com/redis/go-redis/v9" (major-version suffixes are
// stripped so the comparison targets the meaningful name).
func BaseName(modPath string) string {
	segs := strings.Split(modPath, "/")
	name := segs[len(segs)-1]
	if len(segs) > 1 && isMajorVersionSuffix(name) {
		name = segs[len(segs)-2]
	}
	return name
}

// isMajorVersionSuffix reports whether s is a path element the real go
// command recognizes as an explicit major-version suffix. Per
// golang.org/x/mod/module's CheckPath doc comment (the real rule `go`
// itself enforces): "for a final path element of the form /vN, where N
// looks numeric ... must not begin with a leading zero, must not be /v1".
// v0 and v1 are never written as an explicit suffix at all — Go's
// import-compatibility rule omits it for those two — so "v0" and "v1" as
// a bare trailing path element are not major-version suffixes, just an
// ordinary (if unusual) path segment.
//
// Confirmed live, 2026-09: a go.mod containing `require
// example.com/foo/v1 v1.0.0` (or .../v0, or a leading-zero form like
// .../v01) fails to parse at all — "malformed module path" — regardless
// of the version given, on every real go toolchain invocation (go build,
// go list -m all). Before this fix, BaseName("example.com/foo/v1")
// stripped "v1" and returned "foo", same as it would for a genuine
// suffix like "v2" — silently treating a hallucination-shaped path (an
// AI or corrupted go.mod appending an explicit "/v1" the same way it
// would append a real "/v2", not knowing the real go command omits v1's
// suffix entirely) as if it named the same module as its unsuffixed
// form, rather than recognizing "v1"/"v0" is just the module's own last
// path segment.
func isMajorVersionSuffix(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	digits := s[1:]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	if digits[0] == '0' || digits == "1" {
		return false
	}
	return true
}
