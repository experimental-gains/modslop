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
	Directive string // "require", "exclude", "tool", "module", "module-repeated", "replace", or "bom"
	// Path is a best-effort guess at the module path the author was
	// naming — the line's own leading field, e.g. "github.com/pkg/errors"
	// for a require line missing its version entirely, or the first
	// (extraneous-trailing-content) field of a malformed tool/module/
	// replace line. For "module-repeated" it's the repeated directive's
	// own (well-formed) path. "" when the line has no leading field to
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
func ParseGoMod(content string) ([]Requirement, []Replacement, []string, []Requirement, string, []MalformedDirective, error) {
	var reqs []Requirement
	var reps []Replacement
	var tools []string
	var excludes []Requirement
	var modulePath string
	var moduleSeen bool
	var malformed []MalformedDirective
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
	scanner := bufio.NewScanner(strings.NewReader(content))
	blockKind := "" // "", "require", "replace", "tool", "exclude", or "module"

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
				if r, ok := parseRequireLine(rest); ok {
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
				if r, ok := parseReplaceLine(rest); ok {
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
				if t, ok := parseToolLine(rest); ok {
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
				if r, ok := parseRequireLine(rest); ok {
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
				if m, ok := parseToolLine(rest); ok {
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
			continue
		}

		if trimmed == ")" {
			blockKind = ""
			continue
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
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, nil, "", nil, err
	}
	return reqs, reps, tools, excludes, modulePath, malformed, nil
}

func parseRequireLine(s string) (Requirement, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(s, "// indirect"))
	path, rest := firstField(s)
	if path == "" || rest == "" {
		return Requirement{}, false
	}
	version, _ := firstField(rest)
	if version == "" {
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
func LoadGoMod(path string) ([]Requirement, []Replacement, []string, []Requirement, string, []MalformedDirective, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, nil, "", nil, fmt.Errorf("reading %s: %w", path, err)
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
	_, reps, _, _, _, _, err := ParseGoMod(string(data))
	if err != nil {
		return nil
	}
	return reps
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
