package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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
}

// IsLocal reports whether the replacement points at a local filesystem
// path rather than a fetchable module. Per golang.org/x/mod/modfile's
// IsDirectoryPath — the real go tool's own grammar (verified live:
// `replace foo => ..` builds and `go list -m all` resolves it straight
// off disk, no network call) — that's true when the target is exactly
// "." or "..", begins with "./" or "../", or is absolute. Missing the
// bare "." and ".." forms let a purely local replace fall through to
// CheckAll's "another module" branch, which sends the literal string "."
// or ".." to the module proxy as if it were a real dependency — a
// guaranteed "not-found"/hallucinated-import false positive on exactly
// the kind of go.mod this tool exists to audit correctly. Windows-style
// forms (".\", "..\", a drive letter) are in the real x/mod check too,
// but a go.mod containing one fails to parse at all on a non-Windows
// host, so this tool — which only ever runs on Linux — doesn't need to
// recognize them.
func (r Replacement) IsLocal() bool {
	return r.New == "." || r.New == ".." ||
		strings.HasPrefix(r.New, "./") || strings.HasPrefix(r.New, "../") ||
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
func ParseGoMod(content string) ([]Requirement, []Replacement, []string, error) {
	var reqs []Requirement
	var reps []Replacement
	var tools []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	blockKind := "" // "", "require", "replace", or "tool"

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
			}
		case "replace":
			if r, ok := parseReplaceLine(trimmed); ok {
				reps = append(reps, r)
			}
		case "tool":
			if t, ok := parseToolLine(trimmed); ok {
				tools = append(tools, t)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, err
	}
	return reqs, reps, tools, nil
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
// new side's version is ignored — only its path matters for checking what
// code is actually going to be fetched. The old side's version is kept
// (OldVersion, "" if absent) because CheckAll needs it to pick the right
// entry when a go.mod carries both a version-specific and a version-
// agnostic replace for the same module — see selectReplace.
func parseReplaceLine(s string) (Replacement, bool) {
	parts := strings.SplitN(s, "=>", 2)
	if len(parts) != 2 {
		return Replacement{}, false
	}
	oldPath, oldRest := firstField(parts[0])
	oldVersion, _ := firstField(oldRest)
	newPath, _ := firstField(parts[1])
	if oldPath == "" || newPath == "" {
		return Replacement{}, false
	}
	return Replacement{Old: oldPath, OldVersion: oldVersion, New: newPath}, true
}

// parseToolLine parses one `tool` directive entry: a single bare (or
// quoted) package import path, with no version and no "// indirect"
// suffix (those only apply to require entries) — go.mod's own grammar
// for `tool` is just the path, full stop. Reuses firstField so a
// quoted path with a space is unquoted the same way a require or
// replace path is.
func parseToolLine(s string) (string, bool) {
	path, _ := firstField(s)
	if path == "" {
		return "", false
	}
	return path, true
}

// firstField returns the leading field of s and everything after it: for a
// require entry that's the module path (rest starts with the version); for
// a replace side it's the whole path. go.mod's real lexer
// (golang.org/x/mod/modfile) allows any token to be written as a double- or
// backtick-quoted Go string literal instead of a bare word — `go mod edit`
// does this itself for a local replace path containing a space (e.g.
// replace foo => "../my mod"), which `go build` accepts fine. A naive
// whitespace split truncates that at the space and leaves a stray quote
// character, so a quoted token is unquoted first.
func firstField(s string) (field, rest string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if s[0] == '"' || s[0] == '`' {
		if tok, n, ok := leadingQuotedString(s); ok {
			return tok, strings.TrimSpace(s[n:])
		}
	}
	if i := strings.IndexFunc(s, unicode.IsSpace); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// leadingQuotedString parses a double- or backtick-quoted Go string literal
// at the start of s and returns its unquoted value plus the number of bytes
// of s it consumed (including both quote characters). Double-quoted
// strings honor backslash escapes (e.g. \" \\); backtick-quoted raw
// strings don't.
func leadingQuotedString(s string) (value string, consumed int, ok bool) {
	if s[0] == '`' {
		if i := strings.IndexByte(s[1:], '`'); i >= 0 {
			return s[1 : i+1], i + 2, true
		}
		return "", 0, false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '"' {
			return b.String(), i + 1, true
		}
		b.WriteByte(c)
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
func cutKeyword(s, kw string) (rest string, ok bool) {
	if !strings.HasPrefix(s, kw) {
		return "", false
	}
	rest = s[len(kw):]
	if rest == "" {
		return "", false
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
func selectReplace(entries []Replacement, version string) (Replacement, bool) {
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
	if general != nil {
		return *general, true
	}
	return Replacement{}, false
}

// LoadGoMod reads and parses a go.mod file from disk.
func LoadGoMod(path string) ([]Requirement, []Replacement, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseGoMod(string(b))
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

func isMajorVersionSuffix(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
