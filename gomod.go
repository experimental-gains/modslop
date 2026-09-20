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
	Old string // module path being replaced
	New string // another module path, or a local filesystem path
}

// IsLocal reports whether the replacement points at a local filesystem
// path rather than a fetchable module. Per `go help goproxy` semantics,
// that's true when the target begins with "./" or "../", or is absolute.
func (r Replacement) IsLocal() bool {
	return strings.HasPrefix(r.New, "./") || strings.HasPrefix(r.New, "../") || filepath.IsAbs(r.New)
}

// ParseGoMod extracts require and replace entries from a go.mod file's
// content. It handles both single-line ("require foo/bar v1.0.0") and
// block ("require (\n\tfoo/bar v1.0.0\n)") forms for each directive. It
// deliberately does not depend on golang.org/x/mod so this tool has
// zero external dependencies.
func ParseGoMod(content string) ([]Requirement, []Replacement, error) {
	var reqs []Requirement
	var reps []Replacement
	scanner := bufio.NewScanner(strings.NewReader(content))
	blockKind := "" // "", "require", or "replace"

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
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return reqs, reps, nil
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

// parseReplaceLine parses one "old [version] => new [version]" entry.
// The version fields are optional on both sides and ignored — only the
// paths matter for checking what code is actually going to be fetched.
func parseReplaceLine(s string) (Replacement, bool) {
	parts := strings.SplitN(s, "=>", 2)
	if len(parts) != 2 {
		return Replacement{}, false
	}
	oldPath, _ := firstField(parts[0])
	newPath, _ := firstField(parts[1])
	if oldPath == "" || newPath == "" {
		return Replacement{}, false
	}
	return Replacement{Old: oldPath, New: newPath}, true
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

func stripComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// LoadGoMod reads and parses a go.mod file from disk.
func LoadGoMod(path string) ([]Requirement, []Replacement, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", path, err)
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
