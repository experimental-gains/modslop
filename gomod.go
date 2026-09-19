package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Requirement is one entry from a go.mod require block.
type Requirement struct {
	Path    string
	Version string
}

// ParseGoMod extracts require entries from a go.mod file's content.
// It handles both single-line ("require foo/bar v1.0.0") and
// block ("require (\n\tfoo/bar v1.0.0\n)") forms. It deliberately
// does not depend on golang.org/x/mod so this tool has zero
// external dependencies.
func ParseGoMod(content string) ([]Requirement, error) {
	var reqs []Requirement
	scanner := bufio.NewScanner(strings.NewReader(content))
	inBlock := false

	for scanner.Scan() {
		line := stripComment(scanner.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if !inBlock {
			if trimmed == "require (" {
				inBlock = true
				continue
			}
			if strings.HasPrefix(trimmed, "require ") {
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "require"))
				if r, ok := parseRequireLine(rest); ok {
					reqs = append(reqs, r)
				}
			}
			continue
		}

		if trimmed == ")" {
			inBlock = false
			continue
		}
		if r, ok := parseRequireLine(trimmed); ok {
			reqs = append(reqs, r)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return reqs, nil
}

func parseRequireLine(s string) (Requirement, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(s, "// indirect"))
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return Requirement{}, false
	}
	return Requirement{Path: fields[0], Version: fields[1]}, true
}

func stripComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// LoadGoMod reads and parses a go.mod file from disk.
func LoadGoMod(path string) ([]Requirement, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
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
