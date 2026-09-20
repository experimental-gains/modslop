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
	reqs, reps, err := ParseGoMod(content)
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
	reqs, reps, err := ParseGoMod(content)
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
	_, reps, err := ParseGoMod(content)
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

	reqs, _, err := LoadGoMod(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != "github.com/pkg/errors" {
		t.Errorf("got %+v", reqs)
	}

	if _, _, err := LoadGoMod(filepath.Join(dir, "missing.mod")); err == nil {
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
