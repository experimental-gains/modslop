package main

import "testing"

func TestParseGoModBlock(t *testing.T) {
	content := `module example.com/foo

go 1.24

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/pkg/errors v0.9.1 // indirect
)

require golang.org/x/net v0.20.0
`
	reqs, err := ParseGoMod(content)
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
