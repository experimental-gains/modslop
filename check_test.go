package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClosestPopularMatch(t *testing.T) {
	if match, ok := closestPopularMatch("github.com/gni-gonic/gin", "gin"); !ok || match != "" {
		// "gin" itself is short (3 chars, below typoMinNameLen=4) so it
		// should not trigger — this guards against noisy short-name findings.
		if ok {
			t.Errorf("expected no match for short base name, got %q", match)
		}
	}

	if match, ok := closestPopularMatch("github.com/sirupsen/logrusx", "logrusx"); !ok {
		t.Fatal("expected a match for logrusx (one edit from logrus)")
	} else if !strings.Contains(match, "logrus") {
		t.Errorf("expected match to reference logrus, got %q", match)
	}

	if _, ok := closestPopularMatch("github.com/sirupsen/logrus", "logrus"); ok {
		t.Error("exact match on the real module should not be flagged")
	}

	if _, ok := closestPopularMatch("github.com/completely/unrelated-project-name", "unrelated-project-name"); ok {
		t.Error("unrelated name should not match anything")
	}
}

// fakeProxy spins up an httptest server that mimics proxy.golang.org
// responses for a fixed set of modules, so tests don't hit the network.
func fakeProxy(t *testing.T, modules map[string]struct {
	versions []string
	latest   string
	when     time.Time
}) *ProxyClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for path, m := range modules {
			escaped := escapeModulePath(path)
			if r.URL.Path == "/"+escaped+"/@latest" {
				fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, m.latest, m.when.Format(time.RFC3339))
				return
			}
			if r.URL.Path == "/"+escaped+"/@v/list" {
				fmt.Fprint(w, strings.Join(m.versions, "\n"))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
}

func TestCheckRequirement_NotFound(t *testing.T) {
	proxy := fakeProxy(t, nil)
	findings := CheckRequirement(Requirement{Path: "github.com/totally/madeup-pkg-xyz"}, proxy)
	if len(findings) != 1 || findings[0].Reason != "not-found" {
		t.Fatalf("expected one not-found finding, got %+v", findings)
	}
}

func TestCheckRequirement_NewAndThin(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/someone/brandnew": {
			versions: []string{"v0.1.0"},
			latest:   "v0.1.0",
			when:     time.Now().Add(-2 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/someone/brandnew"}, proxy)
	if len(findings) != 1 || findings[0].Reason != "new-and-thin" {
		t.Fatalf("expected one new-and-thin finding, got %+v", findings)
	}
}

func TestCheckRequirement_EstablishedModuleClean(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/someone/established": {
			versions: []string{"v1.0.0", "v1.1.0", "v2.0.0"},
			latest:   "v2.0.0",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/someone/established"}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for an established module, got %+v", findings)
	}
}

func TestCheckRequirement_TyposquatOfPopular(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/sirupsen/logrusx": {
			versions: []string{"v1.0.0", "v1.0.1"},
			latest:   "v1.0.1",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/sirupsen/logrusx"}, proxy)
	if len(findings) != 1 || findings[0].Reason != "name-collision-risk" {
		t.Fatalf("expected one name-collision-risk finding, got %+v", findings)
	}
}
