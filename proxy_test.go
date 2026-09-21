package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewProxyClient(t *testing.T) {
	c := NewProxyClient()
	if c.BaseURL != proxyBaseURL {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL, proxyBaseURL)
	}
	if c.HTTP == nil || c.HTTP.Timeout != 10*time.Second {
		t.Errorf("HTTP client not configured with a 10s timeout: %+v", c.HTTP)
	}
}

func TestEscapeModulePath(t *testing.T) {
	cases := map[string]string{
		"github.com/gin-gonic/gin":     "github.com/gin-gonic/gin",
		"github.com/BurntSushi/toml":   "github.com/!burnt!sushi/toml",
		"ALLCAPS":                      "!a!l!l!c!a!p!s",
		"":                             "",
		"github.com/redis/go-redis/v9": "github.com/redis/go-redis/v9",
	}
	for in, want := range cases {
		if got := escapeModulePath(in); got != want {
			t.Errorf("escapeModulePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProxyClientGetNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status, body, err := c.get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
	if string(body) != "boom" {
		t.Errorf("body = %q, want %q", body, "boom")
	}
}

func TestProxyClientGetTransportError(t *testing.T) {
	c := &ProxyClient{HTTP: &http.Client{}}
	// A URL with an unsupported scheme fails at the transport layer
	// before any response is received, exercising the err != nil branch.
	_, _, err := c.get("not-a-url://\x00")
	if err == nil {
		t.Fatal("expected an error for a malformed URL")
	}
}

func TestProxyClientLookupUnknownOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/whatever")
	if !status.Unknown {
		t.Errorf("expected Unknown=true on a 500 response, got %+v", status)
	}
}

func TestProxyClientLookupNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/missing")
	if status.Exists || status.Unknown {
		t.Errorf("expected Exists=false, Unknown=false on a 404, got %+v", status)
	}
}

func TestProxyClientLookupUsesTagTimeNotPseudoVersionTime(t *testing.T) {
	// Reproduces github.com/grafana/alerting: @latest resolves to a
	// pseudo-version (tip of the default branch, timestamped "now")
	// even though the module has one real tag from months earlier. The
	// module's actual age should come from that tag, not the pseudo-
	// version, or an actively-committed-to old project looks brand new.
	const oldTagTime = "2026-04-07T20:18:58Z"
	const pseudoVersionTime = "2026-09-17T19:44:16Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			w.Write([]byte(`{"Version":"v0.0.0-20260917194416-dc69727f248e","Time":"` + pseudoVersionTime + `"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			w.Write([]byte("v0.0.0-release-12.4.3\n"))
		case strings.HasSuffix(r.URL.Path, "/@v/v0.0.0-release-12.4.3.info"):
			w.Write([]byte(`{"Version":"v0.0.0-release-12.4.3","Time":"` + oldTagTime + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/whatever")

	if status.VersionCount != 1 {
		t.Fatalf("VersionCount = %d, want 1", status.VersionCount)
	}
	wantTime, _ := time.Parse(time.RFC3339, oldTagTime)
	if !status.LatestTime.Equal(wantTime) {
		t.Errorf("LatestTime = %v, want the tag's time %v (not the pseudo-version's %v)", status.LatestTime, wantTime, pseudoVersionTime)
	}
	if looksUnestablished(status) {
		t.Errorf("looksUnestablished(%+v) = true, want false — the tag is months old", status)
	}
}

func TestProxyClientLookupBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/whatever")
	if !status.Unknown {
		t.Errorf("expected Unknown=true on unparseable JSON, got %+v", status)
	}
}

// TestProxyClientLookupPrivatePatternSkipsNetwork is the regression for a
// real false positive confirmed live (run #87): the real `go` command
// never queries the public proxy at all for a path covered by
// GOPRIVATE/GONOPROXY — it fetches directly from VCS instead (confirmed
// with `go get -x` against a GOPRIVATE-matched module: proxy.golang.org
// was never contacted for the module path itself). `modslop` used to
// query the public proxy unconditionally regardless of local
// GOPRIVATE/GONOPROXY config, so every legitimately private dependency —
// something essentially every real company go.mod has — got a
// high-severity "not-found ... may be a hallucinated import" false
// positive on every run, exactly the noise this tool exists to cut
// through. This test asserts the network is never even touched (the test
// server 404s everything and would fail any other test relying on a real
// response) once the path matches a configured private pattern.
func TestProxyClientLookupPrivatePatternSkipsNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected proxy request for a GOPRIVATE-covered path: %s", r.URL)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client(), PrivatePatterns: []string{"corp.example.invalid/*"}}
	status := c.Lookup("corp.example.invalid/internal/widget")
	if !status.Private {
		t.Errorf("expected Private=true for a GOPRIVATE-covered path, got %+v", status)
	}
	if status.Unknown || status.Exists {
		t.Errorf("expected only Private to be set, got %+v", status)
	}
}
