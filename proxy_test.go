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
		// Pins the `r <= 'Z'` boundary (found LIVED by mutation
		// testing, run #127: "ALLCAPS" hits 'A' but no existing case
		// has a literal 'Z').
		"github.com/foo/Zebra": "github.com/foo/!zebra",
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
		_, _ = w.Write([]byte("boom"))
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

// TestProxyClientLookupBlocklistedMalicious is the regression for a real,
// verified false negative (run #122): proxy.golang.org returns 403 with a
// distinctive plain-text body when it has flagged a specific module as
// malicious (confirmed live against three real GHSA-documented malicious
// modules: github.com/shopsprint/decimal, github.com/boltdb-go/bolt,
// github.com/xinfeisoft/crypto — all three return this exact text as of
// 2026-09). Before this fix, `Lookup` treated every non-200/404/410 status
// identically as `Unknown` ("network trouble, say nothing"), so a module
// the Go authorities had already confirmed and actively blocked as
// malware sailed through `modslop` with zero warning — worse than a
// missed typosquat, since the ground truth was sitting right there in
// the proxy's own response.
func TestProxyClientLookupBlocklistedMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("SECURITY ERROR\nThe module proxy considers this module to be malicious\nand will not serve it. It may be dangerous to execute\nthe code contained within this module.\n"))
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("github.com/shopsprint/decimal")
	if !status.Blocklisted {
		t.Errorf("expected Blocklisted=true on a proxy malware-block 403, got %+v", status)
	}
	if status.Unknown || status.Exists {
		t.Errorf("expected only Blocklisted to be set, got %+v", status)
	}
}

// TestProxyClientLookupGeneric403StaysUnknown guards the other direction:
// a 403 with no malware marker (rate limiting, an outage — see golang/go
// issues #48107, #71094, #80655, all spurious 403s against legitimate
// popular modules) must not be misread as a malware block.
func TestProxyClientLookupGeneric403StaysUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("rate limited, try again later"))
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("github.com/klauspost/compress")
	if status.Blocklisted {
		t.Errorf("expected Blocklisted=false on a generic 403, got %+v", status)
	}
	if !status.Unknown {
		t.Errorf("expected Unknown=true on a generic 403, got %+v", status)
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
			_, _ = w.Write([]byte(`{"Version":"v0.0.0-20260917194416-dc69727f248e","Time":"` + pseudoVersionTime + `"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = w.Write([]byte("v0.0.0-release-12.4.3\n"))
		case strings.HasSuffix(r.URL.Path, "/@v/v0.0.0-release-12.4.3.info"):
			_, _ = w.Write([]byte(`{"Version":"v0.0.0-release-12.4.3","Time":"` + oldTagTime + `"}`))
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

// TestProxyClientLookupFetchesLatestModBody is a regression test for the
// retraction check (retract.go): Lookup must fetch a go.mod body so
// evaluateModuleStatus can check it for a `retract` directive covering
// whatever specific version a go.mod actually requires. This case is the
// common one, where @latest's own version already is the highest tag in
// its major-version line, so it's also the one Lookup fetches the go.mod
// from — see TestProxyClientLookupFetchesRetractingVersionPastLatest for
// the case where those two versions diverge.
func TestProxyClientLookupFetchesLatestModBody(t *testing.T) {
	const modBody = "module example.com/whatever\n\ngo 1.21\n\nretract v0.9.0\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.mod"):
			_, _ = w.Write([]byte(modBody))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = w.Write([]byte("v1.0.0\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/whatever")

	if status.LatestModBody != modBody {
		t.Errorf("LatestModBody = %q, want the @latest version's go.mod body %q", status.LatestModBody, modBody)
	}
}

// TestProxyClientLookupFetchesRetractingVersionPastLatest reproduces
// github.com/jayconrod/retract, the Go team's own canonical example of a
// version retracting itself: v1.0.1 retracts both itself and v1.0.0, so
// @latest resolves past both of them to v0.9.9 — a version tagged years
// before the `retract` directive existed, whose go.mod carries no
// retract block at all (confirmed live against the real proxy, 2026-09).
// Before this fix, Lookup always fetched info.Version's (@latest's) own
// go.mod into LatestModBody, so LatestModBody came back empty of
// retractions here and a go.mod requiring v1.0.0 produced no finding —
// the exact false negative the retraction check exists to catch. Lookup
// must instead fetch the go.mod of the highest tag in @latest's own
// major-version line (v1.0.1), matching what `go list -m -u` actually
// consults (go.dev/ref/mod#go-mod-file-retract: retractions are read from
// the version @latest would resolve to *before* retractions are
// considered).
func TestProxyClientLookupFetchesRetractingVersionPastLatest(t *testing.T) {
	const retractingModBody = "module example.com/whatever\n\ngo 1.21\n\nretract (\n\tv1.0.0 // Published accidentally.\n\tv1.0.1 // For retractions only.\n)\n"
	const oldModBody = "module example.com/whatever\n\ngo 1.16\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v0.9.9","Time":"2021-01-26T16:46:49Z"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/v0.9.9.mod"):
			_, _ = w.Write([]byte(oldModBody))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.1.mod"):
			_, _ = w.Write([]byte(retractingModBody))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			// Shuffled on purpose, same as the earliest-time test below —
			// @v/list order carries no meaning and must not be relied on.
			_, _ = w.Write([]byte("v1.0.0\nv0.9.9\nv1.0.1\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/whatever")

	if status.LatestModBody != retractingModBody {
		t.Errorf("LatestModBody = %q, want the highest tag's (v1.0.1's) go.mod body %q", status.LatestModBody, retractingModBody)
	}

	if rationale, retracted := retraction(status.LatestModBody, "v1.0.0"); !retracted {
		t.Errorf("retraction(LatestModBody, %q) = (%q, false), want retracted=true", "v1.0.0", rationale)
	}
}

// TestProxyClientLookupSkipsAbandonedHigherMajorLineForRetraction
// reproduces the other half of the same fix's risk: it must not regress
// into fetching the go.mod of an unrelated, abandoned higher-major-
// version experiment just because it happens to be the highest tag ever
// published. github.com/mattn/go-sqlite3's highest tag overall is
// v2.0.3+incompatible (a v2 experiment abandoned in 2020, whose bare,
// pre-modules go.mod carries no retract block at all — confirmed live
// against the real proxy) while its actual, actively-tagged-through-2026
// v1.x line — where the retract directive covering that abandoned v2
// range actually lives — keeps incrementing past it. `go list -m -u` for
// a go.mod requiring v2.0.3+incompatible still resolves retraction info
// from v1.14.52's go.mod (confirmed live), never v2.0.3+incompatible's
// own, so Lookup must scope its "highest tag" search to @latest's own
// major-version line rather than the true global maximum.
func TestProxyClientLookupSkipsAbandonedHigherMajorLineForRetraction(t *testing.T) {
	const v1ModBody = "module github.com/mattn/go-sqlite3\n\ngo 1.21\n\nretract (\n\t[v2.0.0+incompatible, v2.0.7+incompatible] // Accidental; no major changes or features.\n)\n"
	const v2ModBody = "module github.com/mattn/go-sqlite3\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v1.14.52","Time":"2026-09-05T04:18:43Z"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.14.52.mod"):
			_, _ = w.Write([]byte(v1ModBody))
		case strings.HasSuffix(r.URL.Path, "/@v/v2.0.3+incompatible.mod"):
			_, _ = w.Write([]byte(v2ModBody))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = w.Write([]byte("v1.14.52\nv2.0.0+incompatible\nv2.0.1+incompatible\nv2.0.2+incompatible\nv2.0.3+incompatible\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("github.com/mattn/go-sqlite3")

	if status.LatestModBody != v1ModBody {
		t.Errorf("LatestModBody = %q, want v1.14.52's go.mod body %q (not the abandoned v2 line's)", status.LatestModBody, v1ModBody)
	}
}

// TestProxyClientLookupEarliestTimeUsesSemverNotListOrder is a regression
// test for a real evasion (2026-09, disclosed alongside the Graphalgo
// Terraform/npm campaign): a malicious Go module published 16 versions
// across ~2 months, specifically defeating a "flag if only one version
// exists" check. Catching that requires knowing the *oldest* tag's
// publish time, but @v/list is not returned in chronological or semver
// order (confirmed live against the real proxy for that module) — this
// test's list is deliberately shuffled to make sure EarliestTime is
// derived by comparing versions, not by trusting list position.
func TestProxyClientLookupEarliestTimeUsesSemverNotListOrder(t *testing.T) {
	const earliestTime = "2026-07-21T07:45:05Z"
	const latestTime = "2026-09-02T08:21:59Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v1.3.1","Time":"` + latestTime + `"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			// Shuffled on purpose: not ascending, not descending, not
			// grouped by minor version.
			_, _ = w.Write([]byte("v1.2.1\nv1.3.1\nv1.0.0\nv1.1.0\nv1.0.8\n"))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.info"):
			_, _ = w.Write([]byte(`{"Version":"v1.0.0","Time":"` + earliestTime + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/flooded")

	if status.VersionCount != 5 {
		t.Fatalf("VersionCount = %d, want 5", status.VersionCount)
	}
	wantEarliest, _ := time.Parse(time.RFC3339, earliestTime)
	if !status.EarliestTime.Equal(wantEarliest) {
		t.Errorf("EarliestTime = %v, want v1.0.0's time %v (the semver-lowest tag, not list position)", status.EarliestTime, wantEarliest)
	}
}

func TestProxyClientLookupBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
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

// TestIsMajorVersionBumpOfEstablished reproduces a real false positive
// (run #137): sigs.k8s.io/structured-merge-diff/v7, a dependency of
// kubernetes/kubernetes's own go.mod, has exactly one version published
// within recentWindow (v7.0.0, days old) — the exact "new-and-thin"
// shape — purely because Go's major-version-suffix convention makes a
// version bump a brand-new module path. Its predecessor
// .../structured-merge-diff/v6 has a long publish history on the real
// proxy, confirming this is an established project, not a hallucination.
func TestIsMajorVersionBumpOfEstablished(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/sigs.k8s.io/structured-merge-diff/v6/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v6.4.2","Time":"2020-01-01T00:00:00Z"}`))
		case strings.HasPrefix(r.URL.Path, "/sigs.k8s.io/structured-merge-diff/v6/@v/list"):
			_, _ = w.Write([]byte("v6.0.0\nv6.1.0\nv6.2.0\nv6.3.0\nv6.4.0\nv6.4.1\nv6.4.2\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	if !c.IsMajorVersionBumpOfEstablished("sigs.k8s.io/structured-merge-diff/v7") {
		t.Error("want true: v6 predecessor has an established multi-version history")
	}
	if c.IsMajorVersionBumpOfEstablished("sigs.k8s.io/never-existed/v7") {
		t.Error("want false: v6 predecessor doesn't exist on this server (404s), so no evidence of an established project")
	}
	if c.IsMajorVersionBumpOfEstablished("example.com/no-version-suffix") {
		t.Error("want false: not a versioned path at all, SplitPathVersion returns ok=false")
	}
}

// TestEvaluateModuleStatusSuppressesNewAndThinForMajorVersionBump is the
// end-to-end regression for the same case through the actual finding
// path modslop runs against a go.mod, not just the helper in isolation.
func TestEvaluateModuleStatusSuppressesNewAndThinForMajorVersionBump(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/sigs.k8s.io/structured-merge-diff/v6/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v6.4.2","Time":"2020-01-01T00:00:00Z"}`))
		case strings.HasPrefix(r.URL.Path, "/sigs.k8s.io/structured-merge-diff/v6/@v/list"):
			_, _ = w.Write([]byte("v6.0.0\nv6.1.0\nv6.2.0\nv6.3.0\nv6.4.0\nv6.4.1\nv6.4.2\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := ModuleStatus{Exists: true, VersionCount: 1, LatestTime: time.Now().Add(-24 * time.Hour)}

	findings := evaluateModuleStatus("sigs.k8s.io/structured-merge-diff/v7", "v7.0.0", status, c)
	for _, f := range findings {
		if f.Reason == "new-and-thin" {
			t.Errorf("got new-and-thin finding for an established project's major-version bump: %+v", f)
		}
	}
}
