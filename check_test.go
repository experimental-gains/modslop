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
	// "gin" is short (3 chars, below typoMinNameLen=6), but this is an
	// *exact* base-name match at a different full path, not a typo/near
	// miss — typoMinNameLen's short-string noise problem (see its own doc
	// comment) only ever applies to non-zero edit distance, so it must
	// not suppress this. See TestClosestPopularMatch_ShortExactNameNotGatedByMinLen
	// for the real-world case (github.com/gintool/gin) this guards against
	// regressing back to.
	if match, exact, ok := closestPopularMatch("github.com/gni-gonic/gin", "gin"); !ok {
		t.Fatal("expected an exact-name match for a gin-gonic/gin clone under a different owner, even though \"gin\" is short")
	} else if !exact {
		t.Error("expected exact=true for an identical base name at a different path")
	} else if !strings.Contains(match, "gin-gonic/gin") {
		t.Errorf("expected match to reference gin-gonic/gin, got %q", match)
	}

	// Regression cases for run #30: scanning ~20 real-world go.mod files
	// with the pre-fix thresholds (typoMinNameLen=4, flat typoMaxDistance=2)
	// flagged every one of these as a "high severity" typosquat risk. None
	// of them are typosquats — they're unrelated, legitimate, popular
	// modules that happen to be a couple of edits apart as short strings.
	falsePositives := []struct{ modPath, name string }{
		{"golang.org/x/term", "term"},                 // ~ pterm
		{"github.com/goccy/go-json", "go-json"},       // ~ gjson
		{"go.yaml.in/yaml/v3", "yaml"},                // ~ toml
		{"github.com/sethvargo/go-retry", "go-retry"}, // ~ go-pretty
		{"github.com/subosito/gotenv", "gotenv"},      // ~ godotenv
		{"github.com/tetratelabs/wazero", "wazero"},   // ~ afero
		{"github.com/pb33f/doctor", "doctor"},         // ~ docker
	}
	for _, fp := range falsePositives {
		if match, _, ok := closestPopularMatch(fp.modPath, fp.name); ok {
			t.Errorf("expected no typosquat match for %q, got false positive %q", fp.name, match)
		}
	}

	if match, exact, ok := closestPopularMatch("github.com/sirupsen/logrusx", "logrusx"); !ok {
		t.Fatal("expected a match for logrusx (one edit from logrus)")
	} else if !strings.Contains(match, "logrus") {
		t.Errorf("expected match to reference logrus, got %q", match)
	} else if exact {
		t.Error("logrusx is a one-edit near miss, not an exact match")
	}

	if _, _, ok := closestPopularMatch("github.com/sirupsen/logrus", "logrus"); ok {
		t.Error("exact match on the real module should not be flagged")
	}

	if _, _, ok := closestPopularMatch("github.com/completely/unrelated-project-name", "unrelated-project-name"); ok {
		t.Error("unrelated name should not match anything")
	}

	// The actual gap this run's change closes: a popular module's exact
	// base name, republished verbatim under a different, unestablished
	// owner — not a typo, so the pre-fix code (which required d > 0)
	// missed it entirely. This is the real technique documented in Bae &
	// Yagemann's "Beyond Takedown" (arXiv:2606.26291, 2026): their
	// worked example is portapps/drawio-portable cloned verbatim as
	// anotherteriy/drawio-portable.
	if match, exact, ok := closestPopularMatch("github.com/totallyfakeorg/zerolog", "zerolog"); !ok {
		t.Fatal("expected an exact-name match for an rs/zerolog clone under a different owner")
	} else if !exact {
		t.Error("expected exact=true for an identical base name at a different path")
	} else if !strings.Contains(match, "zerolog") {
		t.Errorf("expected match to reference zerolog, got %q", match)
	}

	// A case-differing clone of a popular module's exact base name (e.g.
	// "Zerolog" instead of "zerolog") is the same impersonation shape as
	// the identical-case clone just above, not a typo: golang.org/x/mod/
	// module.CheckPath accepts uppercase letters in a module path outright
	// (confirmed live), so "github.com/totallyfakeorg/Zerolog" is just as
	// legal and fetchable a module path as the all-lowercase clone — Go's
	// module resolution is case-sensitive (proxy URLs even have a whole
	// "!"-escaping scheme, see escapeModulePath, specifically because two
	// paths differing only in case are two distinct modules). A human (or
	// an LLM) reading go.mod sees an indistinguishable name either way.
	// Before this fix, the exact-match branch below compared pName == name
	// case-sensitively, so a case-differing clone fell through to the
	// Levenshtein near-miss path instead, where case-insensitive
	// Levenshtein("Zerolog", "zerolog") == 0 still produced a match, but
	// mislabeled exact=false — gating it on looksUnestablished (which
	// exempts an untagged module, VersionCount==0) instead of
	// looksUnestablishedForImpersonation (which doesn't). That reopened
	// the identical evasion TestCheckRequirement_ExactNameCloneOfUntaggedPopular
	// closed for same-case clones: an attacker (or a squatted name an LLM
	// hallucinates and someone else registers) just has to vary the case
	// to slip past this tool's own highest-confidence check.
	if match, exact, ok := closestPopularMatch("github.com/totallyfakeorg/Zerolog", "Zerolog"); !ok {
		t.Fatal("expected an exact-name match for a case-differing rs/zerolog clone")
	} else if !exact {
		t.Error("expected exact=true for a case-differing but otherwise identical base name")
	} else if !strings.Contains(match, "zerolog") {
		t.Errorf("expected match to reference zerolog, got %q", match)
	}

	// Regression cases for run #52: scanning 8 large real-world go.mod
	// files (Kubernetes, Grafana, CockroachDB, etcd, Prometheus,
	// Terraform, Hugo, Caddy) found these flagged as "typosquats" of an
	// unrelated popular module purely because they share a generic,
	// conventional trailing segment (errors/protobuf/validation/
	// decimal/common) with it — none are typosquats, they're real,
	// established, unrelated packages. See genericBaseNames.
	genericFalsePositives := []struct{ modPath, name string }{
		{"github.com/olekukonko/errors", "errors"},                                    // ~ x/xerrors
		{"github.com/go-openapi/errors", "errors"},                                    // ~ x/xerrors
		{"github.com/go-errors/errors", "errors"},                                     // ~ x/xerrors
		{"github.com/gogo/protobuf", "protobuf"},                                      // ~ planetscale/vtprotobuf
		{"github.com/Azure/go-autorest/autorest/validation", "validation"},            // ~ go-playground/validator
		{"github.com/quagmt/udecimal", "udecimal"},                                    // ~ shopspring/decimal
		{"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common", "common"}, // ~ labstack/gommon
		// Regression cases for a real-world-testing pass (2026-09) over
		// 18 large popular repos' actual go.mod files: pingcap/tidb's
		// github.com/tikv/pd/client and hashicorp/vault's github.com/
		// jeffchao/backoff are real, established, unrelated modules that
		// each fired name-collision-exact — the highest-severity finding
		// this tool has — purely because "client"/"backoff" are as
		// conventional a trailing package-path segment as "errors" or
		// "common" already are. See genericBaseNames's own comment for
		// the corroborating evidence (moby/moby/client,
		// prometheus-operator's pkg/client, jpillora/backoff,
		// lestrrat-go/backoff/v2) that ruled out coincidence.
		{"github.com/tikv/pd/client", "client"},    // ~ go.etcd.io/etcd/client/v3
		{"github.com/jeffchao/backoff", "backoff"}, // ~ cenkalti/backoff/v4
		// Regression cases surfaced by the exact-name-different-owner
		// scan's own typoMinNameLen fix (see closestPopularMatch's doc
		// comment): removing that length floor from the exact-match
		// branch made these short, conventional trailing segments
		// reachable by it for the first time, exposing the same false-
		// positive shape as "errors"/"client"/"backoff" above, just for
		// *exact* base-name matches instead of near misses. Confirmed
		// scanning the same real-world corpus the length-floor fix itself
		// was verified against: google.golang.org/genproto/googleapis/api,
		// istio.io/api, and sigs.k8s.io/kustomize/api all end in "api" —
		// the conventional trailing segment k8s.io/api (a popularModules
		// entry) also happens to use — purely by convention, in over a
		// dozen large real-world go.mod files; github.com/cncf/xds/go,
		// cloud.google.com/go, and github.com/siddontang/go do the same
		// against github.com/json-iterator/go's own trailing "go"
		// segment; and github.com/influxdata/cron (confirmed via the
		// GitHub API to be a genuinely independent, non-fork project) does
		// it against github.com/robfig/cron's "cron".
		{"google.golang.org/genproto/googleapis/api", "api"}, // ~ k8s.io/api
		{"github.com/cncf/xds/go", "go"},                     // ~ json-iterator/go
		{"github.com/influxdata/cron", "cron"},               // ~ robfig/cron
	}
	for _, fp := range genericFalsePositives {
		if match, _, ok := closestPopularMatch(fp.modPath, fp.name); ok {
			t.Errorf("expected no typosquat match for generic name %q, got false positive %q", fp.name, match)
		}
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
			escaped, _ := escapeModulePath(path)
			if r.URL.Path == "/"+escaped+"/@latest" {
				_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, m.latest, m.when.Format(time.RFC3339))
				return
			}
			if r.URL.Path == "/"+escaped+"/@v/list" {
				_, _ = fmt.Fprint(w, strings.Join(m.versions, "\n"))
				return
			}
			// Backs VersionExists's per-requirement @v/<version>.info
			// check (added for the "version-not-found" finding): any
			// version actually listed in m.versions is a real, existing
			// tag, same as m.latest already is via @latest above — a
			// fakeProxy-based test whose Requirement.Version names one of
			// its own declared versions must not get a spurious
			// version-not-found finding on top of whatever it's actually
			// testing.
			for _, v := range m.versions {
				escapedV, _ := escapeModulePath(v)
				if r.URL.Path == "/"+escaped+"/@v/"+escapedV+".info" {
					_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, v, m.when.Format(time.RFC3339))
					return
				}
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

// TestCheckRequirement_LatestFailsButPinnedVersionResolves is a real,
// live-confirmed regression (2026-09): gravitational/teleport's go.mod
// carries `replace github.com/alecthomas/kingpin/v2 =>
// github.com/gravitational/kingpin/v2 v2.1.11-0.20230515143221-4ec6b70ecd33`.
// proxy.golang.org's github.com/gravitational/kingpin/v2/@latest 404s
// ("invalid version: missing .../v2/go.mod at revision v2.1.10" — the
// semver-highest tag in that major-version line predates the module ever
// adding a v2 go.mod), but the exact pinned pseudo-version the replace
// names resolves cleanly on the proxy, and `go mod download`/`go list -m
// all` on a scratch module with this exact require+replace pair succeed
// outright. Before the fix, evaluateModuleStatus only ever looked at
// status.Exists (decided purely by @latest) here, so this real, currently
// -building dependency was reported as a high-severity "not-found" —
// indistinguishable from an actually-hallucinated import.
func TestCheckRequirement_LatestFailsButPinnedVersionResolves(t *testing.T) {
	const (
		modPath = "github.com/gravitational/kingpin/v2"
		pinned  = "v2.1.11-0.20230515143221-4ec6b70ecd33"
	)
	escaped, _ := escapeModulePath(modPath)
	escapedPinned, _ := escapeModulePath(pinned)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + escaped + "/@latest":
			// Mirrors the real proxy's response exactly: 404, even though
			// the module and the specific pinned version below are both
			// completely real.
			w.WriteHeader(http.StatusNotFound)
		case "/" + escaped + "/@v/list":
			// The real proxy also returns 200 with an empty body here —
			// no tagged releases exist in this major-version line at all,
			// only pseudo-versions used via replace.
		case "/" + escaped + "/@v/" + escapedPinned + ".info":
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2023-05-15T14:32:21Z"}`, pinned)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: modPath, Version: pinned}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a module whose pinned version resolves despite @latest 404ing, got %+v", findings)
	}
}

// TestCheckRequirement_Blocklisted is the CheckRequirement-level
// counterpart to TestProxyClientLookupBlocklistedMalicious in
// proxy_test.go: a module the proxy has flagged as malicious must
// produce a high-severity finding, not silence.
func TestCheckRequirement_Blocklisted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("SECURITY ERROR\nThe module proxy considers this module to be malicious\nand will not serve it."))
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: "github.com/shopsprint/decimal"}, proxy)
	if len(findings) != 1 || findings[0].Reason != "proxy-blocklisted-malicious" || findings[0].Severity != SeverityHigh {
		t.Fatalf("expected one high-severity proxy-blocklisted-malicious finding, got %+v", findings)
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

// TestCheckRequirement_VersionNotFound is the CheckRequirement-level
// regression for TestProxyClientVersionExists: a real, established,
// multi-version module (old enough and populous enough to clear both
// new-and-thin and version-flooded on its own) still must be flagged
// when the specific pinned version was never published — exactly the
// gorilla/mux v3.5.0 case confirmed live against the real proxy. Also
// confirms the module-level freshness heuristics are suppressed rather
// than piling a confusing second finding on top of the much clearer
// version-not-found one.
func TestCheckRequirement_VersionNotFound(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/gorilla/mux": {
			versions: []string{"v1.0.0", "v1.6.1", "v1.8.1"},
			latest:   "v1.8.1",
			when:     time.Now().Add(-800 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/gorilla/mux", Version: "v3.5.0"}, proxy)
	if len(findings) != 1 || findings[0].Reason != "version-not-found" || findings[0].Severity != SeverityHigh {
		t.Fatalf("expected one high-severity version-not-found finding, got %+v", findings)
	}
}

// TestCheckRequirement_VersionNotFoundUnknownOnProxyError confirms a
// transient proxy error while checking the exact version never gets
// reported as version-not-found — same "say nothing on ambiguity"
// discipline ModuleStatus.Unknown already applies everywhere else.
func TestCheckRequirement_VersionNotFoundUnknownOnProxyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprint(w, `{"Version":"v1.8.1","Time":"2023-10-18T11:23:00Z"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprint(w, "v1.0.0\nv1.6.1\nv1.8.1")
		case strings.HasSuffix(r.URL.Path, "/@v/v3.5.0.info"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: "github.com/gorilla/mux", Version: "v3.5.0"}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected no findings on an ambiguous proxy error, got %+v", findings)
	}
}

// TestCheckRequirement_VersionFlooded is a regression test for a real
// incident (2026-09, disclosed alongside the Graphalgo Terraform/npm
// campaign): gocommunity.io/orderedbtree published 16 versions over
// about six weeks on the live proxy, specifically clearing the
// new-and-thin check's "only one version" gate while still being brand
// new. fakeProxy doesn't serve per-version .info, so this uses a custom
// server (matching proxy_test.go's pattern) to give each version a real
// timestamp.
func TestCheckRequirement_VersionFlooded(t *testing.T) {
	const oldest = "2026-07-21T07:45:05Z"
	const newest = "2026-09-02T08:21:59Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprintf(w, `{"Version":"v1.3.1","Time":%q}`, newest)
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprint(w, "v1.3.1\nv1.0.0\nv1.2.0")
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.info"):
			_, _ = fmt.Fprintf(w, `{"Version":"v1.0.0","Time":%q}`, oldest)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: "example.com/flooded"}, proxy)
	if len(findings) != 1 || findings[0].Reason != "version-flooded" || findings[0].Severity != SeverityWarn {
		t.Fatalf("expected one warn-severity version-flooded finding, got %+v", findings)
	}
}

// TestCheckRequirement_ManyOldVersionsClean is the negative counterpart to
// TestCheckRequirement_VersionFlooded: a module with several versions
// whose *oldest* tag is well outside floodedHistoryWindow must not be
// flagged, even though it superficially looks similar (multiple
// versions, most published somewhat recently as an actively-maintained
// project keeps shipping). Uses a real EarliestTime (not the zero value
// a missing .info endpoint would produce) so this can't pass by accident
// the way it would if EarliestTime.IsZero() were the only thing guarding
// the finding.
func TestCheckRequirement_ManyOldVersionsClean(t *testing.T) {
	oldest := time.Now().Add(-400 * 24 * time.Hour).Format(time.RFC3339)
	newest := time.Now().Add(-2 * 24 * time.Hour).Format(time.RFC3339)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprintf(w, `{"Version":"v2.0.0","Time":%q}`, newest)
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprint(w, "v2.0.0\nv1.0.0\nv1.1.0")
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.info"):
			_, _ = fmt.Fprintf(w, `{"Version":"v1.0.0","Time":%q}`, oldest)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: "example.com/established"}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a module whose oldest version is 400 days old, got %+v", findings)
	}
}

// TestCheckRequirement_Retracted is modeled on a real, live-verified case
// (2026-09): github.com/mattn/go-sqlite3's go.mod (at its latest tag,
// v1.14.52) retracts [v2.0.0+incompatible, v2.0.7+incompatible] with the
// rationale "Accidental; no major changes or features." Confirmed live
// that requiring v2.0.3+incompatible resolves and fetches cleanly through
// proxy.golang.org with no warning anywhere — before the retraction check
// existed, modslop reported this go.mod as "nothing flagged" too, missing
// the one signal (the maintainer's own go.mod) that says "don't use this
// version." The version being retracted (v2.0.3+incompatible) has no
// go.mod of its own — it predates Go modules — so its own .mod fetch
// returns a bare module line with no retract directive; the retraction
// only shows up in @latest's go.mod (v1.14.52's), which is why
// ProxyClient.Lookup fetches that one unconditionally rather than the
// checked version's own.
func TestCheckRequirement_Retracted(t *testing.T) {
	const module = "github.com/mattn/go-sqlite3"
	const version = "v2.0.3+incompatible"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprint(w, `{"Version":"v1.14.52","Time":"2026-06-05T00:00:00Z"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.14.52.mod"):
			_, _ = fmt.Fprint(w, "module "+module+"\n\ngo 1.21\n\nretract (\n\t[v2.0.0+incompatible, v2.0.7+incompatible] // Accidental; no major changes or features.\n)\n")
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprintf(w, "%s\nv1.14.52\n", version)
		case strings.HasSuffix(r.URL.Path, "/@v/"+version+".info"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2020-01-01T00:00:00Z"}`, version)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: module, Version: version}, proxy)
	if len(findings) != 1 || findings[0].Reason != "retracted" || findings[0].Severity != SeverityHigh {
		t.Fatalf("expected one high-severity retracted finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, "Accidental; no major changes or features.") {
		t.Errorf("expected the retraction rationale to be quoted in the detail, got: %s", findings[0].Detail)
	}
}

// TestCheckRequirement_RetractedRangeDoesNotCoverVersion is the negative
// counterpart: the same real go-sqlite3 go.mod, checked against a version
// (its own latest, v1.14.52) outside the retracted range, must produce no
// finding — a go.mod carrying *any* retract directive at all is the
// common case for a module with retractions, so this guards against a
// naive "go.mod has a retract block" check that ignores the version
// interval.
func TestCheckRequirement_RetractedRangeDoesNotCoverVersion(t *testing.T) {
	const module = "github.com/mattn/go-sqlite3"
	const version = "v1.14.52"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2026-06-05T00:00:00Z"}`, version)
		case strings.HasSuffix(r.URL.Path, "/@v/"+version+".mod"):
			_, _ = fmt.Fprint(w, "module "+module+"\n\ngo 1.21\n\nretract (\n\t[v2.0.0+incompatible, v2.0.7+incompatible] // Accidental; no major changes or features.\n)\n")
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprintf(w, "%s\n", version)
		case strings.HasSuffix(r.URL.Path, "/@v/"+version+".info"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2026-06-05T00:00:00Z"}`, version)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: module, Version: version}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected no findings (retracted range doesn't cover this version), got %+v", findings)
	}
}

// TestCheckRequirement_Deprecated is modeled on a real, live-verified case
// (2026-09-26): github.com/golang/protobuf's go.mod (at its latest tag,
// v1.5.4) carries `// Deprecated: Use the "google.golang.org/protobuf"
// module instead.` on its module directive. Confirmed live that a plain
// `go get` of this module still succeeds — deprecation is advisory only,
// same as retraction — but prints that exact warning first, a signal
// modslop had no awareness of at all before this check existed.
func TestCheckRequirement_Deprecated(t *testing.T) {
	const module = "github.com/golang/protobuf"
	const version = "v1.5.4"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2024-03-06T06:45:40Z"}`, version)
		case strings.HasSuffix(r.URL.Path, "/@v/"+version+".mod"):
			_, _ = fmt.Fprint(w, "// Deprecated: Use the \"google.golang.org/protobuf\" module instead.\nmodule "+module+"\n\ngo 1.17\n")
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprintf(w, "%s\n", version)
		case strings.HasSuffix(r.URL.Path, "/@v/"+version+".info"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2024-03-06T06:45:40Z"}`, version)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: module, Version: version}, proxy)
	if len(findings) != 1 || findings[0].Reason != "deprecated" || findings[0].Severity != SeverityWarn {
		t.Fatalf("expected one warn-severity deprecated finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, `Use the \"google.golang.org/protobuf\" module instead.`) {
		t.Errorf("expected the deprecation message to be quoted in the detail, got: %s", findings[0].Detail)
	}
}

// TestCheckRequirement_DeprecatedPastNotice confirms deprecation is read
// from the module's latest go.mod, not the checked version's own — mirrors
// TestCheckRequirement_RetractedVersionPastLatest's reasoning for
// retraction. Confirmed live: github.com/golang/protobuf@v1.3.0's own
// go.mod predates the deprecation comment entirely, yet `go get
// github.com/golang/protobuf@v1.3.0` still prints the deprecation warning.
func TestCheckRequirement_DeprecatedPastNotice(t *testing.T) {
	const module = "github.com/golang/protobuf"
	const version = "v1.3.0"
	const latest = "v1.5.4"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2024-03-06T06:45:40Z"}`, latest)
		case strings.HasSuffix(r.URL.Path, "/@v/"+latest+".mod"):
			_, _ = fmt.Fprint(w, "// Deprecated: Use the \"google.golang.org/protobuf\" module instead.\nmodule "+module+"\n\ngo 1.17\n")
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprintf(w, "%s\n%s\n", version, latest)
		case strings.HasSuffix(r.URL.Path, "/@v/"+version+".info"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2018-01-01T00:00:00Z"}`, version)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: module, Version: version}, proxy)
	if len(findings) != 1 || findings[0].Reason != "deprecated" {
		t.Fatalf("expected one deprecated finding (notice lives on latest's go.mod, not this old version's), got %+v", findings)
	}
}

// TestCheckRequirement_RetractedVersionPastLatest is the end-to-end
// counterpart of TestProxyClientLookupFetchesRetractingVersionPastLatest:
// reproduces github.com/jayconrod/retract (the Go team's own canonical
// self-retraction example) at the CheckRequirement level, confirming the
// "retracted" finding actually surfaces through the full Lookup+
// evaluateModuleStatus path, not just in LatestModBody's own value.
func TestCheckRequirement_RetractedVersionPastLatest(t *testing.T) {
	const module = "github.com/jayconrod/retract"
	const version = "v1.0.0"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprint(w, `{"Version":"v0.9.9","Time":"2021-01-26T16:46:49Z"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v0.9.9.mod"):
			_, _ = fmt.Fprint(w, "module "+module+"\n\ngo 1.16\n")
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.1.mod"):
			_, _ = fmt.Fprint(w, "module "+module+"\n\ngo 1.16\n\nretract (\n\tv1.0.0 // Published accidentally.\n\tv1.0.1 // For retractions only.\n)\n")
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprint(w, "v1.0.0\nv0.9.9\nv1.0.1\n")
		case strings.HasSuffix(r.URL.Path, "/@v/"+version+".info"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":"2021-01-01T00:00:00Z"}`, version)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	findings := CheckRequirement(Requirement{Path: module, Version: version}, proxy)
	if len(findings) != 1 || findings[0].Reason != "retracted" || findings[0].Severity != SeverityHigh {
		t.Fatalf("expected one high-severity retracted finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, "Published accidentally.") {
		t.Errorf("expected the retraction rationale to be quoted in the detail, got: %s", findings[0].Detail)
	}
}

func TestCheckAll_LocalReplacementSkipped(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "micron-parser-go", Version: "v0.0.0"}}
	reps := []Replacement{{Old: "micron-parser-go", New: "./third_party/micron"}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a locally-replaced requirement to produce no findings, got %+v", findings)
	}
}

func TestCheckAll_BareDotDotReplacementSkipped(t *testing.T) {
	// Regression test: `replace foo => ..` (no trailing slash) is a real,
	// valid go.mod construct that `go build` resolves entirely off disk —
	// before the IsLocal fix, this fell through to the "another module"
	// branch and sent the literal string ".." to the proxy, producing a
	// guaranteed high-severity "not-found" false positive (see
	// TestReplacementIsLocalBareDotDot in gomod_test.go).
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "vendorbar", Version: "v0.0.0"}}
	reps := []Replacement{{Old: "vendorbar", New: ".."}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a bare \"..\" local replacement to produce no findings, got %+v", findings)
	}
}

// TestCheckAll_GoWorkOnlyLocalReplaceSuppressesRequirementCheck is the
// end-to-end regression for the false positive goWorkReplaces/
// mergeReplaces fix: a go.mod require with no replace of its own,
// satisfied only via a go.work-level replace to a local directory, must
// not reach the network check — same as an ordinary go.mod-level local
// replace (TestCheckAll_LocalReplacementSkipped above) — because the
// real go toolchain never fetches it from the network in workspace mode
// (confirmed live: `go list -m all` inside a workspace member resolves
// such a require straight to the go.work replace's local target). Before
// this fix, main.go only ever passed CheckAll the go.mod's own replaces,
// so this exact requirement would have been checked against the proxy
// and flagged "not-found".
func TestCheckAll_GoWorkOnlyLocalReplaceSuppressesRequirementCheck(t *testing.T) {
	proxy := fakeProxy(t, nil) // proxy knows nothing about this path — a bare check would 404
	reqs := []Requirement{{Path: "example.com/internal-in-progress", Version: "v0.0.0"}}
	gomodReps := []Replacement{} // go.mod itself declares no replace for this path
	goworkReps := []Replacement{{Old: "example.com/internal-in-progress", New: "../local-workspace-member"}}
	reps := mergeReplaces(gomodReps, goworkReps)

	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a go.work-only local replacement to produce no findings, got %+v", findings)
	}
}

// TestCheckAll_GoWorkVersionSpecificReplaceDoesNotShadowUnrelatedGoModReplace
// is the end-to-end regression for the mergeReplaces precedence bug: a
// go.work replace that's specific to one version of a module must not
// blank out a go.mod-level replace for a *different* version (or a
// version-agnostic one) of the same module. Confirmed live against the
// real go toolchain (`go list -m all`/`go run` in a scratch workspace):
// go still resolves the required version through the go.mod-level
// replace in this exact shape, since go.work's own replace never applies
// to it. Before this fix, mergeReplaces dropped every go.mod-level entry
// for a path the instant go.work mentioned that path at all — regardless
// of whether go.work's entry actually applied to the required version —
// so this exact local dependency would have been sent to the proxy and
// flagged "not-found".
func TestCheckAll_GoWorkVersionSpecificReplaceDoesNotShadowUnrelatedGoModReplace(t *testing.T) {
	proxy := fakeProxy(t, nil) // proxy knows nothing about this path — a bare check would 404
	reqs := []Requirement{{Path: "example.com/foo", Version: "v1.0.0"}}
	gomodReps := []Replacement{{Old: "example.com/foo", OldVersion: "v1.0.0", New: "../v1fork"}}
	// go.work only replaces a different, non-required version of the
	// same module — it must not apply here at all.
	goworkReps := []Replacement{{Old: "example.com/foo", OldVersion: "v1.5.0", New: "../v2fork"}}
	reps := mergeReplaces(gomodReps, goworkReps)

	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected the unrelated go.work replace to leave the go.mod-level replace in effect, got %+v", findings)
	}
}

func TestCheckAll_ModuleReplacementChecksNewPath(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/real-org/micron-parser-go": {
			versions: []string{"v1.0.0", "v1.2.0"},
			latest:   "v1.2.0",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "micron-parser-go", Version: "v0.0.0"}}
	reps := []Replacement{{Old: "micron-parser-go", New: "github.com/real-org/micron-parser-go", NewVersion: "v1.2.0"}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected the replacement target to resolve cleanly, got %+v", findings)
	}
}

// TestCheckAll_ReplacementUsesNewSideVersionForRetraction is a regression
// test for a gap in the replace-resolution plumbing that the retraction
// check (check.go, retract.go) exposed: a remote-target replace directive
// always pins an exact version on its new side (go.dev/ref/mod#go-mod-
// file-replace requires it for anything that isn't a local filesystem
// path), but CheckAll used to discard it and keep checking under the
// *original* requirement's version — which names a version of a
// completely different module once replaced. Here the original
// requirement names an old, unretracted version of one module; the
// replace repoints it at github.com/mattn/go-sqlite3 pinned to
// v2.0.3+incompatible, a real retracted version (see
// TestCheckRequirement_Retracted). Only checking against the replace's
// own new-side version catches this; checking against the stale original
// version would silently miss it.
func TestCheckAll_ReplacementUsesNewSideVersionForRetraction(t *testing.T) {
	const module = "github.com/mattn/go-sqlite3"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprint(w, `{"Version":"v1.14.52","Time":"2026-06-05T00:00:00Z"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.14.52.mod"):
			_, _ = fmt.Fprint(w, "module "+module+"\n\ngo 1.21\n\nretract (\n\t[v2.0.0+incompatible, v2.0.7+incompatible] // Accidental; no major changes or features.\n)\n")
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = fmt.Fprint(w, "v2.0.3+incompatible\nv1.14.52\n")
		case strings.HasSuffix(r.URL.Path, "/@v/v2.0.3+incompatible.info"):
			_, _ = fmt.Fprint(w, `{"Version":"v2.0.3+incompatible","Time":"2020-01-01T00:00:00Z"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	reqs := []Requirement{{Path: "example.com/old-fork", Version: "v0.1.0"}}
	reps := []Replacement{{Old: "example.com/old-fork", New: module, NewVersion: "v2.0.3+incompatible"}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 1 || findings[0].Reason != "retracted" {
		t.Fatalf("expected the replace's new-side version (a real retracted version) to be flagged, got %+v", findings)
	}
}

// TestCheckAll_ReplacementOfDeclaredPopularModuleNotFlaggedAsImpersonation
// is the real-world-testing regression this run's fix is for: confirmed
// live against two actual, current go.mod files. cockroachdb/cockroach
// requires github.com/prometheus/client_golang v1.16.0 and replaces it
// with github.com/cockroachdb/client_golang (their own patched fork —
// the replace directive's own adjacent comment reads "See
// https://github.com/cockroachdb/client_golang/pulls for merged
// changes"), and thanos-io/thanos requires github.com/bradfitz/gomemcache
// and replaces it with github.com/themihai/gomemcache (commented "Using
// a 3rd-party branch for custom dialer" with a link to the unmerged
// upstream PR). Neither fork is tagged on the proxy (VersionCount==0),
// so before this fix both fired name-collision-exact — the tool's
// highest-severity finding, worded "verify this isn't a malicious clone
// before trusting it" — against two ordinary, documented vendor-fork
// overrides. This test reproduces the shape directly (a require of a
// real popularModules entry, replaced by a same-base-name, different-
// owner, never-tagged fork) rather than against the live proxy, so it
// stays deterministic; the cockroachdb/thanos cases above were confirmed
// against the real, live proxy.golang.org data during development.
func TestCheckAll_ReplacementOfDeclaredPopularModuleNotFlaggedAsImpersonation(t *testing.T) {
	const fork = "github.com/cockroachdb/client_golang"
	const pseudoVersion = "v0.0.0-20250124161916-2d4b7d300341"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, pseudoVersion, time.Now().Add(-1*time.Hour).Format(time.RFC3339))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			// Never tagged, like the real fork — a pseudo-version never
			// appears in @v/list regardless (see VersionExists's own doc
			// comment), only @latest and the version-specific .info below.
		case strings.HasSuffix(r.URL.Path, "/@v/"+pseudoVersion+".info"):
			_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, pseudoVersion, time.Now().Add(-1*time.Hour).Format(time.RFC3339))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	reqs := []Requirement{{Path: "github.com/prometheus/client_golang", Version: "v1.16.0"}}
	reps := []Replacement{{Old: "github.com/prometheus/client_golang", New: fork, NewVersion: pseudoVersion}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a replace of an already-declared popular module to produce no findings, got %+v", findings)
	}
}

// TestCheckAll_ExactNameCollisionWithoutReplaceStillFlagged is
// TestCheckAll_ReplacementOfDeclaredPopularModuleNotFlaggedAsImpersonation's
// adjacent-case counterpart: the exact same fork path, but named directly
// by a plain require with no replace involved at all — the actual
// impersonation shape (an attacker-controlled path standing in for the
// genuine module with nothing else in the go.mod naming the real one)
// must still fire name-collision-exact. Confirms the fix is scoped to
// "reached via a replace of an already-declared popular module," not a
// blanket exemption for the fork's path or name.
func TestCheckAll_ExactNameCollisionWithoutReplaceStillFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/cockroachdb/client_golang": {
			versions: nil,
			latest:   "v0.0.0-20250124161916-2d4b7d300341",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "github.com/cockroachdb/client_golang", Version: "v0.0.0-20250124161916-2d4b7d300341"}}
	findings := CheckAll(reqs, nil, nil, nil, "", proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-exact"] {
		t.Fatalf("expected a plain require of the same fork path (no replace) to still surface name-collision-exact, got %+v", findings)
	}
}

// TestCheckAll_DirectRequireOfForkAlongsidePopularNotFlagged is the
// real-world-testing regression this run's fix is for, the direct-require
// counterpart to TestCheckAll_ReplacementOfDeclaredPopularModuleNotFlaggedAsImpersonation:
// confirmed live, 2026-09, against grafana/grafana's actual go.mod, which
// requires both github.com/bradfitz/gomemcache (a curated popularModules
// entry) *and* github.com/grafana/gomemcache directly — two ordinary
// require lines, no replace directive joining them at all. Confirmed via
// the GitHub API that github.com/grafana/gomemcache is literally
// `"fork": true, "source": "bradfitz/gomemcache"`, described "Go
// Memcached client library - forked and improved" — a real, deliberate
// fork, not an impersonation attempt. It has never been tagged on the
// real proxy.golang.org (VersionCount==0), so it fires
// looksUnestablishedForImpersonation. Before this fix, CheckAll had no
// way to recognize this shape at all — suppressForkOfDeclaredPopular only
// ever looked at replacedFrom, which is "" for a plain require with no
// replace — so this produced a false-positive name-collision-exact, the
// tool's highest-severity finding, against a real dependency of a major,
// actively-maintained open-source project.
func TestCheckAll_DirectRequireOfForkAlongsidePopularNotFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/bradfitz/gomemcache": {
			versions: []string{"v0.0.1", "v0.0.2"},
			latest:   "v0.0.2",
			when:     time.Now().Add(-5 * 365 * 24 * time.Hour),
		},
		"github.com/grafana/gomemcache": {
			versions: nil,
			latest:   "v0.0.0-20260728143316-9448343bd654",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	reqs := []Requirement{
		{Path: "github.com/bradfitz/gomemcache", Version: "v0.0.2"},
		{Path: "github.com/grafana/gomemcache", Version: "v0.0.0-20260728143316-9448343bd654"},
	}
	findings := CheckAll(reqs, nil, nil, nil, "", proxy)
	for _, f := range findings {
		if f.Module == "github.com/grafana/gomemcache" && f.Reason == "name-collision-exact" {
			t.Fatalf("expected a fork required directly alongside its already-declared popular original not to be flagged, got %+v", findings)
		}
	}
}

// TestCheckAll_ToolDirectiveForkAlongsideDeclaredPopularNotFlagged is the
// sibling regression test to
// TestCheckAll_DirectRequireOfForkAlongsidePopularNotFlagged, one call site
// over: the exact same legitimate-fork shape (github.com/grafana/
// gomemcache, a real, disclosed `"fork":true` fork of the popular
// github.com/bradfitz/gomemcache, confirmed live via the GitHub API in run
// #474) must not be flagged name-collision-exact when it's reached only
// through an uncovered `tool` directive instead of a direct require line —
// live-reproduced before this fix with a real go.mod
// (`require github.com/bradfitz/gomemcache ...` + `tool
// github.com/grafana/gomemcache/cmd/x`, no require/replace for the fork at
// all) run against the real proxy.golang.org and modslop's own built
// binary: it reported name-collision-exact for github.com/grafana/
// gomemcache despite bradfitz/gomemcache being directly declared —
// CheckAll appended CheckTools's findings raw, without ever passing them
// through suppressForkOfDeclaredPopular the way every other resolved
// requirement's findings already were.
func TestCheckAll_ToolDirectiveForkAlongsideDeclaredPopularNotFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/bradfitz/gomemcache": {
			versions: []string{"v0.0.1", "v0.0.2"},
			latest:   "v0.0.2",
			when:     time.Now().Add(-5 * 365 * 24 * time.Hour),
		},
		"github.com/grafana/gomemcache": {
			versions: nil,
			latest:   "v0.0.0-20260728143316-9448343bd654",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "github.com/bradfitz/gomemcache", Version: "v0.0.2"}}
	tools := []string{"github.com/grafana/gomemcache/cmd/x"}
	findings := CheckAll(reqs, nil, tools, nil, "", proxy)
	for _, f := range findings {
		if f.Module == "github.com/grafana/gomemcache" && f.Reason == "name-collision-exact" {
			t.Fatalf("expected a fork reached only via an uncovered tool directive, with its popular original already declared directly, not to be flagged, got %+v", findings)
		}
	}
}

// TestCheckAll_ReplacementOfNonPopularOldStillFlagged confirms the
// exemption only fires when the replace's Old side is *itself* a curated
// popularModules entry: here Old is an ordinary, non-popular module that
// merely happens to share a base name with one, so the fork on New's side
// is not "standing in for an already-declared well-known module" at all —
// closestPopularMatch's match for New (github.com/prometheus/client_golang)
// never equals Old (example.com/mycompany/client_golang), so no
// suppression applies and the exact-name collision on New must still be
// flagged.
func TestCheckAll_ReplacementOfNonPopularOldStillFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/attacker/client_golang": {
			versions: nil,
			latest:   "v0.0.0-20260925120000-abcdef123456",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "example.com/mycompany/client_golang", Version: "v0.1.0"}}
	reps := []Replacement{{Old: "example.com/mycompany/client_golang", New: "github.com/attacker/client_golang", NewVersion: "v0.0.0-20260925120000-abcdef123456"}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-exact"] {
		t.Fatalf("expected a replace whose Old side isn't a popular module to still surface name-collision-exact on the New side, got %+v", findings)
	}
}

// TestCheckAll_OrphanReplaceOfPopularModuleStillFlagged confirms the
// exemption doesn't extend to orphanReplacementTargets: when Old is a
// popular module but no require line in the go.mod covers it at all (an
// orphan replace — see orphanReplacementTargets), there's no "the go.mod
// already, separately names the real module" evidence to lean on, since
// the replace directive is the only place Old's name appears anywhere.
// replacedFrom is always "" for an orphan target (see CheckAll), so
// suppressForkOfDeclaredPopular must not suppress this.
func TestCheckAll_OrphanReplaceOfPopularModuleStillFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/cockroachdb/client_golang": {
			versions: nil,
			latest:   "v0.0.0-20250124161916-2d4b7d300341",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	// No require for github.com/prometheus/client_golang at all — the
	// replace is orphaned.
	var reqs []Requirement
	reps := []Replacement{{Old: "github.com/prometheus/client_golang", New: "github.com/cockroachdb/client_golang", NewVersion: "v0.0.0-20250124161916-2d4b7d300341"}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-exact"] {
		t.Fatalf("expected an orphan replace of a popular module to still surface name-collision-exact on the New side, got %+v", findings)
	}
}

// TestCheckAll_ReplacementNearMissOfDeclaredPopularStillFlagged confirms
// suppressForkOfDeclaredPopular is scoped to the exact-name-collision
// reason only: a replace's New side that's merely a *near miss* (not an
// exact base-name match) of the same popular module Old declares must
// still surface name-collision-risk. Old being a popularModules entry
// only explains away an exact-name fork (New deliberately kept the same
// name under a new owner) — it says nothing about a New side that's
// close-but-not-identical, which is exactly as plausible a typo/hallucination
// as any other near-miss.
func TestCheckAll_ReplacementNearMissOfDeclaredPopularStillFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/someone/client_golan": {
			versions: []string{"v0.1.0"},
			latest:   "v0.1.0",
			when:     time.Now().Add(-2 * 24 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "github.com/prometheus/client_golang", Version: "v1.16.0"}}
	reps := []Replacement{{Old: "github.com/prometheus/client_golang", New: "github.com/someone/client_golan", NewVersion: "v0.1.0"}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-risk"] {
		t.Fatalf("expected a near-miss replacement of a declared popular module to still surface name-collision-risk, got %+v", findings)
	}
	if reasons["name-collision-exact"] {
		t.Fatalf("near-miss case should not also report the exact reason, got %+v", findings)
	}
}

// TestOrphanReplacementTargets exercises orphanReplacementTargets directly
// (table-driven, no network): the join logic that decides which replace
// directives fall outside the normal require-keyed check.
func TestOrphanReplacementTargets(t *testing.T) {
	reqs := []Requirement{{Path: "example.com/direct-dep", Version: "v1.0.0"}}

	tests := []struct {
		name string
		reps []Replacement
		want []Requirement
	}{
		{
			name: "covered replace is not orphaned",
			reps: []Replacement{{Old: "example.com/direct-dep", New: "github.com/real-org/direct-dep", NewVersion: "v1.0.0"}},
			want: nil,
		},
		{
			name: "orphan remote replace is returned",
			reps: []Replacement{{Old: "golang.org/x/sync", New: "github.com/totallyfakeorg/sync-clone", NewVersion: "v0.0.1"}},
			want: []Requirement{{Path: "github.com/totallyfakeorg/sync-clone", Version: "v0.0.1"}},
		},
		{
			name: "orphan local replace is skipped -- nothing is fetched over the network for it",
			reps: []Replacement{{Old: "golang.org/x/sync", New: "../local-fork"}},
			want: nil,
		},
		{
			name: "duplicate New+NewVersion across orphan entries is deduped",
			reps: []Replacement{
				{Old: "golang.org/x/sync", New: "github.com/totallyfakeorg/sync-clone", NewVersion: "v0.0.1"},
				{Old: "golang.org/x/text", New: "github.com/totallyfakeorg/sync-clone", NewVersion: "v0.0.1"},
			},
			want: []Requirement{{Path: "github.com/totallyfakeorg/sync-clone", Version: "v0.0.1"}},
		},
		{
			name: "distinct New targets for the same orphan Old are both returned -- the real version pulled in transitively is unknown",
			reps: []Replacement{
				{Old: "golang.org/x/sync", OldVersion: "v0.1.0", New: "github.com/totallyfakeorg/sync-clone-a", NewVersion: "v1.0.0"},
				{Old: "golang.org/x/sync", OldVersion: "v0.2.0", New: "github.com/totallyfakeorg/sync-clone-b", NewVersion: "v1.0.0"},
			},
			want: []Requirement{
				{Path: "github.com/totallyfakeorg/sync-clone-a", Version: "v1.0.0"},
				{Path: "github.com/totallyfakeorg/sync-clone-b", Version: "v1.0.0"},
			},
		},
		{
			// Replace directives don't chain -- see orphanReplacementTargets'
			// own doc comment for the live verification. rsc.io/quote here is
			// only ever the New side of the first replace (via
			// example.com/direct-dep, which is declared and so already
			// checked through the ordinary require+replace path) -- it is
			// never itself independently required, so the second replace
			// (rsc.io/quote => the fake module) never fires in real go and
			// must not be treated as an orphan case here.
			name: "a replace whose Old is only another replace's New target is not an orphan -- replace directives don't chain",
			reps: []Replacement{
				{Old: "example.com/direct-dep", New: "rsc.io/quote", NewVersion: "v1.5.2"},
				{Old: "rsc.io/quote", New: "github.com/totallyfakeorg/quote-clone", NewVersion: "v1.0.0"},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orphanReplacementTargets(reqs, tt.reps)
			if len(got) != len(tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("entry %d: got %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestCheckAll_OrphanReplaceOfUndeclaredTransitiveDependencyIsChecked is the
// end-to-end regression for the real gap orphanReplacementTargets closes: a
// `replace` directive for a module this go.mod never names in a `require`
// line at all.
//
// Confirmed live against the real go toolchain with a three-module scratch
// chain (example.com/top requires only example.com/mid; example.com/mid
// requires example.com/leaf; top's own go.mod carries a bare `replace
// example.com/leaf => ../leaf-fork` with NO `require example.com/leaf` line
// anywhere in it): both `go run` and `go list -m all`, run inside top,
// resolve example.com/leaf straight to the fork, and `go mod tidy` doesn't
// add a require line for it either — real go never needed one, since
// example.com/leaf is only ever a transitive dependency of the module top
// actually requires (example.com/mid).
//
// Before orphanReplacementTargets existed, CheckAll only ever applied a
// replace whose Old path matched something already in reqs — this exact
// shape (a replace naming a module with no covering require) was parsed by
// ParseGoMod and then silently discarded, so a malicious or hallucinated
// New-side target hiding behind an override of an undeclared transitive
// dependency produced zero findings, no matter how obviously bad it was.
// Here golang.org/x/sync (never mentioned by a `require` line) is
// "replaced" with a path the fake proxy has never heard of at all — the
// simplest, sharpest way to prove the target is actually being checked now.
func TestCheckAll_OrphanReplaceOfUndeclaredTransitiveDependencyIsChecked(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"example.com/direct-dep": {
			versions: []string{"v1.0.0"},
			latest:   "v1.0.0",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "example.com/direct-dep", Version: "v1.0.0"}}
	// golang.org/x/sync never appears in reqs -- it's only a stand-in for a
	// module pulled in transitively by example.com/direct-dep, the same
	// shape as the leaf module in the live-verified scratch chain above.
	reps := []Replacement{{Old: "golang.org/x/sync", New: "github.com/totallyfakeorg/sync-clone", NewVersion: "v0.0.1"}}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 1 || findings[0].Reason != "not-found" || findings[0].Module != "github.com/totallyfakeorg/sync-clone" {
		t.Fatalf("expected a not-found finding on the orphan replace's target, got %+v", findings)
	}
}

// TestCheckAll_ChainedReplaceTargetIsNotChecked is the end-to-end
// regression for the chaining fix in orphanReplacementTargets: a replace
// directive whose Old path is only the New side of a different replace in
// the same go.mod must not be treated as an orphan and checked, because
// (verified live against the real go toolchain, see orphanReplacementTargets'
// own doc comment) replace directives never chain -- the second replace
// here is dead code a real `go build` never applies. Before the fix, this
// exact shape produced a spurious "not-found" finding on a module real go
// never fetches at all; the required module's actual clean replacement
// target (micron-parser-go, resolved through the ordinary require+replace
// path, one hop only) must still be the only thing checked.
func TestCheckAll_ChainedReplaceTargetIsNotChecked(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/real-org/micron-parser-go": {
			versions: []string{"v1.0.0", "v1.2.0"},
			latest:   "v1.2.0",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "example.com/placeholder-oldtool", Version: "v0.0.0"}}
	reps := []Replacement{
		{Old: "example.com/placeholder-oldtool", New: "github.com/real-org/micron-parser-go", NewVersion: "v1.2.0"},
		// Dead code in real go: micron-parser-go is never independently
		// required, only reached as the first replace's own resolution
		// target, so this second replace never fires -- checking its
		// target (a name the fake proxy has never heard of) would be a
		// false finding about a module nothing ever fetches.
		{Old: "github.com/real-org/micron-parser-go", New: "github.com/totallyfakeorg/never-fetched", NewVersion: "v1.9.9"},
	}
	findings := CheckAll(reqs, reps, nil, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected the dead second-hop replace target to be ignored, got %+v", findings)
	}
}

func TestCheckAll_UnreplacedRequirementStillChecked(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "github.com/totally/madeup-pkg-xyz", Version: "v0.0.0"}}
	findings := CheckAll(reqs, nil, nil, nil, "", proxy)
	if len(findings) != 1 || findings[0].Reason != "not-found" {
		t.Fatalf("expected the not-found finding to survive with no replacements, got %+v", findings)
	}
}

// TestCheckAll_ReplacePrecedence_GeneralAppliesWhenSpecificVersionDoesNotMatch
// is a regression test for a real precedence bug: a go.mod can carry both a
// version-specific replace ("foo v1.0.0 => ...") and a version-agnostic one
// ("foo => ...") for the same module at once. Verified live against the real
// go toolchain (`go list -m all`, both file orderings): when the required
// version doesn't match the specific replace's old-version, the
// version-agnostic replace applies instead — the specific one isn't just
// lower priority, it's entirely inapplicable. Before selectReplace existed,
// CheckAll built a plain map[string]Replacement keyed by Old and filled in
// file-scan order, so it silently picked whichever replace was written
// *last* in the file instead of the one real go actually applies — matching
// only by accident of order. Here the specific replace points local (would
// wrongly suppress the check) and the general one points at a hallucinated
// module (should produce a "not-found" finding); both file orderings must
// produce the same, real-go-matching result.
func TestCheckAll_ReplacePrecedence_GeneralAppliesWhenSpecificVersionDoesNotMatch(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "example.com/foo", Version: "v1.5.0"}}
	general := Replacement{Old: "example.com/foo", New: "github.com/totally/madeup-pkg-xyz"}
	specific := Replacement{Old: "example.com/foo", OldVersion: "v1.0.0", New: "./local-only"}

	for _, name := range []string{"general-then-specific", "specific-then-general"} {
		t.Run(name, func(t *testing.T) {
			var reps []Replacement
			if name == "general-then-specific" {
				reps = []Replacement{general, specific}
			} else {
				reps = []Replacement{specific, general}
			}
			findings := CheckAll(reqs, reps, nil, nil, "", proxy)
			if len(findings) != 1 || findings[0].Reason != "not-found" {
				t.Fatalf("expected the version-agnostic replace's module target to be checked (real go applies it, not the non-matching version-specific one), got %+v", findings)
			}
		})
	}
}

// TestCheckAll_ReplacePrecedence_SpecificWinsWhenVersionMatches mirrors the
// other half of the same real-go rule: when the required version *does*
// match the version-specific replace's old-version, that one wins over the
// version-agnostic fallback, regardless of file order.
func TestCheckAll_ReplacePrecedence_SpecificWinsWhenVersionMatches(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "example.com/foo", Version: "v1.0.0"}}
	general := Replacement{Old: "example.com/foo", New: "github.com/totally/madeup-pkg-xyz"}
	specific := Replacement{Old: "example.com/foo", OldVersion: "v1.0.0", New: "./local-only"}

	for _, name := range []string{"general-then-specific", "specific-then-general"} {
		t.Run(name, func(t *testing.T) {
			var reps []Replacement
			if name == "general-then-specific" {
				reps = []Replacement{general, specific}
			} else {
				reps = []Replacement{specific, general}
			}
			findings := CheckAll(reqs, reps, nil, nil, "", proxy)
			if len(findings) != 0 {
				t.Fatalf("expected the version-specific local replace to win (real go applies it over the general one) and produce no findings, got %+v", findings)
			}
		})
	}
}

// TestCheckTools_CoveredByRequireProducesNoFindings is the common,
// correct-go.mod case: `go get -tool` always pairs a `tool` line with a
// covering `require` entry, so the tool path itself must not be
// independently re-checked (it already was, via the normal require
// scan) or double-flagged.
func TestCheckTools_CoveredByRequireProducesNoFindings(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"golang.org/x/tools": {
			versions: []string{"v0.49.0", "v0.50.0"},
			latest:   "v0.50.0",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	resolvedReqs := []Requirement{{Path: "golang.org/x/tools", Version: "v0.50.0"}}
	findings := CheckTools([]string{"golang.org/x/tools/cmd/stringer"}, resolvedReqs, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a tool path covered by an existing require to produce no findings, got %+v", findings)
	}
}

// TestCheckTools_UncoveredButResolvesViaPrefixWalk is the "legitimate
// hand-written tool line before `go mod tidy`" case: no require entry
// covers the tool path, but the module that owns it is real — only the
// module-level prefix is registered with the fake proxy, not the full
// package path, so this also exercises resolveToolPath's prefix walk.
func TestCheckTools_UncoveredButResolvesViaPrefixWalk(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"golang.org/x/tools": {
			versions: []string{"v0.49.0", "v0.50.0"},
			latest:   "v0.50.0",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	findings := CheckTools([]string{"golang.org/x/tools/cmd/stringer"}, nil, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a tool path resolving to a clean module via prefix walk to produce no findings, got %+v", findings)
	}
}

// TestCheckTools_UncoveredAndUnresolvable is the direct regression test
// for the bug this run fixes: a `tool` directive with no covering
// require, naming a package that doesn't resolve at any prefix, must
// surface exactly the same "not-found" finding a require entry would.
func TestCheckTools_UncoveredAndUnresolvable(t *testing.T) {
	proxy := fakeProxy(t, nil)
	findings := CheckTools([]string{"github.com/definitely-not-a-real-hallucinated-tool-xyz123/cmd/foo"}, nil, nil, "", proxy)
	if len(findings) != 1 || findings[0].Reason != "not-found" {
		t.Fatalf("expected exactly one not-found finding, got %+v", findings)
	}
}

// TestCheckTools_CoveredByOwnModulePathProducesNoFindings is the
// regression test for this run's fix: a `tool` directive can legally
// name a package inside the main module itself, with no require or
// replace directive involved at all — confirmed live against real go
// 1.24: a scratch module `example.com/mymodule` with a bare `tool
// example.com/mymodule/cmd/gen` line (an internal code-generator kept in
// the same repo) builds, vets, and runs `go tool gen` cleanly with
// GOPROXY=off, and `go mod tidy` leaves the line untouched — nothing is
// ever fetched over the network for it. The fake proxy here has zero
// modules registered, so if modulePath coverage weren't checked this
// would 404 and produce a spurious "not-found", exactly the false
// positive `/tmp/toolrepro`'s live repro showed against a real build
// before this fix (github.com/experimental-gains/modslop, run #417).
func TestCheckTools_CoveredByOwnModulePathProducesNoFindings(t *testing.T) {
	proxy := fakeProxy(t, nil)
	findings := CheckTools([]string{"example.com/mymodule/cmd/gen"}, nil, nil, "example.com/mymodule", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a tool path inside the main module itself to produce no findings, got %+v", findings)
	}
}

// TestCheckAll_ToolDirectiveCoveredByOrphanReplaceProducesNoDuplicateFinding
// is the regression test for a real false positive found run #404: the same
// require+replace false positive CheckTools's own doc comment already
// documents fixing, but one layer further out — an *orphan* replace (Old
// path named by no `require` line at all, see orphanReplacementTargets) can
// still be exactly what a `tool` directive's package path resolves through.
// Confirmed live before this fix: a bare `replace example.com/oldtool =>
// github.com/real-org/realtool v1.2.3` with no covering require, plus `tool
// example.com/oldtool/cmd/gen`, correctly checked github.com/real-org/
// realtool via orphanReplacementTargets — but CheckTools had no visibility
// into reps at all, so it treated the tool path as uncovered and
// additionally resolved it under the stale example.com/oldtool name,
// producing a spurious second "not-found" even when realtool is clean and
// established (TestCheckAll_ToolDirectiveCoveredByOrphanReplaceOfCleanModule
// below is the sharper case: zero findings expected, one produced).
func TestCheckAll_ToolDirectiveCoveredByOrphanReplaceProducesNoDuplicateFinding(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reps := []Replacement{{Old: "example.com/oldtool", New: "github.com/totallyfakeorg/oldtool-clone", NewVersion: "v0.0.1"}}
	tools := []string{"example.com/oldtool/cmd/gen"}
	findings := CheckAll(nil, reps, tools, nil, "", proxy)
	if len(findings) != 1 || findings[0].Module != "github.com/totallyfakeorg/oldtool-clone" {
		t.Fatalf("expected exactly one finding, on the orphan replace's New target only, got %+v", findings)
	}
}

func TestCheckAll_ToolDirectiveCoveredByOrphanReplaceOfCleanModule(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/real-org/realtool": {
			versions: []string{"v1.0.0", "v1.2.3"},
			latest:   "v1.2.3",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	reps := []Replacement{{Old: "example.com/oldtool", New: "github.com/real-org/realtool", NewVersion: "v1.2.3"}}
	tools := []string{"example.com/oldtool/cmd/gen"}
	findings := CheckAll(nil, reps, tools, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected zero findings (real go resolves this tool through the replace to a clean, established module), got %+v", findings)
	}
}

// TestCheckTools_DuplicateToolPathDeduped confirms the same tool path
// listed twice in a `tool (...)` block produces one finding, not two.
func TestCheckTools_DuplicateToolPathDeduped(t *testing.T) {
	proxy := fakeProxy(t, nil)
	tools := []string{
		"github.com/definitely-not-a-real-hallucinated-tool-xyz123/cmd/foo",
		"github.com/definitely-not-a-real-hallucinated-tool-xyz123/cmd/foo",
	}
	findings := CheckTools(tools, nil, nil, "", proxy)
	if len(findings) != 1 || findings[0].Reason != "not-found" {
		t.Fatalf("expected exactly one deduped not-found finding, got %+v", findings)
	}
}

// TestCheckAll_ToolDirectiveCoveredByReplacedRequirement is the direct
// regression test for the bug CheckTools's own doc comment describes: a
// `tool` directive names its module's declared (pre-replace) path, so a
// require+replace pair that redirects that module to a different, clean
// real module must still count as "covering" the tool line. Reproduced
// live before the fix (CheckAll passed CheckTools the post-replace
// resolved list instead of reqs): example.com/oldtool is a placeholder
// path that was never published (the normal shape for a full-rename
// fork) and never resolves on its own, so the tool directive was treated
// as uncovered and independently resolved under that stale name,
// producing a spurious high-severity "not-found" — even though the
// require-level check had already confirmed the real replacement target
// (github.com/real-org/realtool) is a clean, established module.
func TestCheckAll_ToolDirectiveCoveredByReplacedRequirement(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/real-org/realtool": {
			versions: []string{"v1.0.0", "v1.2.3"},
			latest:   "v1.2.3",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "example.com/oldtool", Version: "v0.0.0"}}
	reps := []Replacement{{Old: "example.com/oldtool", New: "github.com/real-org/realtool", NewVersion: "v1.2.3"}}
	tools := []string{"example.com/oldtool/cmd/gen"}

	findings := CheckAll(reqs, reps, tools, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected the tool directive to be covered by the require+replace pair (real target resolves clean), got %+v", findings)
	}
}

// TestCheckAll_ToolDirectiveCoveredByLocallyReplacedRequirement is the
// local-replace counterpart: CheckAll already skips the require-level
// check entirely for a local replace (no fetchable code to audit — see
// CheckAll's own doc comment), so a `tool` directive under that same
// pre-replace path must be treated as covered too, consistent with that
// design, rather than independently resolved under the stale name
// against public infrastructure the real build never actually queries
// for it.
func TestCheckAll_ToolDirectiveCoveredByLocallyReplacedRequirement(t *testing.T) {
	proxy := fakeProxy(t, nil) // proxy knows nothing — a bare lookup would 404
	reqs := []Requirement{{Path: "example.com/oldtool", Version: "v0.0.0"}}
	reps := []Replacement{{Old: "example.com/oldtool", New: "../local-fork"}}
	tools := []string{"example.com/oldtool/cmd/gen"}

	findings := CheckAll(reqs, reps, tools, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected the tool directive to be covered by the locally-replaced requirement, got %+v", findings)
	}
}

func TestCheckRequirement_TyposquatOfPopular(t *testing.T) {
	// New-and-thin, per run #55: the collision check now only fires
	// alongside evidence the candidate itself looks unestablished — a
	// freshly-published single-version module is the classic shape of a
	// name registered to catch a typo, so it should trip both heuristics
	// at once.
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/sirupsen/logrusx": {
			versions: []string{"v0.1.0"},
			latest:   "v0.1.0",
			when:     time.Now().Add(-2 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/sirupsen/logrusx"}, proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-risk"] || !reasons["new-and-thin"] {
		t.Fatalf("expected both name-collision-risk and new-and-thin findings, got %+v", findings)
	}
}

// TestCheckRequirement_ExactNameCloneOfPopular is the end-to-end version
// of TestClosestPopularMatch's exact-name case: a freshly-published,
// single-version module whose base name exactly matches a popular
// module, published under an unrelated owner, must surface as
// name-collision-exact (not the near-miss name-collision-risk reason) —
// this is the real, disclosed impersonation technique from Bae &
// Yagemann's "Beyond Takedown" (arXiv:2606.26291, 2026), not a typo.
func TestCheckRequirement_ExactNameCloneOfPopular(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/totallyfakeorg/zerolog": {
			versions: []string{"v0.1.0"},
			latest:   "v0.1.0",
			when:     time.Now().Add(-2 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/totallyfakeorg/zerolog"}, proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-exact"] {
		t.Fatalf("expected a name-collision-exact finding, got %+v", findings)
	}
	if reasons["name-collision-risk"] {
		t.Errorf("exact-name case should not also report the near-miss reason, got %+v", findings)
	}
}

// TestCheckRequirement_ExactNameCloneOfPopular_EstablishedNotFlagged
// confirms the exact-name case is gated by looksUnestablished exactly
// like the near-miss case (TestCheckRequirement_TyposquatOfPopular_
// EstablishedNotFlagged below) — this is what keeps a long-lived,
// publicly-maintained fork that deliberately kept a popular module's
// base name (a real, common, legitimate pattern — see run #124's
// decision log finding that replace-to-fork is routine) from being
// flagged just for existing under a different owner. Only a fork that
// also looks brand-new and thin trips this.
func TestCheckRequirement_ExactNameCloneOfPopular_EstablishedNotFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/totallyfakeorg/zerolog": {
			versions: []string{"v1.0.0", "v1.0.1"},
			latest:   "v1.0.1",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/totallyfakeorg/zerolog"}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected an established same-name fork to produce no findings, got %+v", findings)
	}
}

// TestCheckRequirement_NameCollisionExactSuppressedForMajorVersionBump is
// the name-collision-exact counterpart of
// TestEvaluateModuleStatusSuppressesNewAndThinForMajorVersionBump
// (proxy_test.go): a popular module's own next major-version bump is a
// brand-new module path per Go's import-compatibility rule (BaseName
// strips the "/vN" suffix, so its base name is identical to the
// popularModules entry for the module's *previous* major line), and a
// freshly-cut bump is, by definition, thin (one version, days old) —
// exactly closestPopularMatch's exact-name-match branch plus
// looksUnestablishedForImpersonation, which is the highest-severity
// name-collision-exact finding ("verify this isn't a malicious clone").
// IsMajorVersionBumpOfEstablished already exists precisely to recognize
// this shape (see its own doc comment and the sigs.k8s.io/structured-
// merge-diff/v7 case), but before this fix it was only wired into the
// new-and-thin/version-flooded switch below, not into this collision
// check — so the real, same-owner, already-popular github.com/redis/
// go-redis project simply cutting a new v10 would be flagged as a
// likely malicious clone of its own v9 self.
func TestCheckRequirement_NameCollisionExactSuppressedForMajorVersionBump(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		// The established predecessor major line already in
		// popularModules — long history, well outside every freshness
		// window.
		"github.com/redis/go-redis/v9": {
			versions: []string{"v9.0.0", "v9.1.0", "v9.7.0"},
			latest:   "v9.7.0",
			when:     time.Now().Add(-1000 * 24 * time.Hour),
		},
		// The brand-new next major line: same project, same owner, just
		// cut days ago — the exact shape looksUnestablishedForImpersonation
		// exists to flag, except here it's not impersonation at all.
		"github.com/redis/go-redis/v10": {
			versions: []string{"v10.0.0"},
			latest:   "v10.0.0",
			when:     time.Now().Add(-2 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/redis/go-redis/v10", Version: "v10.0.0"}, proxy)
	for _, f := range findings {
		if f.Reason == "name-collision-exact" {
			t.Errorf("got name-collision-exact for an established module's own major-version bump: %+v", f)
		}
	}
}

// TestCheckRequirement_ExactNameCloneOfUntaggedPopular is the real-
// world-testing 67th-angle regression this run's fix is for: an
// attacker-published module that never cuts a git tag at all
// (VersionCount==0, the same shape github.com/zmap/zcrypto has —
// see looksUnestablished's own comment) previously exempted itself from
// *every* collision check, including name-collision-exact, by simply
// never tagging. Confirmed live before this fix: this exact scenario
// produced zero findings, silently letting through the precise
// impersonation technique ("Beyond Takedown", arXiv:2606.26291, 2026)
// this severity level exists to catch. A real attacker doesn't even
// need version history to evade this tool — not tagging is strictly
// easier than publishing a convincing fake one.
func TestCheckRequirement_ExactNameCloneOfUntaggedPopular(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/totallyfakeorg/zerolog": {
			versions: nil, // never tagged
			latest:   "v0.0.0-20260925120000-abcdef123456",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/totallyfakeorg/zerolog"}, proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-exact"] {
		t.Fatalf("expected an untagged exact-name clone to still surface name-collision-exact, got %+v", findings)
	}
}

// TestCheckRequirement_ExactNameCloneOfUntaggedPopular_CaseVariant is
// TestCheckRequirement_ExactNameCloneOfUntaggedPopular's case-differing
// counterpart: an untagged module published as "Zerolog" (capital Z)
// rather than "zerolog" is just as legal a module path as the identical-
// case clone (module.CheckPath accepts uppercase, confirmed live — see
// TestClosestPopularMatch's case-variant case for the full explanation),
// and just as invisible a difference to a human or LLM reading go.mod.
// Before this fix, closestPopularMatch's exact-match branch compared
// base names case-sensitively, so this fell through to the near-miss
// path and got gated on looksUnestablished instead of
// looksUnestablishedForImpersonation — which, like the identical-case bug
// this test's sibling regressions, let an untagged clone (VersionCount==0)
// evade every check by simply never tagging, just reached through a
// different door (case variation instead of same-case cloning).
func TestCheckRequirement_ExactNameCloneOfUntaggedPopular_CaseVariant(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/totallyfakeorg/Zerolog": {
			versions: nil, // never tagged
			latest:   "v0.0.0-20260925120000-abcdef123456",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/totallyfakeorg/Zerolog"}, proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-exact"] {
		t.Fatalf("expected an untagged case-differing exact-name clone to still surface name-collision-exact, got %+v", findings)
	}
}

// TestCheckRequirement_TyposquatOfUntaggedPopularStillExempt confirms
// this run's fix is scoped to the exact-match branch only: the
// near-miss (typosquat) check must keep exempting VersionCount==0,
// since that's the actual github.com/zmap/zcrypto false-positive
// looksUnestablished's own comment documents — this run's fix must not
// regress it.
func TestCheckRequirement_TyposquatOfUntaggedPopularStillExempt(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/zmap/zcrypto": {
			versions: nil, // never tagged, like the real repo
			latest:   "v0.0.0-20260925120000-abcdef123456",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/zmap/zcrypto"}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected the near-miss zcrypto~crypto case to stay exempt when untagged, got %+v", findings)
	}
}

// TestCheckRequirement_ShortExactNameCloneNotGatedByMinLen is the real-
// world-testing regression this run's fix is for. closestPopularMatch's
// exact-name-different-owner scan used to share typoMinNameLen (6 runes)
// with the near-miss scan it was originally written for, so any
// popularModules entry with a base name shorter than that — "gin"
// (github.com/gin-gonic/gin), among many others across the curated list
// — could never trigger name-collision-exact at all, no matter how
// blatant or unestablished an exact clone under a different owner was.
//
// Confirmed live, 2026-09, against a real, existing Go module:
// github.com/gintool/gin ("GI in No Time - a Simple Microframework for
// Genetic Improvement", per its own GitHub description) is a genuine,
// decade-old (created 2017), completely unrelated academic project —
// confirmed via the GitHub API to be `"fork": false`, nothing to do with
// the hugely popular gin-gonic/gin web framework — that happens to share
// its exact base name by pure coincidence. It has never been tagged on
// proxy.golang.org (VersionCount==0, @latest resolves to a pseudo-version
// only), exactly the "unestablished" shape looksUnestablishedForImpersonation
// exists to catch. Before this fix, `modslop` run against a real go.mod
// requiring it (`go.mod` with `require github.com/gintool/gin
// v0.0.0-20260501154844-def278d4fb35`) reported "checked 1 requirement(s),
// nothing flagged" — the exact blind spot an actual attacker-registered
// clone of "gin", or any other short popular name in this tool's own
// list, would have exploited, undetected by modslop's own highest-
// severity, best-evidenced check, purely because the name they chose to
// clone was short.
func TestCheckRequirement_ShortExactNameCloneNotGatedByMinLen(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/gintool/gin": {
			versions: nil, // never tagged, like the real repo
			latest:   "v0.0.0-20260501154844-def278d4fb35",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/gintool/gin"}, proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-exact"] {
		t.Fatalf("expected an untagged exact clone of a short popular base name (\"gin\") to surface name-collision-exact, got %+v", findings)
	}
}

// TestCheckRequirement_GenericClientBaseNameNotFlagged is the real-
// world-testing regression this run's fix is for: pingcap/tidb's actual
// go.mod requires github.com/tikv/pd/client — the real TiKV Placement
// Driver client, an established, widely-used sub-package of the
// tikv/pd project that simply resolves via pseudo-version only (never
// independently tagged, same shape as the zcrypto case above) — which
// matched already-popular go.etcd.io/etcd/client/v3 on major-suffix-
// stripped base name "client" alone and fired the highest-severity
// name-collision-exact finding, purely because "client" is as
// conventional a trailing package-path segment across the ecosystem as
// "errors" or "common" already are (see genericBaseNames's own comment
// for the corroborating real-world evidence that ruled out
// coincidence). Modeled on TestCheckRequirement_ExactNameCloneOfUntaggedPopular's
// shape (untagged, VersionCount==0) specifically to confirm the fix is
// the genericBaseNames exemption itself, not an accidental side effect
// of looksUnestablishedForImpersonation's own tagging-based logic.
func TestCheckRequirement_GenericClientBaseNameNotFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/tikv/pd/client": {
			versions: nil, // never independently tagged, like the real module
			latest:   "v0.0.0-20260926161736-9186d07e9dfe",
			when:     time.Now().Add(-1 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/tikv/pd/client"}, proxy)
	for _, f := range findings {
		if f.Reason == "name-collision-exact" || f.Reason == "name-collision-risk" {
			t.Fatalf("expected no name-collision finding for the generic base name %q, got %+v", "client", f)
		}
	}
}

// TestCheckRequirement_TyposquatOfPopular_EstablishedNotFlagged is the
// regression this run's fix is actually for (run #55, deferred from run
// #52's decision log): a module that's close in name to a popular one
// but demonstrably established (multiple versions, older than
// recentWindow) should NOT be flagged as a name-collision risk — that
// combination is exactly what produced false positives like
// "gogo/protobuf" ~ "vtprotobuf" before genericBaseNames patched around
// it one word at a time. Gating the check on looksUnestablished fixes
// the class structurally instead.
func TestCheckRequirement_TyposquatOfPopular_EstablishedNotFlagged(t *testing.T) {
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
	if len(findings) != 0 {
		t.Fatalf("expected an established near-miss name to produce no findings, got %+v", findings)
	}
}

// TestCheckRequirement_TyposquatOfPopular_NotFoundStillFlagged confirms
// the collision check still runs when the module doesn't resolve at
// all (looksUnestablished treats !Exists as unestablished) — a
// nonexistent name close to a popular one is at least as suspicious as
// a thin new one, and it should surface alongside the not-found finding
// rather than being suppressed by it.
func TestCheckRequirement_TyposquatOfPopular_NotFoundStillFlagged(t *testing.T) {
	proxy := fakeProxy(t, nil)
	findings := CheckRequirement(Requirement{Path: "github.com/sirupsen/logrusx"}, proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-risk"] || !reasons["not-found"] {
		t.Fatalf("expected both name-collision-risk and not-found findings, got %+v", findings)
	}
}

// TestCheckRequirement_PrivatePathNotFlaggedNotFound is the regression
// for the run #87 GOPRIVATE/GONOPROXY false positive: a module path the
// real `go` command would fetch directly from VCS (never touching the
// public proxy at all) must not be flagged "not-found" just because the
// public proxy has never heard of it — that's the expected, correct
// state for a private module, not evidence of anything.
func TestCheckRequirement_PrivatePathNotFlaggedNotFound(t *testing.T) {
	proxy := fakeProxy(t, nil) // 404s everything, same as a real private path would
	proxy.PrivatePatterns = []string{"corp.example.invalid/*"}
	findings := CheckRequirement(Requirement{Path: "corp.example.invalid/internal/widget"}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a GOPRIVATE-covered path to produce no findings, got %+v", findings)
	}
}

// TestCheckRequirement_PrivatePathStillFlagsNameCollision confirms the
// private-path exemption only suppresses the proxy-existence-based
// findings (not-found/new-and-thin), not the pure-string name-collision
// heuristic — an internal module whose base name happens to be a couple
// of edits from a popular one is still worth a look, and looksUnestablished
// already treats an unresolved (including private) module as unestablished
// for that check.
func TestCheckRequirement_PrivatePathStillFlagsNameCollision(t *testing.T) {
	proxy := fakeProxy(t, nil)
	proxy.PrivatePatterns = []string{"corp.example.invalid/*"}
	findings := CheckRequirement(Requirement{Path: "corp.example.invalid/vendor/logrusx"}, proxy)
	reasons := map[string]bool{}
	for _, f := range findings {
		reasons[f.Reason] = true
	}
	if !reasons["name-collision-risk"] {
		t.Fatalf("expected name-collision-risk to still fire for a private path, got %+v", findings)
	}
	if reasons["not-found"] {
		t.Fatalf("expected not-found to stay suppressed for a private path, got %+v", findings)
	}
}

// TestCheckRequirement_UntaggedActiveModuleNotFlagged is the regression
// for a real false positive found by running modslop against 15 large
// real-world go.mod files (kubernetes, moby, cilium, etc): a module
// with zero tagged releases whose @latest pseudo-version always
// resolves to a recent commit (true of any actively-maintained
// untagged module, not just new ones) was flagged as a "high severity"
// name-collision risk purely because it happened to be a couple of
// edits from a popular module's name. github.com/zmap/zcrypto — a
// decade-old dependency of moby/moby and cilium/cilium that has never
// cut a tagged release — is the real case that surfaced this against
// golang.org/x/crypto.
func TestCheckRequirement_UntaggedActiveModuleNotFlagged(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/zmap/zcrypto": {
			versions: nil,
			latest:   "v0.0.0-20260919232836-751f288b7287",
			when:     time.Now().Add(-1 * 24 * time.Hour),
		},
	})
	findings := CheckRequirement(Requirement{Path: "github.com/zmap/zcrypto"}, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected an untagged-but-active module to produce no findings, got %+v", findings)
	}
}

// TestCheckAll_ConcurrentAndOrdered guards against two regressions in
// the concurrent CheckAll (run #52, added after CheckAll ran every
// requirement's proxy lookups fully sequentially and didn't finish
// within a minute on a real 250+ requirement go.mod): that it's
// actually concurrent (this test would take >= 50*10ms sequentially,
// well over the deadline, but finishes well under it in parallel), and
// that findings still come back in requirement order despite
// goroutines finishing in whatever order the fake proxy responds.
func TestCheckAll_ConcurrentAndOrdered(t *testing.T) {
	const n = 50
	modules := make(map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}, n)
	var reqs []Requirement
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("github.com/totally/madeup-pkg-%03d", i)
		reqs = append(reqs, Requirement{Path: path, Version: "v1.0.0"})
		// Left out of modules on purpose for every 5th path, so it
		// resolves as not-found — gives each finding a distinct,
		// checkable module to confirm ordering.
		if i%5 != 0 {
			modules[path] = struct {
				versions []string
				latest   string
				when     time.Time
			}{versions: []string{"v1.0.0"}, latest: "v1.0.0", when: time.Now().Add(-400 * 24 * time.Hour)}
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		for path, m := range modules {
			escaped, _ := escapeModulePath(path)
			if r.URL.Path == "/"+escaped+"/@latest" {
				_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, m.latest, m.when.Format(time.RFC3339))
				return
			}
			if r.URL.Path == "/"+escaped+"/@v/list" {
				_, _ = fmt.Fprint(w, strings.Join(m.versions, "\n"))
				return
			}
			if r.URL.Path == "/"+escaped+"/@v/v1.0.0.info" {
				_, _ = fmt.Fprintf(w, `{"Version":"v1.0.0","Time":%q}`, m.when.Format(time.RFC3339))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	start := time.Now()
	findings := CheckAll(reqs, nil, nil, nil, "", proxy)
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("CheckAll took %s for %d requirements with a 10ms-per-call fake proxy — looks sequential, not concurrent", elapsed, n)
	}

	if len(findings) != n/5 {
		t.Fatalf("expected %d not-found findings, got %d: %+v", n/5, len(findings), findings)
	}
	for i, f := range findings {
		want := fmt.Sprintf("github.com/totally/madeup-pkg-%03d", i*5)
		if f.Module != want {
			t.Errorf("finding %d: expected module %q in original requirement order, got %q", i, want, f.Module)
		}
	}
}

// TestCheckAll_ExcludedRequirementExactMatch is the end-to-end regression
// for the exclude-directive gap: a require directive whose exact version
// is also named by an exclude directive in the same go.mod makes `go
// build`/`go list -m all` fail outright (confirmed live, see
// checkExcludedRequirements's doc comment) — a real, deterministic
// build-breaking config error that has nothing to do with whether the
// module actually exists. The fake proxy here serves the module cleanly
// (established, multi-version, old) precisely to isolate that: even a
// module that would otherwise sail through every other check clean still
// must be flagged, because the exclude/require contradiction is fatal on
// its own.
func TestCheckAll_ExcludedRequirementExactMatch(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/pkg/errors": {
			versions: []string{"v0.8.0", "v0.9.1"},
			latest:   "v0.9.1",
			when:     time.Now().Add(-1000 * 24 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "github.com/pkg/errors", Version: "v0.9.1"}}
	excludes := []Requirement{{Path: "github.com/pkg/errors", Version: "v0.9.1"}}

	findings := CheckAll(reqs, nil, nil, excludes, "", proxy)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Reason != "excluded-requirement" || findings[0].Severity != SeverityHigh {
		t.Errorf("got %+v, want a high-severity excluded-requirement finding", findings[0])
	}
	if findings[0].Module != "github.com/pkg/errors" {
		t.Errorf("got module %q, want github.com/pkg/errors", findings[0].Module)
	}
}

// TestCheckAll_ExcludeDifferentVersionNoEffect confirms the match is
// exact, not per-module: excluding a *different* version of the same
// module the go.mod actually requires must produce no finding at all —
// confirmed live that this exact shape (exclude v0.9.0 while requiring
// v0.9.1) builds and resolves completely normally with the real go
// toolchain, unlike the exact-match case above.
func TestCheckAll_ExcludeDifferentVersionNoEffect(t *testing.T) {
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/pkg/errors": {
			versions: []string{"v0.9.0", "v0.9.1"},
			latest:   "v0.9.1",
			when:     time.Now().Add(-1000 * 24 * time.Hour),
		},
	})
	reqs := []Requirement{{Path: "github.com/pkg/errors", Version: "v0.9.1"}}
	excludes := []Requirement{{Path: "github.com/pkg/errors", Version: "v0.9.0"}}

	findings := CheckAll(reqs, nil, nil, excludes, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when the excluded version differs from the required one, got %+v", findings)
	}
}

// TestClosestPopularMatch_LongNameIsFast is a regression test for run #109:
// a go.mod requirement with an adversarially (or just corrupted) long
// module path used to cost O(len(name)) per entry in popularModules, since
// closestPopularMatch ran the full Levenshtein DP against every candidate
// regardless of how far apart the lengths already were. A single 10MB name
// took ~19s before the length-difference short-circuit was added; this
// checks it now stays well under a second.
func TestClosestPopularMatch_LongNameIsFast(t *testing.T) {
	longName := "github.com/example/" + strings.Repeat("a", 10_000_000)

	start := time.Now()
	_, _, ok := closestPopularMatch(longName, longName)
	elapsed := time.Since(start)

	if ok {
		t.Error("expected no match for a nonsense long name")
	}
	if elapsed > 2*time.Second {
		t.Errorf("closestPopularMatch on a 10MB name took %s, want well under 2s", elapsed)
	}
}

// TestClosestPopularMatch_MinNameLenBoundary pins the exact edge of
// typoMinNameLen=6 (found via mutation testing, run #125: gremlins
// flagged the `<` in `len(name) < typoMinNameLen` as LIVED — every
// existing test used names far from the cutoff, so a `<=` mutant
// survived undetected). "consul" (6 chars, popular) vs "consol" (6
// chars, one edit away) must still match at exactly the minimum
// length; dropping either name to 5 chars must exclude it, per the
// "excludes short base names" comment on typoMinNameLen.
func TestClosestPopularMatch_MinNameLenBoundary(t *testing.T) {
	if match, _, ok := closestPopularMatch("github.com/example/consol", "consol"); !ok {
		t.Fatal("expected a match: \"consol\" is exactly typoMinNameLen (6) and one edit from popular \"consul\"")
	} else if !strings.Contains(match, "consul") {
		t.Errorf("expected match to reference consul, got %q", match)
	}

	// One character shorter (5, below typoMinNameLen) and otherwise the
	// same shape must NOT match, even though it's still one edit away.
	if match, _, ok := closestPopularMatch("github.com/example/consu", "consu"); ok {
		t.Errorf("expected no match: \"consu\" (5 chars) is below typoMinNameLen, got false positive %q", match)
	}
}

// TestClosestPopularMatch_LengthDiffPrefilterBoundary pins the exact
// edge of the run #109 length-difference short-circuit (found via
// mutation testing, run #125: both arms of `diff > typoMaxDistance ||
// diff < -typoMaxDistance` had LIVED mutants — every existing test
// used names either identical in length or wildly apart, never exactly
// typoMaxDistance apart). A pair exactly typoMaxDistance(2) apart in
// length, with maxLen at or above typoScaledMaxLen(10) so the full
// allowed distance applies, must still be compared (and match) rather
// than skipped by the prefilter — in both length directions.
func TestClosestPopularMatch_LengthDiffPrefilterBoundary(t *testing.T) {
	// Candidate 2 chars *longer* than the popular name (diff = +2).
	if match, _, ok := closestPopularMatch("github.com/example/fsnotifyab", "fsnotifyab"); !ok {
		t.Error("expected a match: \"fsnotifyab\" is exactly typoMaxDistance longer than popular \"fsnotify\", not past the prefilter cutoff")
	} else if !strings.Contains(match, "fsnotify") {
		t.Errorf("expected match to reference fsnotify, got %q", match)
	}

	// Candidate 2 chars *shorter* than the popular name (diff = -2).
	if match, _, ok := closestPopularMatch("github.com/example/contanrd", "contanrd"); !ok {
		t.Error("expected a match: \"contanrd\" is exactly typoMaxDistance shorter than popular \"containerd\", not past the prefilter cutoff")
	} else if !strings.Contains(match, "containerd") {
		t.Errorf("expected match to reference containerd, got %q", match)
	}
}

// TestCheckTools_ExactPathMatchIsCovered pins the exact-match arm of
// CheckTools' coverage check (found via mutation testing, run #125: a
// LIVED CONDITIONALS_NEGATION mutant on `tool == r.Path` — every
// existing coverage test used a tool path that's a strict sub-package
// of the require path, never identical to it). A tool directive naming
// exactly the same path as an existing require entry (no trailing
// package segment) must be treated as covered, not re-checked.
func TestCheckTools_ExactPathMatchIsCovered(t *testing.T) {
	proxy := fakeProxy(t, nil) // empty: if this were (wrongly) re-checked, it'd resolve as not-found
	resolvedReqs := []Requirement{{Path: "github.com/example/sometool", Version: "v1.0.0"}}
	findings := CheckTools([]string{"github.com/example/sometool"}, resolvedReqs, nil, "", proxy)
	if len(findings) != 0 {
		t.Fatalf("expected an exact tool==require path match to be covered with no findings, got %+v", findings)
	}
}

// TestCheckRequirement_RecentWindowBoundary pins the exact edge of
// recentWindow=30 days (found via mutation testing, run #125: the `<`
// in `time.Since(status.LatestTime) < recentWindow` had a LIVED
// CONDITIONALS_BOUNDARY mutant — existing tests used -2d and -400d,
// nowhere near the cutoff). A module published just under 30 days ago
// must still fire new-and-thin; just over must not. A 1-hour margin on
// each side avoids flakiness from wall-clock drift between here and
// the check itself, while still tightly bracketing the boundary.
func TestCheckRequirement_RecentWindowBoundary(t *testing.T) {
	justUnder := 30*24*time.Hour - time.Hour
	justOver := 30*24*time.Hour + time.Hour

	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/someone/just-under": {
			versions: []string{"v0.1.0"},
			latest:   "v0.1.0",
			when:     time.Now().Add(-justUnder),
		},
		"github.com/someone/just-over": {
			versions: []string{"v0.1.0"},
			latest:   "v0.1.0",
			when:     time.Now().Add(-justOver),
		},
	})

	findings := CheckRequirement(Requirement{Path: "github.com/someone/just-under"}, proxy)
	if len(findings) != 1 || findings[0].Reason != "new-and-thin" {
		t.Errorf("expected new-and-thin just under the 30-day window, got %+v", findings)
	}

	findings = CheckRequirement(Requirement{Path: "github.com/someone/just-over"}, proxy)
	if len(findings) != 0 {
		t.Errorf("expected no finding just over the 30-day window, got %+v", findings)
	}
}

// TestResolveToolPath_PrefixWalkCapBoundary pins the exact edge of
// toolPrefixWalkCap=8 (found via mutation testing, run #125: the `>`
// in `if attempts > toolPrefixWalkCap` and the `<` in the walk loop
// both had LIVED mutants — no existing test used a path anywhere near
// 8 segments). An 8-segment path must walk all the way down to its
// single-segment root prefix; a 9-segment path must NOT reach its
// root prefix, per toolPrefixWalkCap's documented cap on total
// attempts (see the const's comment on resolveToolPath).
func TestResolveToolPath_PrefixWalkCapBoundary(t *testing.T) {
	eightSegRoot := "root8"
	eightSegPath := eightSegRoot + "/b/c/d/e/f/g/h"
	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		eightSegRoot: {
			versions: []string{"v1.0.0"},
			latest:   "v1.0.0",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	if modPath, _, resolved := resolveToolPath(eightSegPath, proxy); !resolved || modPath != eightSegRoot {
		t.Errorf("expected an 8-segment path to walk down to its root prefix %q, got modPath=%q resolved=%v", eightSegRoot, modPath, resolved)
	}

	nineSegRoot := "root9"
	nineSegPath := nineSegRoot + "/b/c/d/e/f/g/h/i"
	proxy = fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		nineSegRoot: {
			versions: []string{"v1.0.0"},
			latest:   "v1.0.0",
			when:     time.Now().Add(-400 * 24 * time.Hour),
		},
	})
	if _, _, resolved := resolveToolPath(nineSegPath, proxy); resolved {
		t.Errorf("expected a 9-segment path to stay capped short of its root prefix %q, but it resolved", nineSegRoot)
	}
}

// TestClosestPopularMatch_SameBaseNameDifferentOrgIsExactMatch used to
// pin the `d > 0` guard as a "correctly not flagged" case (run #127,
// added to isolate a mutation-testing survivor — see git history for
// that reasoning). That guard was never a deliberate call that a
// same-name-different-owner candidate is safe; it was just what a
// distance-based typo check naturally does, and run #127 pinned the
// existing behavior rather than stress-testing the assumption behind
// it. Reversed this run: Bae & Yagemann, "Beyond Takedown: Measuring
// Malicious Go Module Persistence in the Wild" (arXiv:2606.26291,
// 2026) documents an active, disclosed campaign (2,289 malicious
// module versions; 684 GitHub repos and 1,377 proxy-cached versions
// remediated after disclosure) whose core technique is exactly this —
// republishing a popular module's exact name under a new, unfamiliar
// owner, not misspelling it (their worked example: real
// portapps/drawio-portable cloned verbatim as
// anotherteriy/drawio-portable). "docker" is still a deliberate choice
// among fake third-party-org candidates: docker/docker is in
// popularModules and nothing else in the list is a near-miss
// contaminant for it (unlike jsonschema, see the old comment), so this
// isolates the exact-match path cleanly.
func TestClosestPopularMatch_SameBaseNameDifferentOrgIsExactMatch(t *testing.T) {
	got, exact, ok := closestPopularMatch("github.com/example/docker", "docker")
	if !ok {
		t.Fatal("github.com/example/docker should be flagged as an exact-name collision against github.com/docker/docker")
	}
	if !exact {
		t.Error("expected exact=true for a 0-edit base-name match at a different path")
	}
	if !strings.Contains(got, "docker") {
		t.Errorf("expected match to reference docker/docker, got %q", got)
	}
}

// TestClosestPopularMatch_MultiByteNameUsesRuneLengthForScaling pins a
// bug found via real-world testing: the typoScaledMaxLen comparison used
// to compare len(name)/len(pName) (byte counts) instead of the rune
// counts used everywhere else in this function (nameLen/pLen, and the
// length-diff prefilter right above it). Since a multi-byte UTF-8 rune
// always encodes to more than one byte, that inflated the apparent
// length of any candidate name containing one — this name is 8 runes
// (two of them 2-byte Cyrillic look-alikes for "u"), which should get
// the scaled allowed=1 threshold like any other short name, but the
// byte-length bug pushed its apparent length to 10, past
// typoScaledMaxLen, letting the looser allowed=2 threshold through and
// flagging a 2-edit-distance name the tool's own documented policy says
// is too coincidental to be worth a warning at this length. Confirmed
// this only matters for the untrusted candidate name, not pName: pName
// always comes from the static, pure-ASCII popularModules list (see
// BaseName), so its byte and rune counts can never diverge — no fix
// needed on that side, just a note that it was checked.
func TestClosestPopularMatch_MultiByteNameUsesRuneLengthForScaling(t *testing.T) {
	// "logrus" (6 runes/bytes, pure ASCII) with two trailing 2-byte
	// Cyrillic characters appended (U+0445 twice — the same "encoding
	// artifact from somewhere else" shape an LLM copy-pasting a module
	// path can introduce): 8 runes, but each 2-byte char adds one extra
	// byte over its ASCII-equivalent length, so 10 bytes total.
	name := "logrusхх"
	if utf8RuneCount := len([]rune(name)); utf8RuneCount != 8 {
		t.Fatalf("test setup: expected an 8-rune name, got %d runes (%q)", utf8RuneCount, name)
	}
	if byteLen := len(name); byteLen != 10 {
		t.Fatalf("test setup: expected a 10-byte name (to cross typoScaledMaxLen via the byte-count bug), got %d bytes (%q)", byteLen, name)
	}

	match, _, ok := closestPopularMatch("github.com/attacker/"+name, name)
	if ok {
		t.Errorf("expected no match: %q is a 2-edit distance from popular \"logrus\" at rune-length 8 (< typoScaledMaxLen), so only a 1-edit distance should count — got flagged as %q", name, match)
	}
}

// TestLooksUnestablished_RecentWindowBoundary pins the same 30-day
// boundary as TestCheckRequirement_RecentWindowBoundary, but for
// looksUnestablished's own copy of the condition (check.go:150) rather
// than evaluateModuleStatus's new-and-thin copy (check.go:192). Found
// LIVED separately by mutation testing, run #127: the existing
// boundary test only chains through CheckRequirement's new-and-thin
// finding, which never exercises looksUnestablished (that function
// only gates name-collision-risk, and the existing test's module names
// aren't close to any popular module). Chains through a real
// name-collision instead so looksUnestablished's own boundary is what
// actually flips the assertion.
func TestLooksUnestablished_RecentWindowBoundary(t *testing.T) {
	justUnder := 30*24*time.Hour - time.Hour
	justOver := 30*24*time.Hour + time.Hour

	proxy := fakeProxy(t, map[string]struct {
		versions []string
		latest   string
		when     time.Time
	}{
		"github.com/someone-under/logruz": {
			versions: []string{"v0.1.0"},
			latest:   "v0.1.0",
			when:     time.Now().Add(-justUnder),
		},
		"github.com/someone-over/logruz": {
			versions: []string{"v0.1.0"},
			latest:   "v0.1.0",
			when:     time.Now().Add(-justOver),
		},
	})

	findings := CheckRequirement(Requirement{Path: "github.com/someone-under/logruz"}, proxy)
	found := false
	for _, f := range findings {
		if f.Reason == "name-collision-risk" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected name-collision-risk just under the 30-day window (against logrus), got %+v", findings)
	}

	findings = CheckRequirement(Requirement{Path: "github.com/someone-over/logruz"}, proxy)
	for _, f := range findings {
		if f.Reason == "name-collision-risk" {
			t.Errorf("expected no name-collision-risk just over the 30-day window, got %+v", findings)
		}
	}
}
