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
	if match, _, ok := closestPopularMatch("github.com/gni-gonic/gin", "gin"); !ok || match != "" {
		// "gin" itself is short (3 chars, below typoMinNameLen=6) so it
		// should not trigger — this guards against noisy short-name findings.
		if ok {
			t.Errorf("expected no match for short base name, got %q", match)
		}
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
			escaped := escapeModulePath(path)
			if r.URL.Path == "/"+escaped+"/@latest" {
				_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, m.latest, m.when.Format(time.RFC3339))
				return
			}
			if r.URL.Path == "/"+escaped+"/@v/list" {
				_, _ = fmt.Fprint(w, strings.Join(m.versions, "\n"))
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

func TestCheckAll_LocalReplacementSkipped(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "micron-parser-go", Version: "v0.0.0"}}
	reps := []Replacement{{Old: "micron-parser-go", New: "./third_party/micron"}}
	findings := CheckAll(reqs, reps, nil, proxy)
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
	findings := CheckAll(reqs, reps, nil, proxy)
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

	findings := CheckAll(reqs, reps, nil, proxy)
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

	findings := CheckAll(reqs, reps, nil, proxy)
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
	reps := []Replacement{{Old: "micron-parser-go", New: "github.com/real-org/micron-parser-go"}}
	findings := CheckAll(reqs, reps, nil, proxy)
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
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	reqs := []Requirement{{Path: "example.com/old-fork", Version: "v0.1.0"}}
	reps := []Replacement{{Old: "example.com/old-fork", New: module, NewVersion: "v2.0.3+incompatible"}}
	findings := CheckAll(reqs, reps, nil, proxy)
	if len(findings) != 1 || findings[0].Reason != "retracted" {
		t.Fatalf("expected the replace's new-side version (a real retracted version) to be flagged, got %+v", findings)
	}
}

func TestCheckAll_UnreplacedRequirementStillChecked(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "github.com/totally/madeup-pkg-xyz", Version: "v0.0.0"}}
	findings := CheckAll(reqs, nil, nil, proxy)
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
			findings := CheckAll(reqs, reps, nil, proxy)
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
			findings := CheckAll(reqs, reps, nil, proxy)
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
	findings := CheckTools([]string{"golang.org/x/tools/cmd/stringer"}, resolvedReqs, proxy)
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
	findings := CheckTools([]string{"golang.org/x/tools/cmd/stringer"}, nil, proxy)
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
	findings := CheckTools([]string{"github.com/definitely-not-a-real-hallucinated-tool-xyz123/cmd/foo"}, nil, proxy)
	if len(findings) != 1 || findings[0].Reason != "not-found" {
		t.Fatalf("expected exactly one not-found finding, got %+v", findings)
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
	findings := CheckTools(tools, nil, proxy)
	if len(findings) != 1 || findings[0].Reason != "not-found" {
		t.Fatalf("expected exactly one deduped not-found finding, got %+v", findings)
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
		reqs = append(reqs, Requirement{Path: path, Version: "v0.0.0"})
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
			escaped := escapeModulePath(path)
			if r.URL.Path == "/"+escaped+"/@latest" {
				_, _ = fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, m.latest, m.when.Format(time.RFC3339))
				return
			}
			if r.URL.Path == "/"+escaped+"/@v/list" {
				_, _ = fmt.Fprint(w, strings.Join(m.versions, "\n"))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	start := time.Now()
	findings := CheckAll(reqs, nil, nil, proxy)
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
	findings := CheckTools([]string{"github.com/example/sometool"}, resolvedReqs, proxy)
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
