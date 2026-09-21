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
		if match, ok := closestPopularMatch(fp.modPath, fp.name); ok {
			t.Errorf("expected no typosquat match for %q, got false positive %q", fp.name, match)
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
		if match, ok := closestPopularMatch(fp.modPath, fp.name); ok {
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

func TestCheckAll_LocalReplacementSkipped(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "micron-parser-go", Version: "v0.0.0"}}
	reps := []Replacement{{Old: "micron-parser-go", New: "./third_party/micron"}}
	findings := CheckAll(reqs, reps, nil, proxy)
	if len(findings) != 0 {
		t.Fatalf("expected a locally-replaced requirement to produce no findings, got %+v", findings)
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

func TestCheckAll_UnreplacedRequirementStillChecked(t *testing.T) {
	proxy := fakeProxy(t, nil)
	reqs := []Requirement{{Path: "github.com/totally/madeup-pkg-xyz", Version: "v0.0.0"}}
	findings := CheckAll(reqs, nil, nil, proxy)
	if len(findings) != 1 || findings[0].Reason != "not-found" {
		t.Fatalf("expected the not-found finding to survive with no replacements, got %+v", findings)
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
	_, ok := closestPopularMatch(longName, longName)
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
	if match, ok := closestPopularMatch("github.com/example/consol", "consol"); !ok {
		t.Fatal("expected a match: \"consol\" is exactly typoMinNameLen (6) and one edit from popular \"consul\"")
	} else if !strings.Contains(match, "consul") {
		t.Errorf("expected match to reference consul, got %q", match)
	}

	// One character shorter (5, below typoMinNameLen) and otherwise the
	// same shape must NOT match, even though it's still one edit away.
	if match, ok := closestPopularMatch("github.com/example/consu", "consu"); ok {
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
	if match, ok := closestPopularMatch("github.com/example/fsnotifyab", "fsnotifyab"); !ok {
		t.Error("expected a match: \"fsnotifyab\" is exactly typoMaxDistance longer than popular \"fsnotify\", not past the prefilter cutoff")
	} else if !strings.Contains(match, "fsnotify") {
		t.Errorf("expected match to reference fsnotify, got %q", match)
	}

	// Candidate 2 chars *shorter* than the popular name (diff = -2).
	if match, ok := closestPopularMatch("github.com/example/contanrd", "contanrd"); !ok {
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

// TestClosestPopularMatch_SameBaseNameDifferentOrgNotFlagged pins the
// `d > 0` guard in closestPopularMatch's scoring loop (found LIVED by
// mutation testing, run #127). Two earlier attempts at this test were
// wrong: (1) reusing a popularModules pair sharing a short base name
// ("text", "mock") never even reaches this guard, typoMinNameLen=6
// filters those out first; (2) reusing modPath values that are
// themselves literal popularModules entries (the real
// invopop/jsonschema vs santhosh-tekuri/jsonschema/v6 pair) gets
// masked by the separate p==modPath early-return once the loop
// reaches that same entry, regardless of the mutation — confirmed by
// hand-mutating `d > 0` to `d >= 0` locally and seeing that version
// still pass. What actually isolates and kills this mutant: a
// candidate under a fake third-party org whose base name exactly
// matches a real popular module's — "docker" was chosen (over
// "jsonschema") because a same-named "gojsonschema" is already a
// genuine 2-edit typo match for "jsonschema" and contaminates the
// result via the ordinary typo path before this guard even matters.
// Verified against a hand-mutated `d >= 0` build that this construction
// does flip ok from false to true.
func TestClosestPopularMatch_SameBaseNameDifferentOrgNotFlagged(t *testing.T) {
	if got, ok := closestPopularMatch("github.com/example/docker", "docker"); ok {
		t.Errorf("github.com/example/docker should not be flagged as a collision risk against github.com/docker/docker purely for having an identical (0-edit) base name, got %q", got)
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
