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
