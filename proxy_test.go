package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
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
		got, ok := escapeModulePath(in)
		if !ok {
			t.Errorf("escapeModulePath(%q) ok = false, want true", in)
			continue
		}
		if got != want {
			t.Errorf("escapeModulePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEscapeModulePathRejectsBang guards against a real, live-confirmed
// bug (run #462): a literal "!" is a valid, unreserved URL path character
// (RFC 3986), so Go's HTTP client sends it through unescaped rather than
// percent-encoding it — but "!" is also the real Go module proxy's own
// escape meta-character (golang.org/x/mod/module's unescapeString), which
// decodes "!" followed by a lowercase letter into that letter's uppercase
// form. Before this fix, escapeModulePath passed a literal "!" straight
// through, so a corrupted/adversarial go.mod requirement like
// "github.com/foo!bar" silently became a proxy query for
// "github.com/fooBar" once the real proxy server decoded it — a
// completely different, unrelated module never named in the go.mod, with
// every resulting Finding still mislabeled under the original,
// uninspected path. Confirmed live against a mock server that implements
// the real proxy's own module.UnescapePath decode algorithm.
// escapeModulePath must instead report ok=false so callers skip the
// network round-trip rather than risk querying under a silently
// different path — module.CheckPath rejects "!" in a real module path
// outright, so this can never be a legitimate module reference to begin
// with.
func TestEscapeModulePathRejectsBang(t *testing.T) {
	cases := []string{
		"github.com/foo!bar",
		"!",
		"github.com/!!doublebang",
		"ends!with!bangs!",
	}
	for _, in := range cases {
		if _, ok := escapeModulePath(in); ok {
			t.Errorf("escapeModulePath(%q) ok = true, want false (contains a literal '!', which can never round-trip through the real proxy's own escaping scheme)", in)
		}
	}
}

// TestEscapeModulePathRejectsControlCharacters is a real, live-confirmed
// regression (run #490): a go.mod require/replace line's path or version
// can carry an ASCII control byte via a quoted string's own escape syntax
// (e.g. `"github.com\tfoo/bar"` — an ordinary two-character `\t` escape
// sequence in the go.mod file on disk, no literal control byte anywhere in
// the file itself) that gomod.go's leadingQuotedString correctly decodes
// via strconv.Unquote into a real embedded tab byte, exactly the way a
// real `go.mod` parser would too. module.CheckPath rejects every one of
// these bytes in a real module path (confirmed live: tab, CR, NUL, and DEL
// all produce "malformed module path ...: invalid char ..."), so no real
// go.mod could ever carry one — but a corrupted/adversarial one can, and
// that's this tool's whole threat model. Before this fix, escapeModulePath
// let a control byte straight through, and Go's own net/url rejected the
// resulting request URL outright ("invalid control character in URL") —
// an error Lookup/VersionExists both treat identically to a transient
// proxy outage (Unknown), silently suppressing any finding at all for a
// go.mod requirement that cannot possibly build under the real go
// toolchain (confirmed live, GOPROXY=off included: `go list -m all`
// Fatals immediately with the same "malformed module path" error, never
// touching the network).
func TestEscapeModulePathRejectsControlCharacters(t *testing.T) {
	cases := []string{
		"github.com/foo\tbar",
		"github.com/foo\rbar",
		"github.com/foo\x00bar",
		"github.com/foo\x7fbar",
		"\n",
	}
	for _, in := range cases {
		if _, ok := escapeModulePath(in); ok {
			t.Errorf("escapeModulePath(%q) ok = true, want false (contains an ASCII control byte, which real net/url rejects with \"invalid control character in URL\" rather than a clean 404)", in)
		}
	}
}

// TestProxyClientLookupControlCharacterInPathReportsNotFound is the
// end-to-end regression for the same bug: a control byte embedded in a
// module path must make Lookup report Exists=false (the same "definitely
// not a real module reference" outcome the "!" guard already produces),
// not Unknown — Unknown suppresses every finding downstream
// (evaluateModuleStatus's "network/proxy trouble, say nothing" case),
// which is the wrong outcome for a deterministic, always-reproducing
// client-side failure caused entirely by the untrusted go.mod content,
// not a maybe-transient server-side one.
func TestProxyClientLookupControlCharacterInPathReportsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Lookup must reject a control-character path before ever making a network request")
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("github.com/foo\tbar")
	if status.Unknown {
		t.Errorf("Lookup(%q) = %+v, want Unknown=false (a control byte can never be part of a real module path, so this must be treated as definitively nonexistent, not as ambiguous network trouble)", "github.com/foo\tbar", status)
	}
	if status.Exists {
		t.Errorf("Lookup(%q) = %+v, want Exists=false", "github.com/foo\tbar", status)
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

// TestProxyClientLookupBangInPathNeverQueriesADifferentModule is a real,
// live-confirmed regression (run #462): a go.mod requirement path
// containing a literal "!" (unreachable from a go.mod the real `go`
// toolchain would ever accept — module.CheckPath rejects "!" outright —
// but reachable from a corrupted or adversarial one, exactly this tool's
// threat model, since gomod.go's parser applies no character validation)
// must never cause Lookup to silently resolve a *different* module.
//
// "!" is a valid, unreserved URL path character (RFC 3986), so Go's own
// HTTP client sends it through unescaped rather than percent-encoding it
// — but "!" is also the real module proxy's own escape meta-character
// (golang.org/x/mod/module's unescapeString decodes "!" followed by a
// lowercase letter into that letter's uppercase form). Before this fix,
// escapeModulePath passed a literal "!" straight through, so a request
// for "github.com/foo!bar" arrived at the real proxy unmodified and got
// server-side-decoded as "github.com/fooBar" — confirmed live against
// module.UnescapePath directly. This test's fake server implements that
// same real decode algorithm, so if escapeModulePath's ok=false guard
// were removed, this test would start hitting the fooBarExists branch
// below and fail.
func TestProxyClientLookupBangInPathNeverQueriesADifferentModule(t *testing.T) {
	fooBarExists := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mirror the real proxy.golang.org server: decode the escaped
		// module path segment using the real x/mod escaping algorithm
		// before deciding what to serve.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if i := strings.Index(p, "/@"); i >= 0 {
			if decoded, err := module.UnescapePath(p[:i]); err == nil && decoded == "github.com/fooBar" {
				fooBarExists = true
				_, _ = w.Write([]byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("github.com/foo!bar")

	if fooBarExists {
		t.Fatal("BUG: the request for github.com/foo!bar was decoded server-side as github.com/fooBar — a different module never named in the go.mod")
	}
	if status.Exists {
		t.Errorf("Lookup(%q) = %+v, want Exists=false (a literal '!' can never be part of a real module path, so this must be treated as nonexistent without ever querying the network under a silently different path)", "github.com/foo!bar", status)
	}
}

// TestProxyClientVersionExists is a regression test for a real,
// live-confirmed gap (2026-09): modslop's Lookup only ever checks a
// module *path*'s existence (@latest, @v/list), never whether the
// *specific version* a go.mod actually requires was ever published.
// Confirmed live against proxy.golang.org: github.com/gorilla/mux (a
// real, popular, long-established module that has never gone past
// v1.8.x) 404s at /@v/v3.5.0.info, while its real v1.8.1 tag resolves
// 200 at /@v/v1.8.1.info — a completely fabricated version number of an
// otherwise-real module, exactly the shape of an AI-hallucinated version
// bump, sailed through every other check with zero findings before this
// method existed (the module itself is old and multi-version enough to
// clear new-and-thin/version-flooded).
func TestProxyClientVersionExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github.com/gorilla/mux/@v/v1.8.1.info":
			_, _ = w.Write([]byte(`{"Version":"v1.8.1","Time":"2023-10-18T11:23:00Z"}`))
		case "/github.com/gorilla/mux/@v/v3.5.0.info":
			w.WriteHeader(http.StatusNotFound)
		case "/github.com/gorilla/mux/@v/v9.9.9.info":
			w.WriteHeader(http.StatusGone) // 410, same "definitely doesn't exist" signal as 404
		case "/github.com/gorilla/mux/@v/v0.0.0.info":
			w.WriteHeader(http.StatusInternalServerError) // ambiguous — must not be treated as "doesn't exist"
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	if exists, unknown := c.VersionExists("github.com/gorilla/mux", "v1.8.1"); !exists || unknown {
		t.Errorf("VersionExists(real tag) = (%v, %v), want (true, false)", exists, unknown)
	}
	if exists, unknown := c.VersionExists("github.com/gorilla/mux", "v3.5.0"); exists || unknown {
		t.Errorf("VersionExists(fabricated version, 404) = (%v, %v), want (false, false)", exists, unknown)
	}
	if exists, unknown := c.VersionExists("github.com/gorilla/mux", "v9.9.9"); exists || unknown {
		t.Errorf("VersionExists(fabricated version, 410) = (%v, %v), want (false, false)", exists, unknown)
	}
	if exists, unknown := c.VersionExists("github.com/gorilla/mux", "v0.0.0"); exists || !unknown {
		t.Errorf("VersionExists(server error) = (%v, %v), want (false, true) — a transient error must never be reported as version-not-found", exists, unknown)
	}
}

func TestProxyClientVersionExistsTransportError(t *testing.T) {
	c := &ProxyClient{BaseURL: "not-a-url://\x00", HTTP: &http.Client{}}
	if exists, unknown := c.VersionExists("example.com/foo", "v1.0.0"); exists || !unknown {
		t.Errorf("VersionExists on transport error = (%v, %v), want (false, true)", exists, unknown)
	}
}

func TestParseComparisonQuery(t *testing.T) {
	cases := []struct {
		version    string
		wantOp     string
		wantTarget string
		wantOK     bool
	}{
		{"<v1.2.3", "<", "v1.2.3", true},
		{"<=v1.2.3", "<=", "v1.2.3", true},
		{">v1.2.3", ">", "v1.2.3", true},
		{">=v1.2.3", ">=", "v1.2.3", true},
		// A literal version, a plain prefix query, and a revision
		// identifier are all NOT comparison queries.
		{"v1.2.3", "", "", false},
		{"v1.2", "", "", false},
		{"master", "", "", false},
		{"", "", "", false},
		// ">=" must not be misparsed as ">" with a bogus "=v1.2.3" target
		// (caught by the semver.IsValid guard either way, but the operator
		// list order is what avoids relying on that fallback).
		{">=v0.9.0", ">=", "v0.9.0", true},
		{"<=v0.9.0", "<=", "v0.9.0", true},
	}
	for _, c := range cases {
		op, target, ok := parseComparisonQuery(c.version)
		if ok != c.wantOK || (ok && (op != c.wantOp || target != c.wantTarget)) {
			t.Errorf("parseComparisonQuery(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.version, op, target, ok, c.wantOp, c.wantTarget, c.wantOK)
		}
	}
}

// TestIsAmbiguousComparisonQuery is the regression test for
// isAmbiguousComparisonQuery: real cmd/go's own newQueryMatcher
// (modload/query.go) Fatals a "<=" or ">" comparison query at go.mod parse
// time, before ever contacting the network, whenever its operand is an
// incomplete ("prefix") version — bare major or major.minor, missing the
// patch component — because it refuses to guess whether the bound means
// exactly vX.Y(.0) or the whole vX.Y.* line. Confirmed live, 2026-09
// (go1.24.4, real proxy.golang.org): `require github.com/pkg/errors <=v0.9`
// and `require github.com/pkg/errors >v0` both make `go build`/`go list -m
// all` fail immediately with "ambiguous semantic version \"v0.9\" in range
// \"<=v0.9\"" / "... \"v0\" in range \">v0\"" — while the identical operand
// shape under "<" or ">=" (confirmed live to be unambiguous either way)
// resolves fine (to v0.8.1 / v0.9.0 respectively), and a fully-qualified
// major.minor.patch operand under "<=" or ">" (even with a pre-release
// suffix, e.g. "v0.9.0-rc1") also resolves fine under every operator.
func TestIsAmbiguousComparisonQuery(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"<=v0.9", true},
		{">v0", true},
		{"<=v1", true},
		{">v1.2", true},
		// Unambiguous: "<" and ">=" never need to guess which end of the
		// missing components to assume.
		{"<v0.9", false},
		{">=v0.9", false},
		{"<v0", false},
		{">=v1.2", false},
		// Unambiguous: a fully-qualified major.minor.patch operand, with or
		// without a pre-release/build suffix, is never a "prefix" version.
		{"<=v0.9.0", false},
		{">v0.9.0", false},
		{"<=v0.9.0-rc1", false},
		{">v1.2.3+build5", false},
		// Not a comparison query at all.
		{"v0.9", false},
		{"v1.2.3", false},
		{"master", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isAmbiguousComparisonQuery(c.version); got != c.want {
			t.Errorf("isAmbiguousComparisonQuery(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

// TestProxyClientVersionExistsComparisonQuery is the regression test for a
// real, live-confirmed gap (2026-09): a go.mod require directive's version
// doesn't have to be a literal tag — golang.org/x/mod/modfile.Parse (and the
// real go command) also accept a comparison-operator version query like
// "<v1.2.3" per go.dev/ref/mod#version-queries, which real go resolves
// against the module's *tagged version list* — "the nearest available
// version to the comparison target (the lowest version for > and >=, and
// the highest version for < and <=)" — never by querying
// proxy.golang.org's @v/<version>.info endpoint with the literal query
// string. Confirmed live: .../@v/%3Cv1.0.0.info (the properly-escaped form
// of "<v1.0.0") 404s with "invalid char '<'", and a real modslop binary
// built from the pre-fix source reported a high-severity "version-not-found"
// against `require github.com/pkg/errors <v1.0.0` — a real, valid go.mod
// requirement the actual go toolchain resolves to v0.9.1 without any build
// error (confirmed live with `go build`/`go mod tidy`).
func TestProxyClientVersionExistsComparisonQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/foo/@v/list":
			_, _ = w.Write([]byte("v0.7.0\nv0.8.0\nv0.8.1\nv0.9.0\nv0.9.1\n"))
		case "/example.com/foo/@v/v0.9.1.info":
			_, _ = w.Write([]byte(`{"Version":"v0.9.1","Time":"2023-10-18T11:23:00Z"}`))
		case "/example.com/foo/@v/v0.8.1.info":
			_, _ = w.Write([]byte(`{"Version":"v0.8.1","Time":"2023-01-01T00:00:00Z"}`))
		case "/example.com/foo/@v/v0.9.0.info":
			_, _ = w.Write([]byte(`{"Version":"v0.9.0","Time":"2023-06-01T00:00:00Z"}`))
		case "/example.com/nolist/@v/list":
			w.WriteHeader(http.StatusNotFound)
		case "/example.com/broken/@v/list":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	cases := []struct {
		name        string
		modPath     string
		version     string
		wantExists  bool
		wantUnknown bool
	}{
		// "<v1.0.0": highest tag below v1.0.0 is v0.9.1 — matches the live
		// `go list -m github.com/pkg/errors@'<v1.0.0'` result exactly.
		{"less-than resolves to highest below target", "example.com/foo", "<v1.0.0", true, false},
		// "<=v0.9.0": highest tag at-or-below v0.9.0 is v0.9.0 itself, not
		// v0.9.1 (which is above it).
		{"less-equal resolves to exact tag", "example.com/foo", "<=v0.9.0", true, false},
		// ">v0.8.0": lowest tag *above* v0.8.0 is v0.8.1 — confirmed live
		// this is NOT the module's overall highest tag (v0.9.1); real go
		// picks the nearest match, not the highest available.
		{"greater-than resolves to nearest above target", "example.com/foo", ">v0.8.0", true, false},
		// ">=v0.9.0": lowest tag at-or-above v0.9.0 is v0.9.0 itself.
		{"greater-equal resolves to exact tag", "example.com/foo", ">=v0.9.0", true, false},
		// No tag satisfies "<v0.0.1" (nothing published that old) or
		// ">v99.0.0" — deterministically unresolvable, same as a literal
		// fabricated version, not network trouble.
		{"less-than with no match", "example.com/foo", "<v0.0.1", false, false},
		{"greater-than with no match", "example.com/foo", ">v99.0.0", false, false},
		// A module with no tags at all has nothing for a comparison query
		// to match either — still deterministic, not "unknown".
		{"no tags at all", "example.com/nolist", "<v1.0.0", false, false},
		// A genuine proxy error while fetching the version list must stay
		// "unknown" — never reported as version-not-found.
		{"proxy error fetching list", "example.com/broken", "<v1.0.0", false, true},
	}
	for _, c2 := range cases {
		t.Run(c2.name, func(t *testing.T) {
			exists, unknown := c.VersionExists(c2.modPath, c2.version)
			if exists != c2.wantExists || unknown != c2.wantUnknown {
				t.Errorf("VersionExists(%q, %q) = (%v, %v), want (%v, %v)",
					c2.modPath, c2.version, exists, unknown, c2.wantExists, c2.wantUnknown)
			}
		})
	}
}

// TestProxyClientResolveVersionComparisonQuery mirrors
// TestProxyClientVersionExistsComparisonQuery for ResolveVersion, used by
// checkExcludedRequirements — a comparison query on either side of a
// require/exclude pair must resolve to the same concrete tagged version
// VersionExists would, not 404 against the literal query string.
func TestProxyClientResolveVersionComparisonQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/foo/@v/list":
			_, _ = w.Write([]byte("v0.8.0\nv0.8.1\nv0.9.0\nv0.9.1\n"))
		case "/example.com/foo/@v/v0.8.1.info":
			_, _ = w.Write([]byte(`{"Version":"v0.8.1","Time":"2023-01-01T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	resolved, ok := c.ResolveVersion("example.com/foo", ">v0.8.0")
	if !ok || resolved != "v0.8.1" {
		t.Errorf(`ResolveVersion(">v0.8.0") = (%q, %v), want ("v0.8.1", true)`, resolved, ok)
	}

	if _, ok := c.ResolveVersion("example.com/foo", ">v99.0.0"); ok {
		t.Error(`ResolveVersion(">v99.0.0") ok = true, want false (no tag satisfies the query)`)
	}
}

// TestProxyClientVersionExistsLatestNamedQuery is the regression test for a
// real, live-confirmed gap (2026-10): a go.mod require/exclude directive's
// version field can carry the literal go.dev/ref/mod#version-queries named
// query "latest" (or "upgrade", which resolves identically here — see
// resolveLatestQuery's own doc comment) instead of a tag. Confirmed live,
// go1.24.4: `go mod tidy` on a scratch module with `require
// github.com/pkg/errors latest` rewrites the line to v0.9.1 without any
// build error, yet proxy.golang.org's own .../@v/latest.info 404s with
// "not found: invalid version" — a real modslop binary built from the
// pre-fix source reported this exact, successfully-buildable go.mod's
// requirement as a high-severity "version-not-found", indistinguishable
// from an actually-hallucinated version.
func TestProxyClientVersionExistsLatestNamedQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/foo/@latest":
			_, _ = w.Write([]byte(`{"Version":"v0.9.1","Time":"2023-10-18T11:23:00Z"}`))
		case "/example.com/foo/@v/v0.9.1.info":
			_, _ = w.Write([]byte(`{"Version":"v0.9.1","Time":"2023-10-18T11:23:00Z"}`))
		case "/example.com/broken/@latest":
			w.WriteHeader(http.StatusInternalServerError)
		case "/example.com/gone/@latest":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	for _, q := range []string{"latest", "upgrade"} {
		if exists, unknown := c.VersionExists("example.com/foo", q); !exists || unknown {
			t.Errorf("VersionExists(%q) = (%v, %v), want (true, false)", q, exists, unknown)
		}
	}
	if _, unknown := c.VersionExists("example.com/broken", "latest"); !unknown {
		t.Error(`VersionExists("latest") on a proxy error should report unknown=true, never a false version-not-found`)
	}
	if exists, unknown := c.VersionExists("example.com/gone", "latest"); exists || unknown {
		t.Errorf(`VersionExists("latest") on a 404'd module = (%v, %v), want (false, false)`, exists, unknown)
	}
}

// TestProxyClientResolveVersionLatestNamedQuery mirrors
// TestProxyClientVersionExistsLatestNamedQuery for ResolveVersion, used by
// checkExcludedRequirements — an `exclude module latest` that names the
// same real release an exact-version `require` line pins must resolve to
// the identical canonical tag, so the self-contradiction is actually
// caught. Confirmed live: a go.mod with both `require github.com/pkg/
// errors v0.9.1` and `exclude github.com/pkg/errors latest` makes `go
// build` Fatal with "ignoring requirement on excluded version
// github.com/pkg/errors v0.9.1" — before this fix, modslop's
// checkExcludedRequirements reported "nothing flagged" instead, since
// ResolveVersion("latest") failed to resolve at all.
func TestProxyClientResolveVersionLatestNamedQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/foo/@latest":
			_, _ = w.Write([]byte(`{"Version":"v0.9.1","Time":"2023-10-18T11:23:00Z"}`))
		case "/example.com/foo/@v/v0.9.1.info":
			_, _ = w.Write([]byte(`{"Version":"v0.9.1","Time":"2023-10-18T11:23:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	resolved, ok := c.ResolveVersion("example.com/foo", "latest")
	if !ok || resolved != "v0.9.1" {
		t.Errorf(`ResolveVersion("latest") = (%q, %v), want ("v0.9.1", true)`, resolved, ok)
	}
	resolved, ok = c.ResolveVersion("example.com/foo", "upgrade")
	if !ok || resolved != "v0.9.1" {
		t.Errorf(`ResolveVersion("upgrade") = (%q, %v), want ("v0.9.1", true)`, resolved, ok)
	}
}

// TestProxyClientResolveComparisonQueryDoesNotSkipRetracted is a regression
// test for resolveComparisonQuery (proxy.go): a retracted candidate MUST
// win a comparison query when it's the nearest raw-semver match, the same
// way real go resolves a version query already written into an on-disk
// go.mod. A prior rotation's fix made this function skip retracted
// candidates, modeling `go get`/`go list -m module@query`'s own interactive
// CheckRetractions filtering — but that's the wrong cmd/go code path for
// what this function actually needs to mirror. Confirmed live, 2026-10-01
// (go1.24.4, real proxy.golang.org): a go.mod literally containing `require
// github.com/mattn/go-sqlite3 <v3.0.0` (go.mod retracts
// [v2.0.0+incompatible, v2.0.7+incompatible]), loaded with `go list -m all`
// (reproduced under both -mod=readonly and -mod=mod, GOSUMDB=off, no
// pre-existing go.sum), resolves to v2.0.3+incompatible — squarely inside
// the retracted range, not past it to v1.14.52 the way a bare `go get
// module@'<v3.0.0'` command-line query does. `go list -m -u -retracted`
// confirms the result is Retracted. See resolveComparisonQuery's own doc
// comment for the full live-reproduction detail.
func TestProxyClientResolveComparisonQueryDoesNotSkipRetracted(t *testing.T) {
	const module = "example.com/retracttest"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = w.Write([]byte("v1.0.0\nv1.2.0\nv1.3.0\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	resolved, unknown := c.resolveComparisonQuery(module, "<", "v2.0.0")
	if unknown || resolved != "v1.3.0" {
		t.Errorf(`resolveComparisonQuery(%q, "<", "v2.0.0") = (%q, %v), want ("v1.3.0", false) — the nearest-below match, even though it would be retracted, matches real go's own retraction-blind go.mod-query resolution`, module, resolved, unknown)
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

// TestProxyClientLookupSkipsHigherSortingPrereleaseForRetraction
// reproduces the real google.golang.org/grpc module's tagging shape: its
// v1.x line carries ordinary release tags alongside a "-dev" pre-release
// tag cut ahead of the next release, whose minor number (and therefore
// raw semver ordering) is already higher than the actual latest release —
// confirmed live, 2026-09: v1.86.0-dev sorts above the real latest release
// v1.84.0, yet real `go list -m -retracted google.golang.org/grpc@latest`
// (go1.24.4, live proxy) resolves to v1.84.0, never v1.86.0-dev, matching
// go.dev/ref/mod#version-queries' "release versions are preferred over
// pre-release versions" rule. Before this fix, Lookup's "highest tag in
// this major line" search used plain semver.Compare with no release/
// pre-release distinction, so it would walk modVersion past the real
// release (v1.84.0, whose go.mod actually carries the retract directive)
// up to the higher-sorting v1.86.0-dev pre-release (whose go.mod has none)
// — losing the one real retraction a go.mod requiring the retracted
// version needed to be flagged for.
func TestProxyClientLookupSkipsHigherSortingPrereleaseForRetraction(t *testing.T) {
	const releaseModBody = "module google.golang.org/grpc\n\ngo 1.21\n\nretract v1.83.0 // Published accidentally.\n"
	const devModBody = "module google.golang.org/grpc\n\ngo 1.21\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v1.84.0","Time":"2026-09-17T20:03:25Z"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.84.0.mod"):
			_, _ = w.Write([]byte(releaseModBody))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.86.0-dev.mod"):
			_, _ = w.Write([]byte(devModBody))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			// Real @v/list order for this module: not sorted, releases and
			// "-dev" pre-releases interleaved, exactly as proxy.golang.org
			// actually returns it.
			_, _ = w.Write([]byte("v1.83.0\nv1.83.0-dev\nv1.84.0\nv1.84.0-dev\nv1.85.0-dev\nv1.86.0-dev\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("google.golang.org/grpc")

	if status.LatestModBody != releaseModBody {
		t.Errorf("LatestModBody = %q, want the real latest release's (v1.84.0's) go.mod body %q, not the higher-sorting v1.86.0-dev pre-release's", status.LatestModBody, releaseModBody)
	}

	if rationale, retracted := retraction(status.LatestModBody, "v1.83.0"); !retracted {
		t.Errorf("retraction(LatestModBody, %q) = (%q, false), want retracted=true", "v1.83.0", rationale)
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

// TestProxyClientLookupEscapesVersionForModBodyFetch exercises the
// escaping fix's other leg (see TestProxyClientLookupEscapesVersionFor-
// SingleTagFetch's/-EarliestTagFetch's identical rationale) in the
// modVersion/retraction-go.mod fetch specifically: when a major line has
// shipped no full release at all yet — only release-candidate
// pre-releases, a normal shape while a new major version is still in
// development, the same "-RC"-style naming apache/beam uses for its own
// in-progress releases (see the sibling escaping tests) — go.dev/ref/
// mod#version-queries' fallback rule ("If there are no release versions,
// latest selects the highest pre-release version") makes that pre-release
// tag the correct target for both @latest and the "-retracted" variant
// go.dev/ref/mod#go-mod-file-retract has the go command load retract
// directives from, so its .mod fetch still needs the same $version
// escaping @latest's own non-pre-release fetches do.
//
// This test previously used github.com/apache/beam's real v2 line
// (highest tag v2.77.0-RC2+incompatible, alongside the real release
// v2.76.0+incompatible) as its fixture, on the assumption that the
// pre-release tag was the correct retraction-fetch target purely for
// being the highest tag overall. That assumption was never actually
// verified against real go — confirmed live, 2026-09, that it's false:
// `go list -m -retracted github.com/apache/beam@latest` (go1.24.4, live
// proxy) resolves to v2.76.0+incompatible, the release, never the
// higher-sorting v2.77.0-RC2+incompatible pre-release, per the release-
// preferred-over-prerelease rule this run's fix now applies (see
// TestProxyClientLookupSkipsHigherSortingPrereleaseForRetraction). Since
// a real release version's numeric core can never itself contain a
// letter (Go's only source of an uppercase letter in a *release* tag is
// build metadata like "+incompatible", which real go tooling only ever
// lowercases), the modVersion-fetch escaping path can only still be
// exercised by a pre-release tag in the one shape where a pre-release
// really is the correct selection: no release tag anywhere in the major
// line. The fixture below models that shape with a synthetic scratch
// module rather than a real one, since no currently-tagged real module
// was found in exactly this pre-release-only-major-line state.
func TestProxyClientLookupEscapesVersionForModBodyFetch(t *testing.T) {
	const modBody = "module example.com/inprogress/v2\n\ngo 1.21\n\nretract v2.0.0-RC1 // Bad release candidate.\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v2.0.0-RC2","Time":"2026-08-21T12:48:32Z"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = w.Write([]byte("v2.0.0-RC1\nv2.0.0-RC2\n"))
		case strings.HasSuffix(r.URL.Path, "/@v/v2.0.0-!r!c2.mod"):
			_, _ = w.Write([]byte(modBody))
		case strings.HasSuffix(r.URL.Path, "/@v/v2.0.0-RC2.mod"):
			t.Errorf("Lookup fetched the .mod URL with an unescaped version %q — the real proxy would 404 this", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/inprogress/v2")

	if status.LatestModBody != modBody {
		t.Errorf("LatestModBody = %q, want the escaped-version fetch's body %q", status.LatestModBody, modBody)
	}
}

// TestProxyClientLookupEscapesVersionForSingleTagFetch is the same
// escaping gap in TestProxyClientLookupUsesTagTimeNotPseudoVersionTime's
// code path: the sole tag of a single-tag module can itself carry an
// uppercase letter (e.g. a project's only release so far is an RC), and
// the info fetch used to look up its real timestamp needs the same
// escaping as any other version.
func TestProxyClientLookupEscapesVersionForSingleTagFetch(t *testing.T) {
	const tagTime = "2026-04-07T20:18:58Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v0.0.0-20260917194416-dc69727f248e","Time":"2026-09-17T19:44:16Z"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = w.Write([]byte("v1.0.0-RC1\n"))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0-!r!c1.info"):
			_, _ = w.Write([]byte(`{"Version":"v1.0.0-RC1","Time":"` + tagTime + `"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0-RC1.info"):
			t.Errorf("Lookup fetched the single-tag .info URL with an unescaped version %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/onlyrc")

	wantTime, _ := time.Parse(time.RFC3339, tagTime)
	if !status.LatestTime.Equal(wantTime) {
		t.Errorf("LatestTime = %v, want the escaped-version tag fetch's time %v", status.LatestTime, wantTime)
	}
}

// TestProxyClientLookupEscapesVersionForEarliestTagFetch is the same
// escaping gap in TestProxyClientLookupEarliestTimeUsesSemverNotListOrder's
// code path: the semver-earliest tag among several is often a project's
// very first prerelease, which commonly carries an uppercase letter
// (e.g. "-RC1"), and needs the same version escaping the other two fetch
// sites do.
func TestProxyClientLookupEscapesVersionForEarliestTagFetch(t *testing.T) {
	const earliestTime = "2026-07-21T07:45:05Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v1.3.1","Time":"2026-09-02T08:21:59Z"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			_, _ = w.Write([]byte("v1.3.1\nv1.0.0-RC1\n"))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0-!r!c1.info"):
			_, _ = w.Write([]byte(`{"Version":"v1.0.0-RC1","Time":"` + earliestTime + `"}`))
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0-RC1.info"):
			t.Errorf("Lookup fetched the earliest-tag .info URL with an unescaped version %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}
	status := c.Lookup("example.com/earlyrc")

	wantEarliest, _ := time.Parse(time.RFC3339, earliestTime)
	if !status.EarliestTime.Equal(wantEarliest) {
		t.Errorf("EarliestTime = %v, want the escaped-version tag fetch's time %v", status.EarliestTime, wantEarliest)
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

// TestIsMajorVersionBumpOfEstablishedWalksBackPastThinPredecessor is a
// real-world regression: checking only the immediate predecessor major
// version isn't enough for a project that cuts major-version bumps
// unusually often, since the immediate predecessor can itself still be
// within recentWindow. Confirmed live, 2026-09-27, against
// github.com/google/go-github (a decade-old, widely used GitHub API
// client — a direct dependency of both cilium/cilium's and
// go-gitea/gitea's real go.mod files, found by running modslop against
// both): it cuts a new major version for essentially every breaking API
// change, roughly monthly. At the time of this test, v92 (the current
// major, published 2026-09-14) has exactly one tagged version; so does
// its immediate predecessor v91 (published 2026-09-03, only 24 days
// before v92 — still inside recentWindow); only v90 (published
// 2026-08-04, 54 days before) is old enough to clear the plain
// recentWindow test on its own. Before this fix,
// IsMajorVersionBumpOfEstablished looked at v91 alone, found it exists
// but is itself thin/recent, and gave up — reporting no evidence of an
// established project, so `modslop` flagged a real go.mod requiring
// github.com/google/go-github/v92 with a high-confidence-sounding
// "new-and-thin" warning on a package that's neither new nor thin, just
// fast-moving about major-version bumps. This test reproduces the exact
// three-major-version shape (checked major thin, immediate predecessor
// also thin, one further back established) against a fake proxy so it
// doesn't depend on go-github's real tags still matching this shape by
// the time this test runs again.
func TestIsMajorVersionBumpOfEstablishedWalksBackPastThinPredecessor(t *testing.T) {
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/example.com/fastmover/v91/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v91.0.0","Time":"` + now.Add(-24*time.Hour).Format(time.RFC3339) + `"}`))
		case strings.HasPrefix(r.URL.Path, "/example.com/fastmover/v91/@v/list"):
			_, _ = w.Write([]byte("v91.0.0\n"))
		case strings.HasPrefix(r.URL.Path, "/example.com/fastmover/v90/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v90.0.0","Time":"` + now.Add(-54*24*time.Hour).Format(time.RFC3339) + `"}`))
		case strings.HasPrefix(r.URL.Path, "/example.com/fastmover/v90/@v/list"):
			_, _ = w.Write([]byte("v90.0.0\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	if !c.IsMajorVersionBumpOfEstablished("example.com/fastmover/v92") {
		t.Error("want true: v91 is itself thin/recent, but v90 two steps back is established — should walk back past a thin immediate predecessor rather than giving up on it")
	}
}

// TestIsMajorVersionBumpOfEstablished_IncompatiblePredecessorHasNoSuffixedPath
// is a real-world regression: predecessorMajorPath always builds an
// explicit "prefix+sep+m" path for a major version m >= 2, but Go's own
// "+incompatible" convention (go.dev/ref/mod#incompatible-versions) lets a
// pre-Go-modules project keep tagging v2, v3, ... releases under its
// *original, unsuffixed* import path forever, as long as it never
// published a go.mod requiring the suffix — the explicit "/vN" path for
// that major is never created at all in that case. Confirmed live,
// 2026-09-29, against two real, long-established, widely-used modules
// that made exactly this transition: github.com/go-redis/redis/v7's
// immediate predecessor, github.com/go-redis/redis/v6, 404s on the real
// proxy ("invalid version: missing .../v6/go.mod at revision v6.15.9") —
// the real v6 history (v6.15.9+incompatible, tagged 2020) lives unsuffixed
// at github.com/go-redis/redis instead, which resolves fine; same shape
// for github.com/labstack/echo/v4 and its v3 predecessor. Calling
// IsMajorVersionBumpOfEstablished directly against the real, live proxy
// confirmed both github.com/go-redis/redis/v7 and github.com/labstack/
// echo/v4 came back false before this fix — treating two of the Go
// ecosystem's most established projects as having "no evidence" of a
// prior history, purely because their pre-Modules major was never given
// its own suffixed path. This test reproduces that exact shape (a 404 on
// the suffixed predecessor, real history sitting at the unsuffixed base
// path instead) against a fake proxy mirroring the real go-redis/echo
// shape, so it doesn't depend on either module's real tags still matching
// this shape by the time this test runs again.
func TestIsMajorVersionBumpOfEstablished_IncompatiblePredecessorHasNoSuffixedPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// example.com/legacyweb/v3 (the suffixed predecessor path) doesn't
		// exist at all — matching the real github.com/go-redis/redis/v6 and
		// github.com/labstack/echo/v3 404s — so every request under that
		// prefix falls through to the default 404 below.
		case strings.HasPrefix(r.URL.Path, "/example.com/legacyweb/@latest"):
			_, _ = w.Write([]byte(`{"Version":"v3.9.0+incompatible","Time":"2019-01-01T00:00:00Z"}`))
		case strings.HasPrefix(r.URL.Path, "/example.com/legacyweb/@v/list"):
			_, _ = w.Write([]byte("v1.0.0\nv2.0.0\nv3.0.0\nv3.9.0\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client()}

	if !c.IsMajorVersionBumpOfEstablished("example.com/legacyweb/v4") {
		t.Error("want true: v3 has real, established history, just published unsuffixed (+incompatible) at the base path instead of an explicit /v3 — a 404 on the suffixed predecessor path alone must not be treated as \"no evidence of an established project\"")
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
