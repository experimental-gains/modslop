package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

const proxyBaseURL = "https://proxy.golang.org"

// ProxyClient talks to a Go module proxy (proxy.golang.org by default)
// to answer two questions a hallucinated or freshly-squatted module
// can't fake: does this path resolve at all, and if so, how long has
// it existed?
type ProxyClient struct {
	BaseURL string
	HTTP    *http.Client

	// PrivatePatterns are GOPRIVATE/GONOPROXY-style glob patterns (see
	// matchesAnyPattern). A module path matching one is never looked up
	// on the public proxy — the real `go` command bypasses the proxy
	// for these paths too (see `go help goproxy`), so a 404 for one
	// carries no signal at all, positive or negative.
	PrivatePatterns []string
}

func NewProxyClient() *ProxyClient {
	return &ProxyClient{
		BaseURL: proxyBaseURL,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

type latestInfo struct {
	Version string
	Time    string
}

// ModuleStatus describes what the proxy knows about a module path.
type ModuleStatus struct {
	Exists       bool
	Unknown      bool // network/proxy error; caller should not treat as a finding
	Private      bool // matched GOPRIVATE/GONOPROXY; never queried, not a finding either
	Blocklisted  bool // proxy has explicitly flagged this module as malicious
	VersionCount int
	LatestTime   time.Time
	// EarliestTime is the publish time of the module's oldest tagged
	// version (semver-lowest, not list order — @v/list is not sorted).
	// Zero if VersionCount is 0 (no tags at all, see the VersionCount==0
	// comment in looksUnestablished) or the earliest-version fetch failed.
	EarliestTime time.Time
	// LatestModBody is the go.mod content of the highest tagged version in
	// modPath's *current* major-version line — not necessarily @latest's
	// own version (empty if the fetch failed). Real `go` finds retract
	// directives by loading go.mod from the version @latest would
	// resolve to *before* retractions are considered (go.dev/ref/mod#go-
	// mod-file-retract), which is the version this fetch targets — see
	// the divergence explained in Lookup. Not the specific version being
	// checked, so this is fetched once per module regardless of which
	// version(s) of it a go.mod actually requires. See retraction() in
	// retract.go.
	LatestModBody string
}

// proxyMalwareMarker is the distinctive substring proxy.golang.org's
// module mirror includes in the plain-text body of a 403 response when
// it has flagged a specific module as malicious (confirmed live, 2026-09,
// against three real GHSA-documented malicious modules: github.com/
// shopsprint/decimal, github.com/boltdb-go/bolt, github.com/xinfeisoft/
// crypto — all three return this exact text). A 403 can also happen for
// unrelated reasons (rate limiting, transient outages — see golang/go
// issues #48107, #71094, #80655, all against legitimate popular
// modules), so the status code alone isn't a safe signal; this text is.
const proxyMalwareMarker = "considers this module to be malicious"

// escapeModulePath implements the Go module proxy's escaped-path
// encoding: each uppercase letter is replaced with "!" followed by
// its lowercase form, since proxy URLs must be case-insensitive-safe
// on case-insensitive filesystems. See golang.org/ref/mod#module-proxy.
//
// The identical algorithm also applies to the $version path element,
// not just $module (golang.org/x/mod/module's EscapePath and
// EscapeVersion share the same underlying escapeString helper) — so
// this function is reused below for any version string interpolated
// into a proxy URL, not just module paths. Confirmed live, 2026-09:
// github.com/apache/beam's current v2 major-line tag is genuinely
// v2.77.0-RC2+incompatible (a real, live, in-the-wild example of a
// maintained module whose highest-ever tag in a major line is still an
// unescaped-uppercase prerelease) — fetching its .mod file with the
// version left unescaped 404s, while escaping "RC" to "!r!c" the same
// way a module path would be returns 200. Before this fix, every
// version-bearing proxy fetch in this file (the retraction check's
// go.mod, and both of the single-tag/earliest-tag info lookups below)
// used the version raw, so any of those could silently fail exactly
// when a module's relevant tag carries an uppercase letter.
//
// ok is false when path contains a literal "!". That's not just an
// unescaped character, it's the escape scheme's own meta-character (see
// golang.org/x/mod/module's unescapeString, which turns "!" followed by a
// lowercase letter into that letter's uppercase form) — module.CheckPath
// already rejects "!" in a real module path outright (confirmed live via
// module.EscapePath, which refuses to escape a path containing one at
// all: "invalid char '!'"), so this case never arises from a go.mod a
// real `go build` would accept. But a corrupted or adversarial go.mod is
// exactly this tool's threat model (see the run #109/#458 comments
// elsewhere in this file), and gomod.go's firstField applies no character
// restriction when parsing a require/replace path or version. Before this
// fix, a literal "!" was passed straight through unescaped in the else
// branch below — "!" is a valid, unreserved URL path character per RFC
// 3986, so Go's HTTP client sends it as-is rather than percent-encoding
// it — confirmed live against a mock server implementing the real proxy's
// own decode algorithm (module.UnescapePath): a request built from
// "github.com/foo!bar" arrives over the wire unmodified, and the
// server-side unescaper reads the "!b" as its own escape sequence and
// decodes the whole path to "github.com/fooBar" — a different, unrelated
// module path never named anywhere in the go.mod. When that path happens
// to resolve to a real, established module, Lookup reported Exists:true
// with that module's real version history, while every resulting Finding
// was still labeled with the original, uninspected "github.com/foo!bar" —
// silently vouching for a corrupted/adversarial require line, the exact
// opposite of the "not-found"/suspicious signal unparseable input like
// this should produce. Callers must treat ok=false as "cannot be a real
// module reference" and skip the network round-trip rather than querying
// under a path that would be silently reinterpreted as something else.
//
// ok is also false when path contains any ASCII control character (byte
// value < 0x20, or 0x7F). module.CheckPath rejects every one of these too
// (confirmed live: "malformed module path ...: invalid char '\t'"/'\r'/
// '\x00'/'\x7f'), but the more urgent reason to guard them here is that
// they break the HTTP request itself, not just module-path validity: a
// control byte reaches here from a go.mod's own quoted-string require/
// replace token via leadingQuotedString's strconv.Unquote, which happily
// decodes an ordinary two-character escape sequence like `\t` (backslash,
// then the letter t — no literal control byte anywhere in the go.mod file
// on disk) into a real 0x09 tab byte in the decoded path/version. Passing
// that byte straight into a proxy URL makes Go's own net/url reject the
// request outright with "invalid control character in URL" — confirmed
// live. Before this fix, that error came back through c.get as an
// ordinary network error, and Lookup/VersionExists both treat *any*
// c.get error identically to a transient proxy outage (ModuleStatus.Unknown
// / VersionExists's unknown=true) — "network/proxy trouble, say nothing
// rather than a false finding" (see evaluateModuleStatus's own comment).
// That's the right call for an actual outage, but wrong here: this is a
// deterministic, always-reproducing client-side failure caused entirely by
// the untrusted input, not a maybe-transient server-side one, and treating
// it as "say nothing" let a go.mod requirement that cannot possibly build
// under the real go toolchain (confirmed live, GOPROXY=off included to
// rule out any network dependency: `go list -m all` Fatals immediately
// with "malformed module path ...: invalid char '\t'", never reaching the
// network) sail through modslop reporting "nothing flagged" instead of
// the "not-found"/suspicious signal a corrupted go.mod like this should
// produce. Rejecting here, the same way the "!" guard already does, makes
// Lookup/VersionExists treat it as definitively nonexistent instead.
func escapeModulePath(path string) (escaped string, ok bool) {
	var b strings.Builder
	for _, r := range path {
		switch {
		case r == '!' || r < 0x20 || r == 0x7F:
			return "", false
		case r >= 'A' && r <= 'Z':
			b.WriteByte('!')
			b.WriteRune(r - 'A' + 'a')
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), true
}

func (c *ProxyClient) get(url string) (int, []byte, error) {
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// normalizedMajor returns v's major-version-compatibility line, the way
// the go command's own major-version-suffix rules group them: v0 and v1
// collapse into the same implicit line (neither ever carries a path
// suffix or +incompatible marker), while v2 and above are each their own
// line. semver.Major returns "" for a string that isn't valid semver at
// all; that can't happen for real proxy.golang.org data, but grouping it
// with the v0/v1 line rather than treating it as a line of its own is the
// conservative choice — it can only ever suppress a comparison, not
// wrongly promote an invalid string to "highest tag."
func normalizedMajor(v string) string {
	switch m := semver.Major(v); m {
	case "v0", "v1", "":
		return "v1"
	default:
		return m
	}
}

// Lookup queries the proxy for a module's existence, version count,
// and the timestamp of its latest release.
func (c *ProxyClient) Lookup(modPath string) ModuleStatus {
	if matchesAnyPattern(modPath, c.PrivatePatterns) {
		return ModuleStatus{Private: true}
	}

	escaped, ok := escapeModulePath(modPath)
	if !ok {
		// A literal "!" makes modPath unescapable in a way that wouldn't
		// just fail, it would silently query a *different* module (see
		// escapeModulePath's doc comment) — treat as definitively
		// nonexistent rather than risk that, same as a real 404.
		return ModuleStatus{Exists: false}
	}

	status, body, err := c.get(fmt.Sprintf("%s/%s/@latest", c.BaseURL, escaped))
	if err != nil {
		return ModuleStatus{Unknown: true}
	}
	if status == 404 || status == 410 {
		return ModuleStatus{Exists: false}
	}
	if status == 403 && strings.Contains(string(body), proxyMalwareMarker) {
		return ModuleStatus{Blocklisted: true}
	}
	if status != 200 {
		return ModuleStatus{Unknown: true}
	}

	var info latestInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return ModuleStatus{Unknown: true}
	}
	t, _ := time.Parse(time.RFC3339, info.Time)

	result := ModuleStatus{Exists: true, LatestTime: t}

	vstatus, vbody, verr := c.get(fmt.Sprintf("%s/%s/@v/list", c.BaseURL, escaped))
	var lines []string
	if verr == nil && vstatus == 200 {
		lines = strings.FieldsFunc(strings.TrimSpace(string(vbody)), func(r rune) bool { return r == '\n' })
		result.VersionCount = len(lines)
	}

	// The go.mod fetched here must be the one @latest would have resolved
	// to *before* retraction is considered, per go.dev/ref/mod#go-mod-
	// file-retract — not necessarily info.Version (@latest's own,
	// already-retraction-filtered result), because those two only agree
	// when the highest tag in the current major-version line isn't itself
	// retracted. Confirmed live, 2026-09, against github.com/jayconrod/
	// retract — the Go team's own canonical example of this feature:
	// v1.0.1 retracts both itself and v1.0.0, so @latest resolves past
	// both, all the way back to v0.9.9, whose go.mod predates the
	// `retract` directive's introduction and carries no retract block at
	// all. `go list -m -u` still correctly reports
	// github.com/jayconrod/retract v1.0.0 as retracted ("Published
	// accidentally.") because it reads v1.0.1's go.mod instead — the
	// highest tag, not the post-retraction @latest. Before this fix,
	// modslop fetched info.Version's (v0.9.9's) go.mod unconditionally, so
	// a go.mod requiring v1.0.0 of this exact module produced zero
	// findings — reproduced against the real, live proxy.
	//
	// "Highest tag" is scoped to info.Version's own major-version line
	// (collapsing v0/v1 into one implicit line, matching
	// golang.org/x/mod/semver.Major), not the highest tag over all of
	// @v/list: a module can carry an abandoned, unrelated higher-major
	// experiment that was never — and, per go's own major-version-suffix
	// rules, never automatically would be — part of the same latest-
	// version line. Confirmed live against github.com/mattn/go-sqlite3:
	// its highest tag overall is v2.0.3+incompatible (from a 2020 v2
	// experiment abandoned the same year), but `go list -m -u` for a
	// go.mod requiring that exact version still resolves retraction from
	// v1.14.52's go.mod — the module's real, actively-tagged-through-2026
	// v1.x line — never v2.0.3+incompatible's own (a bare, pre-modules
	// go.mod with no retract block, which would have silently swallowed
	// this exact retraction had it been used instead). Scoping by major
	// line keeps both live-verified cases correct at once.
	//
	// Within that major line, a higher-sorting pre-release tag must never
	// win over a release tag. go.dev/ref/mod#version-queries is explicit
	// that "latest" (and, per go-mod-file-retract, the "-retracted" variant
	// used to load retract directives) "selects the highest available
	// release version. If there are no release versions, latest selects
	// the highest pre-release version" — release versions are preferred
	// over pre-release ones regardless of raw semver ordering. Confirmed
	// live, 2026-09, against the real google.golang.org/grpc module: its
	// v1.x line carries release tags (..., v1.83.0, v1.84.0) interleaved
	// with "-dev" pre-release tags cut ahead of each upcoming release
	// (v1.84.0-dev, v1.85.0-dev, v1.86.0-dev), and the latter sort higher
	// than v1.84.0 by raw semver.Compare purely because their minor number
	// is higher — yet real `go list -m -retracted google.golang.org/
	// grpc@latest` (go1.24.4, live proxy) resolves to v1.84.0, never
	// v1.86.0-dev. Before this fix, the loop below compared every same-
	// major-line tag with plain semver.Compare and had no notion of
	// release vs. pre-release, so it would walk modVersion past a real
	// release like v1.84.0 up to v1.86.0-dev whenever a project tags its
	// next pre-release ahead of the current release line (a common
	// release-engineering pattern, not a rare edge case) — fetching a
	// pre-release's go.mod instead of the actual governing release's, and
	// silently losing any retract directive that lived only in the real
	// release's go.mod (or picking up retract directives that only exist
	// in a throwaway pre-release's go.mod and were never in a released
	// version at all). The fix mirrors the real preference rule: find the
	// highest release tag in the major line first, and only fall back to
	// the highest pre-release tag when the line has no release tag at all
	// (matching info.Version itself in that case, since @latest applies
	// the identical fallback).
	modVersion := info.Version
	if len(lines) > 0 {
		wantMajor := normalizedMajor(info.Version)
		var highestRelease, highestPrerelease string
		for _, v := range lines {
			if normalizedMajor(v) != wantMajor {
				continue
			}
			if semver.Prerelease(v) == "" {
				if highestRelease == "" || semver.Compare(v, highestRelease) > 0 {
					highestRelease = v
				}
			} else if highestPrerelease == "" || semver.Compare(v, highestPrerelease) > 0 {
				highestPrerelease = v
			}
		}
		switch {
		case highestRelease != "" && semver.Compare(highestRelease, modVersion) > 0:
			modVersion = highestRelease
		case highestRelease == "" && highestPrerelease != "" && semver.Compare(highestPrerelease, modVersion) > 0:
			modVersion = highestPrerelease
		}
	}
	if modVersion != "" {
		// modVersion comes from the proxy's own @latest/@v/list responses,
		// never straight from an untrusted go.mod, so escaping it should
		// always succeed in practice — but guard anyway rather than assume,
		// same defensive posture as every other proxy-response handling in
		// this function.
		if ev, ok := escapeModulePath(modVersion); ok {
			if mstatus, mbody, merr := c.get(fmt.Sprintf("%s/%s/@v/%s.mod", c.BaseURL, escaped, ev)); merr == nil && mstatus == 200 {
				result.LatestModBody = string(mbody)
			}
		}
	}

	if len(lines) > 0 {
		// @latest can resolve to a pseudo-version (the tip of the default
		// branch) instead of the one real tag when that tag doesn't sort
		// as the semver-highest version — e.g. a "vX.Y.Z-something" tag
		// that Go treats as a prerelease. When that happens, info.Time is
		// the timestamp of whatever was last committed, which for any
		// actively-developed repo is "recent" almost by definition and
		// says nothing about how long the module has existed. Confirmed
		// against a real case: github.com/grafana/alerting (4-year-old,
		// 89-star, actively-maintained Grafana Labs repo) has exactly one
		// tag from ~5 months ago, but @latest returns a same-week pseudo-
		// version, which made it look "new-and-thin". Fetch the actual
		// tag's own info when @latest didn't resolve to it.
		if len(lines) == 1 && lines[0] != info.Version {
			if ev, ok := escapeModulePath(lines[0]); ok {
				if _, tbody, terr := c.get(fmt.Sprintf("%s/%s/@v/%s.info", c.BaseURL, escaped, ev)); terr == nil {
					var tagInfo latestInfo
					if json.Unmarshal(tbody, &tagInfo) == nil {
						if tt, err := time.Parse(time.RFC3339, tagInfo.Time); err == nil {
							result.LatestTime = tt
						}
					}
				}
			}
		}

		// EarliestTime needs the semver-lowest tag, not list order — @v/list
		// is not sorted (confirmed live, 2026-09, against a real module:
		// proxy.golang.org's list for a 16-version module came back in
		// arbitrary, non-chronological order).
		switch {
		case len(lines) == 1:
			result.EarliestTime = result.LatestTime
		case len(lines) > 1:
			earliest := lines[0]
			for _, v := range lines[1:] {
				if semver.Compare(v, earliest) < 0 {
					earliest = v
				}
			}
			if ev, ok := escapeModulePath(earliest); ok {
				if _, ebody, eerr := c.get(fmt.Sprintf("%s/%s/@v/%s.info", c.BaseURL, escaped, ev)); eerr == nil {
					var earliestInfo latestInfo
					if json.Unmarshal(ebody, &earliestInfo) == nil {
						if et, err := time.Parse(time.RFC3339, earliestInfo.Time); err == nil {
							result.EarliestTime = et
						}
					}
				}
			}
		}
	}
	return result
}

// versionComparisonOperators are go.dev/ref/mod#version-queries' four
// comparison-query prefixes. Checked longest-first so ">="/"<=" are never
// misparsed as ">"/"<" with a target of "=v1.2.3" (which fails the
// semver.IsValid check in parseComparisonQuery anyway, but checking in this
// order avoids relying on that fallback).
var versionComparisonOperators = []string{">=", "<=", ">", "<"}

// parseComparisonQuery reports whether version is shaped like one of
// go.dev/ref/mod#version-queries' four comparison queries (e.g. "<v1.2.3",
// ">=v1.5.6") and, if so, splits it into the operator and its semver target.
func parseComparisonQuery(version string) (op, target string, ok bool) {
	for _, o := range versionComparisonOperators {
		if t, found := strings.CutPrefix(version, o); found && semver.IsValid(t) {
			return o, t, true
		}
	}
	return "", "", false
}

// resolveComparisonQuery resolves a comparison-operator version query (op,
// target — see parseComparisonQuery) against modPath's *tagged* version
// list, mirroring the real go command's own query semantics exactly.
// go.dev/ref/mod#version-queries: a comparison query "selects the nearest
// available version to the comparison target (the lowest version for > and
// >=, and the highest version for < and <=)" and, like every version query
// other than a specific version or revision, "consider[s] available
// versions reported by `go list -m -versions`" — tagged versions only, never
// a pseudo-version. Confirmed live, 2026-09, against the real proxy and
// `go list -m`: github.com/pkg/errors (tags v0.1.0 through v0.9.1) resolves
// "@>v0.8.0" to v0.8.1 (nearest *above* the target, not the module's overall
// highest tag), "@>=v0.9.0" to v0.9.0, "@<v1.0.0" to v0.9.1, and
// "@<=v0.9.0" to v0.9.0 — all confirmed with `GOFLAGS=-mod=mod go list -m`
// against the live proxy.
//
// proxy.golang.org's own @v/<version>.info endpoint — the one VersionExists
// and ResolveVersion otherwise use for every other version shape, including
// a plain prefix query like "v0.9" (see ResolveVersion's own doc comment) —
// cannot resolve this query shape at all: confirmed live, a request for
// .../@v/%3Cv1.0.0.info (the properly-escaped form of "<v1.0.0") 404s with
// "bad request: invalid escaped version \"<v1.0.0\": invalid char '<'".
// Before this function existed, VersionExists sent a comparison query
// straight to that endpoint like any other version string, got that 404,
// and reported a completely real, resolvable version constraint on a
// popular, well-established module (e.g. `require github.com/pkg/errors
// <v1.0.0`, confirmed live with the actual modslop binary) as a
// high-severity "version-not-found" — indistinguishable from an actually
// hallucinated version — even though the real go command resolves this
// exact go.mod's requirement to v0.9.1 without any error (confirmed live:
// `go build`/`go list -m all` on a scratch module with this require line
// only ever complain that go.mod needs `go mod tidy` to rewrite the query
// down to its resolved tag, the same "needs tidying, not unbuildable" shape
// checkExcludedRequirements's own doc comment already established for a
// plain abbreviated version like "v0.9").
//
// unknown reports a network/proxy error while fetching the version list —
// the same "say nothing" signal every other proxy-trouble path in this file
// uses. A successful fetch that simply has no tagged version satisfying the
// constraint returns ("", false): confirmed live that this is a real,
// deterministic failure mode for the real go command too (`go list -m
// github.com/pkg/errors@'>v99.0.0'` fails immediately with "no matching
// versions for query", never touching the network again) — go.mod's own
// query grammar can express a constraint that can never resolve, and that
// deserves the same "not found" signal as any other unresolvable version,
// not "network trouble."
func (c *ProxyClient) resolveComparisonQuery(modPath, op, target string) (resolved string, unknown bool) {
	escaped, ok := escapeModulePath(modPath)
	if !ok {
		return "", false
	}
	status, body, err := c.get(fmt.Sprintf("%s/%s/@v/list", c.BaseURL, escaped))
	if err != nil {
		return "", true
	}
	if status == 404 || status == 410 {
		// No tagged versions at all (same "doesn't exist" shape @v/list
		// gives Lookup) — deterministically nothing for the query to match,
		// not network trouble.
		return "", false
	}
	if status != 200 {
		return "", true
	}

	lines := strings.FieldsFunc(strings.TrimSpace(string(body)), func(r rune) bool { return r == '\n' })
	best := ""
	for _, v := range lines {
		if !semver.IsValid(v) {
			continue
		}
		cmp := semver.Compare(v, target)
		var matches bool
		switch op {
		case "<":
			matches = cmp < 0
		case "<=":
			matches = cmp <= 0
		case ">":
			matches = cmp > 0
		case ">=":
			matches = cmp >= 0
		}
		if !matches {
			continue
		}
		switch op {
		case "<", "<=":
			// Nearest below/at the target: the highest matching version.
			if best == "" || semver.Compare(v, best) > 0 {
				best = v
			}
		default: // ">", ">="
			// Nearest above/at the target: the lowest matching version.
			if best == "" || semver.Compare(v, best) < 0 {
				best = v
			}
		}
	}
	return best, false
}

// VersionExists reports whether modPath's exact version resolves via the
// module proxy's @v/<version>.info endpoint — the version-specific
// analogue of Lookup's module-path-level @latest/@v/list existence
// check. Lookup never answers this: it fetches @v/list only to count
// and date tagged releases (VersionCount/EarliestTime), never to check
// whether the *specific* version a go.mod actually requires is among
// them — and a pseudo-version (go.dev/ref/mod#pseudo-versions) never
// appears in @v/list at all regardless, tagged or not. That leaves a
// real, established, popular module with a completely fabricated
// version number sailing through every other check with zero findings,
// since not-found/new-and-thin/version-flooded/retracted/deprecated all
// key off the module path or its *latest* go.mod, never the checked
// version's own existence. Confirmed live, 2026-09: proxy.golang.org's
// github.com/gorilla/mux/@v/v3.5.0.info 404s (gorilla/mux has never
// gone past v1.8.x) while .../v1.8.1.info (a real tag) resolves 200 —
// and a go.mod requiring the fake v3.5.0 produced "nothing flagged"
// before this check existed, since gorilla/mux is old and multi-version
// enough to clear new-and-thin/version-flooded on the module level. A
// hallucinated version number of a real module is exactly as fabricable
// as a hallucinated module path, and go.mod's own grammar can't tell
// the two apart.
//
// A comparison-operator query (e.g. "<v1.2.3") is resolved against the
// tagged version list first — see resolveComparisonQuery's own doc comment
// for why that query shape can't go through the ordinary @v/<version>.info
// path below at all.
//
// unknown reports a network/proxy error, the same "say nothing" signal
// ModuleStatus.Unknown already uses elsewhere — a transient outage here
// must never produce a false version-not-found finding.
func (c *ProxyClient) VersionExists(modPath, version string) (exists, unknown bool) {
	if op, target, isQuery := parseComparisonQuery(version); isQuery {
		resolved, unk := c.resolveComparisonQuery(modPath, op, target)
		if unk {
			return false, true
		}
		if resolved == "" {
			return false, false
		}
		version = resolved
	}

	// Both modPath and version can come straight from an untrusted go.mod
	// requirement/replace line (gomod.go's firstField applies no character
	// restriction), so both need the same "!" guard Lookup applies — see
	// escapeModulePath's doc comment for why a literal "!" left unescaped
	// silently queries a different module than the one named in the
	// go.mod, rather than just failing.
	escaped, ok := escapeModulePath(modPath)
	if !ok {
		return false, false
	}
	escapedVersion, ok := escapeModulePath(version)
	if !ok {
		return false, false
	}
	status, _, err := c.get(fmt.Sprintf("%s/%s/@v/%s.info", c.BaseURL, escaped, escapedVersion))
	if err != nil {
		return false, true
	}
	switch status {
	case 200:
		return true, false
	case 404, 410:
		return false, false
	default:
		return false, true
	}
}

// ResolveVersion resolves version against modPath via the same
// @v/<version>.info endpoint VersionExists uses, but returns the canonical
// version the proxy actually resolved it to instead of a plain yes/no. This
// matters because a require or exclude directive's version doesn't have to
// already be a full, canonical semver string to be legal go.mod syntax —
// golang.org/x/mod/modfile.Parse accepts an abbreviated version like "v0.9"
// on either side, and both the real go command and the module proxy itself
// silently resolve it as a version *query* (the highest version matching
// that prefix), not a literal tag name. Confirmed live, 2026-09: `curl
// https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.info` returns
// `{"Version":"v0.9.1",...}` — a different string than the one queried for.
// See checkExcludedRequirements's own doc comment for why this matters: two
// differently-spelled versions of the same module can still name the exact
// same real release, which an exact string comparison alone would miss.
//
// ok is false on any network/proxy trouble or a 404/410 (nothing to
// resolve to) — callers must treat that as "no evidence of a match" rather
// than inferring a conflict either way, the same "say nothing" posture
// VersionExists's own unknown return uses.
//
// A comparison-operator query (e.g. "<v1.2.3") is resolved against the
// tagged version list first, same as VersionExists — see
// resolveComparisonQuery's own doc comment for why that query shape 404s
// against the @v/<version>.info endpoint used below instead of resolving
// like every other query shape (including a plain prefix query such as
// "v0.9", which that endpoint already handles fine).
func (c *ProxyClient) ResolveVersion(modPath, version string) (resolved string, ok bool) {
	if op, target, isQuery := parseComparisonQuery(version); isQuery {
		resolvedQuery, unknown := c.resolveComparisonQuery(modPath, op, target)
		if unknown || resolvedQuery == "" {
			return "", false
		}
		version = resolvedQuery
	}

	escaped, eok := escapeModulePath(modPath)
	if !eok {
		return "", false
	}
	escapedVersion, vok := escapeModulePath(version)
	if !vok {
		return "", false
	}
	status, body, err := c.get(fmt.Sprintf("%s/%s/@v/%s.info", c.BaseURL, escaped, escapedVersion))
	if err != nil || status != 200 {
		return "", false
	}
	var info latestInfo
	if json.Unmarshal(body, &info) != nil || info.Version == "" {
		return "", false
	}
	return info.Version, true
}

// majorVersionWalkBackCap bounds how many predecessor major versions
// IsMajorVersionBumpOfEstablished will walk back through before giving
// up. A project that cuts major-version bumps unusually often can chain
// several thin-looking predecessors in a row while still being a long-
// established project overall — confirmed live, 2026-09-27, against
// github.com/google/go-github (a decade-old, widely used GitHub API
// client, a direct dependency of both cilium/cilium's and
// go-gitea/gitea's real go.mod files): it cuts a new major version for
// essentially every breaking API change, roughly monthly, so at any
// given time both the current major and its immediate predecessor can
// still be within recentWindow — see
// TestIsMajorVersionBumpOfEstablishedWalksBackPastThinPredecessor.
// Capped rather than unbounded for the same reason toolPrefixWalkCap
// exists: an adversarial or corrupted module path shouldn't be able to
// trigger unbounded sequential network round-trips. 8 covers even an
// unusually fast-moving real project (go-github needed 2) while keeping
// the worst case cheap.
const majorVersionWalkBackCap = 8

// predecessorMajorPath returns the module path for major-version number m
// of the module named by prefix/sep/gopkgIn (as split out of modPath by
// module.SplitPathVersion), or ok=false once m has walked back past the
// lowest valid major version (v1 for an ordinary module — v0/v1 share the
// same implicit, suffix-free path — or v1 for gopkg.in, which per its own
// "gopkg.in requires ".vN" for all N, even 1" convention has no implicit
// form at all).
func predecessorMajorPath(prefix, sep string, gopkgIn bool, m int) (path string, ok bool) {
	switch {
	case m >= 2:
		return prefix + sep + strconv.Itoa(m), true
	case m == 1:
		if gopkgIn {
			return prefix + sep + "1", true
		}
		return prefix, true // implicit v0/v1, no suffix
	default:
		return "", false
	}
}

// IsMajorVersionBumpOfEstablished reports whether modPath looks new-and-
// thin only because it's the first release under a fresh Go major-version
// suffix (e.g. ".../v7") of an otherwise long-established module. Go's
// import-compatibility rule (https://go.dev/ref/mod#major-version-suffixes)
// makes every major version bump a distinct module path with its own
// fresh publish history, so a real, well-known project cutting a v7.0.0
// is indistinguishable from a brand-new hallucinated module by version
// count and age alone. Confirmed against a real case: sigs.k8s.io/
// structured-merge-diff/v7 (a Kubernetes SIG project, part of
// kubernetes/kubernetes's own go.mod) has exactly one version published
// within recentWindow, but its immediate predecessor sigs.k8s.io/
// structured-merge-diff/v6 has 10 published versions going back years —
// same repo, just a major-version bump.
//
// Walking back only ever the *immediate* predecessor (this function's
// shape before this comment) isn't always enough, though: see
// majorVersionWalkBackCap's go-github example, where the immediate
// predecessor itself still looks thin. So this keeps walking further
// back, up to majorVersionWalkBackCap steps, until it finds a predecessor
// that either has more than one published version or is old enough to
// clear recentWindow on its own (either is enough evidence the project
// itself is established, regardless of how recently or how often it
// bumps majors) — or a predecessor that doesn't exist at all, at which
// point there's no more evidence to find by going further back.
func (c *ProxyClient) IsMajorVersionBumpOfEstablished(modPath string) bool {
	prefix, pathMajor, ok := module.SplitPathVersion(modPath)
	if !ok || pathMajor == "" {
		return false
	}

	gopkgIn := strings.HasPrefix(pathMajor, ".v")
	sep := "/v"
	if gopkgIn {
		sep = ".v"
	}
	n, err := strconv.Atoi(strings.TrimPrefix(pathMajor, sep))
	if err != nil {
		return false
	}

	for m := n - 1; m > n-1-majorVersionWalkBackCap; m-- {
		predecessor, ok := predecessorMajorPath(prefix, sep, gopkgIn, m)
		if !ok {
			return false
		}
		status := c.Lookup(predecessor)
		if !status.Exists {
			return false
		}
		if status.VersionCount > 1 || time.Since(status.LatestTime) >= recentWindow {
			return true
		}
	}
	return false
}
