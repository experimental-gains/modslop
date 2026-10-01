package main

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Severity of a finding, roughly in order of how confident it is
// that something is actually wrong.
type Severity string

const (
	SeverityHigh Severity = "high"
	SeverityWarn Severity = "warn"
)

// Finding is one flagged requirement.
type Finding struct {
	Module   string   `json:"module"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
	Detail   string   `json:"detail"`
}

const (
	recentWindow = 30 * 24 * time.Hour
	// floodedHistoryWindow gates the "version-flooded" finding: a module
	// can defeat the single-version recentWindow check simply by
	// publishing many versions before ever being referenced — see
	// evaluateModuleStatus's "version-flooded" case for the real
	// incident that motivated this (2026-09, the Graphalgo campaign's
	// gocommunity.io/orderedbtree published 16 versions between Jul 21
	// and Sep 2, all still well inside this window).
	// Wider than recentWindow on purpose: a burst of versions is itself
	// part of the evasion, so the same 30-day bar used for a single
	// version would be too easy to clear by tagging quickly.
	floodedHistoryWindow = 90 * 24 * time.Hour

	// typoMaxDistance is the absolute cap on edit distance, but it's
	// only allowed for names at or above typoScaledMaxLen — see below.
	typoMaxDistance = 2
	// typoMinNameLen excludes short base names (both the candidate's
	// and the popular module's) from *typo* (near-miss, non-zero edit
	// distance) comparison entirely. Found empirically (run #30):
	// scanning ~20 real go.mod files turned up "term"~"pterm",
	// "yaml"~"toml", "gin"~"gonp" and similar — 2 edits is a huge
	// fraction of a 3-6 letter string, so short names collide
	// constantly by chance, not by typosquatting. Deliberately does
	// NOT gate the separate exact-name-different-owner check in
	// closestPopularMatch — see that function's own doc comment for
	// why zero edit distance carries entirely different evidence that
	// this rationale never applied to in the first place.
	typoMinNameLen = 6
	// typoScaledMaxLen: below this length, only a single-edit distance
	// counts as suspicious. A 2-edit distance on an 8-9 letter name
	// (e.g. "go-retry"~"go-pretty", "gotenv"~"godotenv") is still just
	// as likely to be two unrelated real projects as a typosquat.
	typoScaledMaxLen = 10
)

// genericBaseNames are trailing path segments so conventional across
// the Go ecosystem that edit-distance proximity to them carries no
// typosquat signal — found empirically (run #52) by scanning 8 large
// real-world go.mod files (Kubernetes, Grafana, CockroachDB, etcd,
// Prometheus, Terraform, Hugo, Caddy): "errors" and "protobuf" alone
// produced a false positive in 5 of the 8, because dozens of unrelated
// orgs each ship their own "errors" or "*protobuf" subpackage by
// convention, and that's close (1-2 edits) to *some* popular module's
// base name by chance. Unlike a coined name (e.g. "logrus"), a near
// miss on a generic word says nothing about intent to deceive. This
// list only ever grows by evidence, the same way popularModules does —
// don't add a name here on suspicion alone. It's checked against both
// the candidate's base name and each popular module's base name: run
// #30's fix of adding the *victim* of a collision (e.g. "vtprotobuf")
// to popularModules is what created the "protobuf" false positive here
// in the first place — every generic word added to popularModules as
// an exemption is also a new magnet for the next unrelated package
// that happens to end in it.
var genericBaseNames = map[string]bool{
	"errors":     true,
	"protobuf":   true,
	"validator":  true,
	"validation": true,
	"decimal":    true,
	"common":     true,
	// Added during a real-world-testing pass (2026-09) over 18 large
	// popular repos' actual go.mod files: pingcap/tidb requires
	// github.com/tikv/pd/client (the real, established TiKV Placement
	// Driver client — a core, widely-used sub-package of the tikv/pd
	// project, just never independently tagged, so it resolves via
	// pseudo-version only) at an exact base-name match with the
	// already-popular go.etcd.io/etcd/client/v3 (major-suffix-stripped
	// base name "client"), which fired name-collision-exact — the
	// highest-severity finding — purely because "client" is as
	// conventional a trailing package-path segment as "errors" or
	// "common" already are, not because of any real relationship
	// between the two modules. Confirmed by more of the same shape
	// found in the same scan: github.com/moby/moby/client,
	// github.com/prometheus-operator/prometheus-operator/pkg/client,
	// and sigs.k8s.io/container-object-storage-interface/client are all
	// distinct, unrelated, real modules that also end in "/client" —
	// none of them happened to fire only because each is independently
	// established enough to clear looksUnestablished(ForImpersonation)
	// on its own, which a differently-shaped (newer or untagged) real
	// project sharing the same generic name would not be.
	"client": true,
	// Same pass, same shape: hashicorp/vault requires github.com/
	// jeffchao/backoff (a real, tiny, decade-plus-old (2014) backoff
	// helper by a different, unrelated author — not a clone of
	// cenkalti/backoff, just an independently-written package that
	// happens to share its generic, conventional name) as an indirect
	// dependency, which matched the already-popular github.com/
	// cenkalti/backoff/v4 on base name alone and fired name-collision-
	// exact. The same go.mod also requires github.com/jpillora/backoff
	// and github.com/lestrrat-go/backoff/v2 — two more distinct,
	// unrelated, real "backoff" packages — confirming "backoff" is a
	// generic, conventional retry-helper package name across the
	// ecosystem, not evidence of impersonation on its own.
	"backoff": true,
	// Added alongside the exact-name-different-owner scan's typoMinNameLen
	// fix (see closestPopularMatch's own doc comment): removing that
	// length floor from the exact-match branch exposed that several of
	// popularModules' own short base names ("api" from k8s.io/api, "go"
	// from github.com/json-iterator/go) are themselves conventional,
	// widely-reused trailing path segments — the exact-match analogue of
	// what "errors"/"client"/"backoff" above already are for the near-miss
	// case, just never reachable before because the length floor
	// incidentally shielded every short name, generic or not. Found
	// empirically scanning the same ~50 large real-world go.mod files the
	// typoMinNameLen fix was verified against: "api" alone produced a
	// false-positive name-collision-exact (against k8s.io/api) in over a
	// dozen of them purely because google.golang.org/genproto/googleapis/
	// api, istio.io/api, and sigs.k8s.io/kustomize/api all end their own,
	// unrelated import path in the conventional "/api" segment — none of
	// them have anything to do with Kubernetes. "go" did the same against
	// github.com/json-iterator/go: github.com/cncf/xds/go,
	// cloud.google.com/go, and github.com/siddontang/go are three more
	// distinct, unrelated, real modules that also end in the single
	// conventional segment "go".
	"api": true,
	"go":  true,
	// Same pass, same shape, a single confirmed case rather than a
	// dozen: influxdata/influxdb's actual go.mod requires
	// github.com/influxdata/cron directly (confirmed via the GitHub API
	// to be a genuinely independent, non-fork project — "A fast,
	// zero-allocation cron parser in ragel and golang," InfluxData's own
	// cron-expression parser for their Flux query language, unrelated to
	// github.com/robfig/cron beyond sharing the conventional scheduling
	// term "cron") — an exact base-name match against the already-popular
	// robfig/cron that fired name-collision-exact purely because "cron"
	// is as generic a package name for a scheduling helper as "backoff"
	// already is for a retry helper.
	"cron": true,
}

// closestPopularMatch returns the popular module whose base name is
// within the allowed edit distance of name, or an exact match of name at
// a *different* full path, or ("", "", false) if neither applies. exact
// reports which case fired, since the two carry different evidence and
// warrant different wording: a same-name-different-owner match isn't a
// typosquat (nothing is misspelled) — it's the impersonation technique
// documented in a real, disclosed, active Go supply-chain campaign
// (Bae & Yagemann, "Beyond Takedown: Measuring Malicious Go Module
// Persistence in the Wild", arXiv:2606.26291, 2026): attackers republish
// a popular module's exact name under a new, attacker-controlled owner
// rather than misspelling it (their worked example: the real
// portapps/drawio-portable re-uploaded verbatim as
// anotherteriy/drawio-portable). Before this, closestPopularMatch
// required d > 0, so an exact-name clone under a different owner was
// treated the same as "this is the real module" instead of flagged —
// confirmed live: closestPopularMatch("github.com/totallyfakeorg/zerolog",
// "zerolog") returned no match despite rs/zerolog being in
// popularModules. The exact-name case is reported directly, ahead of the
// edit-distance scan below, since identical-name evidence is at least as
// strong as a one- or two-edit near miss.
//
// The exact-name scan runs first and, deliberately, unconditionally —
// with no typoMinNameLen (or per-entry length) floor at all, unlike the
// near-miss scan below it. typoMinNameLen exists to suppress *coincidental*
// near-miss collisions on short strings (see its own doc comment): a 1-2
// edit distance on a 3-6 letter name is common by chance, so it carries
// little evidence of intent. Zero edit distance never has that problem
// at any length — an identical base name at a different full path is
// either the same project or a deliberate clone, regardless of how short
// the name is. Before this fix, that length floor was applied to the
// exact-match scan too (inherited from the near-miss scan it was
// originally written for, before the exact-match case existed at all),
// which meant every popularModules entry with a base name under 6
// characters — a substantial fraction of the list's most attractive,
// most-imported targets: "gin" (gin-gonic/gin), "mux" (gorilla/mux),
// "cli" (urfave/cli), "chi" (go-chi/chi), "zap" (uber/zap), "jwt"
// (golang-jwt/jwt), "dns" (miekg/dns), "pgx" (jackc/pgx), "echo"
// (labstack/echo), "wire" (google/wire), "gorm" (gorm.io/gorm), "cron"
// (robfig/cron), "viper"/"pflag"/"afero"/"cast" (all spf13) — was
// completely exempt from ever triggering name-collision-exact, the
// tool's own highest-severity finding, no matter how blatant or
// unestablished an exact clone under a different owner was. Confirmed
// live, 2026-09, against a real, existing Go module:
// github.com/gintool/gin ("GI in No Time", a genuine, decade-old,
// completely unrelated academic project — confirmed via the GitHub API
// to be `"fork": false`, nothing to do with the gin-gonic/gin web
// framework — sharing its exact base name by pure coincidence) has never
// been tagged on proxy.golang.org (VersionCount==0), exactly the
// "unestablished" shape looksUnestablishedForImpersonation exists to
// catch. A go.mod requiring it reported "nothing flagged" before this
// fix — the same blind spot an actual attacker-registered exact clone of
// any of the short names above would have sailed through, undetected by
// this tool's own most-severe, best-evidenced check, purely because the
// popular name they chose to clone happened to be short.
func closestPopularMatch(modPath, name string) (match string, exact bool, ok bool) {
	nameLower := toLower(name)
	if genericBaseNames[nameLower] {
		return "", false, false
	}
	for _, p := range popularModules {
		if p == modPath {
			return "", false, false // exact match on the real thing
		}
		pName := BaseName(p)
		if genericBaseNames[toLower(pName)] {
			continue
		}
		// Case-insensitive: golang.org/x/mod/module.CheckPath accepts
		// uppercase letters in a module path outright (confirmed live), so
		// a base name that's identical except for letter case (e.g.
		// "Zerolog" vs "zerolog") names a different, legally-registrable
		// module — not a typo, and just as invisible a difference to a
		// human or LLM reading go.mod as the identical-case clone this
		// branch already exists to catch. See TestClosestPopularMatch's
		// case-variant case for the full explanation and the real-world
		// precedent (sirupsen/logrus's own rename history is exactly this
		// class of case collision).
		if toLower(pName) == nameLower {
			return p, true, true
		}
	}

	// Below here: the near-miss (non-zero edit distance) scan only, which
	// does still need typoMinNameLen and the rest of the length-based
	// guards — see their own doc comments, all about coincidental
	// short-string collisions, a problem specific to non-zero edit
	// distance.
	//
	// Rune count, not len() (byte count): name comes straight from an
	// untrusted go.mod require line (this tool's whole threat model is a
	// crafted or corrupted go.mod, same as the Levenshtein length guard
	// below — see run #109's comment) and can contain multi-byte UTF-8
	// characters, which always encode to *more* bytes than runes. Using
	// byte count here would only ever inflate the apparent length,
	// letting a genuinely short (by rune count) name skip the
	// typoMinNameLen exclusion it should hit. pName is always pure ASCII
	// (from the static popularModules list), so its byte and rune counts
	// never diverge — no equivalent risk there.
	nameLen := utf8.RuneCountInString(name)
	if nameLen < typoMinNameLen {
		return "", false, false
	}
	best := ""
	bestDist := typoMaxDistance + 1
	for _, p := range popularModules {
		pName := BaseName(p)
		if len(pName) < typoMinNameLen || genericBaseNames[toLower(pName)] {
			continue
		}
		// Edit distance is always >= the difference in rune length, so a
		// name/pName pair whose lengths already differ by more than
		// typoMaxDistance can never end up within the allowed distance —
		// skip the O(nameLen*len(pName)) Levenshtein DP entirely rather
		// than running it just to discard the result. This is a pure
		// performance guard (never changes which pair wins), but it's
		// also what keeps a single adversarially long candidate name (a
		// crafted or corrupted go.mod requirement) from costing
		// O(nameLen) work per popular module — found via a 10MB synthetic
		// name taking ~19s without this guard (run #109).
		pLen := utf8.RuneCountInString(pName)
		if diff := nameLen - pLen; diff > typoMaxDistance || diff < -typoMaxDistance {
			continue
		}
		// d can no longer be 0 here — the exact-match scan above already
		// returned on any pName == name pair.
		d := Levenshtein(name, pName)
		allowed := typoMaxDistance
		// Rune count again, for the same reason as nameLen above: byte
		// count would let a multi-byte name that's genuinely short (in
		// runes) dodge the tighter single-edit threshold this length
		// scaling exists to enforce. nameLen/pLen (already computed
		// above) are the rune counts; reuse them instead of re-deriving
		// byte lengths here.
		if maxLen := max(nameLen, pLen); maxLen < typoScaledMaxLen {
			allowed = 1
		}
		if d <= allowed && d < bestDist {
			best, bestDist = p, d
		}
	}
	if best == "" {
		return "", false, false
	}
	return best, false, true
}

// looksUnestablished reports whether status gives no reason to trust
// that a module is a real, maintained project — either it doesn't
// resolve at all, or it resolves but is thin enough to be indistinguishable
// from a name just registered to catch something (see CheckRequirement).
// Unknown (network trouble) counts as unestablished too: with no age
// data available, the collision check falls back to running rather than
// silently skipping.
func looksUnestablished(status ModuleStatus) bool {
	if status.Unknown || !status.Exists {
		return true
	}
	if status.VersionCount == 0 {
		// No tagged releases at all: @latest resolves to a pseudo-version
		// of the default branch tip, so LatestTime is the last commit
		// time, not a publish event. For an actively-maintained module
		// that never cuts tags, that's "recent" by definition no matter
		// how old the module actually is, so it carries no age signal —
		// unlike the VersionCount==1 case there's no tag to re-fetch a
		// trustworthy timestamp from either. Confirmed against a real
		// module: github.com/zmap/zcrypto (a decade-old dependency of
		// moby/moby and cilium/cilium, never tagged) always resolves to
		// a same-day pseudo-version, which made it permanently look
		// "unestablished" and mis-fired the high-severity name-collision
		// check against golang.org/x/crypto. Fall back to "not
		// unestablished" rather than treating an untrustworthy recency
		// signal as evidence.
		return false
	}
	if status.VersionCount == 1 {
		return time.Since(status.LatestTime) < recentWindow
	}
	// Multiple versions don't make a module trustworthy by themselves if
	// every one of them was published recently — see the "version-
	// flooded" case in evaluateModuleStatus. An established project has
	// some real track record older than floodedHistoryWindow; a name
	// registered purely to catch something doesn't, however many
	// versions were tagged to make it look otherwise.
	return !status.EarliestTime.IsZero() && time.Since(status.EarliestTime) < floodedHistoryWindow
}

// looksUnestablishedForImpersonation is looksUnestablished's counterpart
// for the exact-name-collision check only. looksUnestablished's
// VersionCount==0 case deliberately treats an untagged module as "not
// unestablished" (see its own comment — needed to stop a real false
// positive on github.com/zmap/zcrypto, an old, legitimately-maintained,
// never-tagged module whose base name happens to be a *near* miss of
// "crypto"). That exemption is safe for the near-miss check, which
// exists to catch typos and needs real age evidence to avoid drowning
// users in false positives on generic near-collisions. It is not safe
// for an *exact* name match: identical name, different owner is itself
// high-confidence impersonation evidence (see the "Beyond Takedown"
// citation on closestPopularMatch) that doesn't depend on age at all —
// but VersionCount==0's blanket exemption meant a real attacker could
// evade this tool's own highest-severity check entirely just by never
// tagging the malicious module. Confirmed live/via fakeProxy
// (TestCheckRequirement_ExactNameCloneOfUntaggedPopular) that an
// untagged github.com/totallyfakeorg/zerolog produced zero findings at
// all before this fix — the exact impersonation shape this tool exists
// to catch, sailing through silently.
func looksUnestablishedForImpersonation(status ModuleStatus) bool {
	if status.VersionCount == 0 {
		return true
	}
	return looksUnestablished(status)
}

// pinnedVersionResolves reports whether a specific, already-known version
// of modPath resolves via the module proxy's per-version endpoint, even
// though Lookup's @latest-based existence check (status.Exists) came back
// false. See evaluateModuleStatus's "not-found" case for the real
// gravitational/kingpin/v2 incident this exists to fix: @latest can 404
// for reasons that have nothing to do with whether a specific, already-
// pinned version is real (e.g. the semver-highest tag in a major-version
// line predates that line's go.mod ever existing), so a bare version
// string with no module status to check against still deserves its own,
// direct proxy query before being written off as hallucinated. Returns
// false — deferring to the ordinary not-found path — when there's no
// version to check at all, or the version-specific query itself is
// inconclusive (network trouble) or negative.
func pinnedVersionResolves(modPath, version string, proxy *ProxyClient) bool {
	if version == "" {
		return false
	}
	exists, unknown := proxy.VersionExists(modPath, version)
	return exists && !unknown
}

// CheckRequirement runs all heuristics against one go.mod requirement
// and returns any findings (zero, one, or more).
func CheckRequirement(req Requirement, proxy *ProxyClient) []Finding {
	status := proxy.Lookup(req.Path)
	return evaluateModuleStatus(req.Path, req.Version, status, proxy)
}

// evaluateModuleStatus is CheckRequirement's finding logic, factored out
// so CheckTools can reuse it against a module path it resolved itself
// (via resolveToolPath) without a second, duplicate proxy fetch for the
// same path. version is the specific version actually being pulled in
// (used only by the retraction check below); CheckTools passes "" since a
// `tool` directive names no version, and retraction() treats "" as
// nothing to check.
func evaluateModuleStatus(modPath, version string, status ModuleStatus, proxy *ProxyClient) []Finding {
	var findings []Finding

	// checkVersion is what gets compared against the module's own retract
	// intervals below — see the "Independent of the switch above" comment
	// for why that check needs a canonical version, not necessarily
	// whatever version literally appears in the go.mod requirement.
	// Defaults to the raw, as-written version; the default branch below
	// overwrites it with the proxy's own resolved answer whenever the
	// requirement's version is itself a query rather than a literal tag.
	checkVersion := version

	switch {
	case status.Blocklisted:
		findings = append(findings, Finding{
			Module:   modPath,
			Severity: SeverityHigh,
			Reason:   "proxy-blocklisted-malicious",
			Detail:   "the Go module proxy has explicitly flagged this module as malicious and refuses to serve it — do not use it",
		})
		return findings
	case status.Unknown:
		// Network/proxy trouble — say nothing rather than a false finding.
	case status.Private:
		// The real `go` command never queries the public proxy for this
		// path either (GOPRIVATE/GONOPROXY covers it) — it fetches
		// directly from VCS instead. A miss on the public proxy is the
		// expected, correct outcome for a private module, not evidence
		// it's hallucinated.
	case !status.Exists && pinnedVersionResolves(modPath, version, proxy):
		// Lookup's Exists is decided entirely by the @latest endpoint, but
		// @latest can 404 for a module that is nonetheless completely real
		// at a specific, already-known version — confirmed live, 2026-09,
		// against a real dependency of gravitational/teleport (a large
		// real-world repo this tool is regularly tested against):
		// teleport's go.mod carries `replace github.com/alecthomas/
		// kingpin/v2 => github.com/gravitational/kingpin/v2
		// v2.1.11-0.20230515143221-4ec6b70ecd33`. proxy.golang.org's
		// github.com/gravitational/kingpin/v2/@latest 404s with "invalid
		// version: missing .../v2/go.mod at revision v2.1.10" — the
		// semver-highest tag in that major-version line predates the
		// module ever adding a v2 go.mod, so @latest can't resolve at all —
		// yet the exact pinned pseudo-version the replace names resolves
		// cleanly (its own @v/<version>.info and .mod both 200), and `go
		// mod download`/`go list -m all` on a scratch module with this
		// exact require+replace pair succeed outright, resolving straight
		// to it. Before this fix, evaluateModuleStatus only ever looked at
		// status.Exists here, so this real, currently-building dependency
		// was reported as a high-severity "not-found" — indistinguishable
		// from an actually-hallucinated import — purely because of an
		// unrelated historical quirk in the module's *other*, unused tags.
		// A version-specific fallback query only ever suppresses this
		// finding when the exact pinned version genuinely resolves on the
		// proxy — a truly hallucinated path 404s there too, so this adds
		// no blind spot for the case this check exists to catch.
	case !status.Exists:
		findings = append(findings, Finding{
			Module:   modPath,
			Severity: SeverityHigh,
			Reason:   "not-found",
			Detail:   "module does not resolve via the Go module proxy — if this came from AI-generated code, it may be a hallucinated import that was never real",
		})
	default:
		versionMissing := false
		if version != "" {
			if exists, unknown := proxy.VersionExists(modPath, version); !unknown && !exists {
				versionMissing = true
				findings = append(findings, Finding{
					Module:   modPath,
					Severity: SeverityHigh,
					Reason:   "version-not-found",
					Detail:   "the module exists, but this exact version was never published to the Go module proxy — if this came from AI-generated code, it may be a hallucinated version number for an otherwise-real module",
				})
			} else if !unknown && status.LatestModBody != "" {
				// A require/exclude directive's version field doesn't have to
				// already be a literal, canonical tag — golang.org/x/mod/
				// modfile's own grammar (and the real go command) also accepts
				// a version *query* here: an abbreviated prefix like "v0.9"
				// (see ResolveVersion's own doc comment) or a "<"/"<="/">"/">="
				// comparison query (see resolveComparisonQuery's). Both resolve
				// to some other, specific tag on the tagged version list —
				// exactly the tag retraction() below needs to compare against
				// the module's own retract intervals via semver.Compare, which
				// requires a canonical version on both sides. The raw query
				// string itself (e.g. ">=v2.0.1+incompatible") is not valid
				// semver syntax — its comparison-operator prefix alone makes
				// semver.Compare treat it as invalid, so it can never fall
				// inside a retract interval no matter what it actually
				// resolves to. Confirmed live, 2026-10-01 (go1.24.4, real
				// proxy.golang.org, loaded from an actual go.mod file via
				// `go list -m all` under both -mod=readonly and -mod=mod —
				// see resolveComparisonQuery's own doc comment for why that,
				// not a bare `go get`/`go list -m module@query` command-line
				// argument, is the operation that matters here): a go.mod
				// with `require github.com/mattn/go-sqlite3
				// >=v2.0.1+incompatible` resolves to v2.0.1+incompatible —
				// squarely inside the real, live [v2.0.0+incompatible,
				// v2.0.7+incompatible] range that module's own latest go.mod
				// retracts — and `go list -m -u -retracted` on the result
				// reports it Retracted with the maintainer's own rationale.
				// Before this fix, modslop's retraction check compared the
				// raw, un-resolved ">=v2.0.1+incompatible" string against that
				// same interval and never matched, reporting "nothing flagged"
				// for a go.mod the real go command flags as retracted. Only
				// attempted when the module actually has a go.mod to check
				// retract intervals against (status.LatestModBody != "") —
				// retraction() itself already no-ops otherwise, so resolving
				// first would just be a wasted round trip.
				if resolved, ok := proxy.ResolveVersion(modPath, version); ok {
					checkVersion = resolved
				}
			}
		}
		switch {
		case versionMissing:
			// The module-level new-and-thin/version-flooded heuristics
			// below answer "does this module look freshly squatted," which
			// is a different question from "does this exact pinned version
			// exist at all" and would just add a confusing, redundant
			// warning on top of the much clearer version-not-found finding
			// above.
		case status.VersionCount == 1 && time.Since(status.LatestTime) < recentWindow &&
			!proxy.IsMajorVersionBumpOfEstablished(modPath):
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityWarn,
				Reason:   "new-and-thin",
				Detail:   "only one version published, in the last 30 days — could be a legitimate new project, but it's also the exact shape of a name registered to catch AI-hallucinated imports",
			})
		case status.VersionCount > 1 && !status.EarliestTime.IsZero() && time.Since(status.EarliestTime) < floodedHistoryWindow &&
			!proxy.IsMajorVersionBumpOfEstablished(modPath):
			// Real incident (2026-09, the Graphalgo Terraform/npm
			// campaign's Go expansion): gocommunity.io/orderedbtree
			// published 16 versions over about six weeks, all with
			// realistic-looking version bumps — specifically defeating
			// the VersionCount==1 gate above. A module's whole tagged
			// history still starting inside floodedHistoryWindow is
			// itself the suspicious shape, regardless of how many
			// versions got tagged along the way.
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityWarn,
				Reason:   "version-flooded",
				Detail:   "multiple versions published, but the oldest one is still less than 90 days old — publishing many versions quickly is one way to defeat a single-version freshness check; could be a legitimate fast-moving new project, but a real 2026 Go supply-chain campaign used exactly this pattern",
			})
		}
	}

	// Independent of the switch above (a retracted version can be old,
	// established, and by every other measure trustworthy — retraction
	// is the maintainer's own explicit "don't use this exact version"
	// signal, not a freshness or existence problem). retraction() already
	// no-ops when LatestModBody is empty (Blocklisted/Unknown/Private/
	// !Exists never populate it, see ProxyClient.Lookup) or version is ""
	// (CheckTools has none to check), so this doesn't need its own status
	// guard. See retract.go for why it's the *latest* version's go.mod,
	// not the checked version's own, that carries the retract directive.
	if rationale, retracted := retraction(status.LatestModBody, checkVersion); retracted {
		// "retracted by module author" — not "no rationale was given" (this
		// function's wording before this fix) — matching the real go
		// command's own phrasing exactly (cmd/go/internal/modload/
		// modfile.go's ModuleRetractedError.Error(): msg := "retracted by
		// module author"; only appended ": "+rationale when one was actually
		// attributed to *this* entry). The distinction matters because an
		// empty rationale here doesn't mean the go.mod gave no explanation —
		// golang.org/x/mod/modfile.Parse (the same parser retraction() uses)
		// only attributes a retract block's leading "//" comment to the
		// first version immediately following it, not to every version in a
		// multi-version group sharing that comment. Confirmed live, 2026-09,
		// against the real, current github.com/klauspost/compress go.mod:
		//
		//	retract (
		//		// https://github.com/klauspost/compress/issues/1114
		//		v1.18.1
		//
		//		// https://github.com/klauspost/compress/pull/503
		//		v1.14.3
		//		v1.14.2
		//		v1.14.1
		//	)
		//
		// mf.Retract[i].Rationale is "" for v1.14.2 and v1.14.1 even though
		// the "pull/503" comment plainly explains the whole group — before
		// this fix, checking a go.mod requiring v1.14.2 produced "no
		// rationale was given in the retract directive", which is simply
		// false: a rationale was given, just not re-attached to every
		// sibling entry by the parser. `go list -m -u -retracted -f
		// '{{.Retracted}}'` against the real proxy (go1.24.4) confirms real
		// go never makes this false claim either — it prints "[retracted by
		// module author]" for this exact version, the same fixed fallback
		// string used whether or not a sibling entry in the same go.mod
		// happens to carry a comment.
		explain := "retracted by module author"
		if rationale != "" {
			explain = "retracted by module author: " + strconv.Quote(rationale)
		}
		findings = append(findings, Finding{
			Module:   modPath,
			Severity: SeverityHigh,
			Reason:   "retracted",
			Detail:   "this exact version is covered by a `retract` directive in the module's own go.mod (" + explain + ") — retraction is advisory only, so proxy.golang.org and a plain `go install`/`go get` still serve it fine, but it's the maintainer's own explicit signal not to use this version",
		})
	}

	// Same independence rationale as retraction above, and reusing the
	// same status.LatestModBody fetch: a module can be deprecated
	// (superseded by a different import path) regardless of how
	// established or trustworthy it otherwise looks — this is exactly the
	// shape of mistake stale LLM training data produces, suggesting an
	// old, real, still-installable import path (e.g.
	// github.com/golang/protobuf) that the ecosystem has since moved off
	// of (google.golang.org/protobuf). deprecation() already no-ops on an
	// empty LatestModBody, so this needs no extra status guard either.
	// Severity is Warn, not High: unlike retraction (a version-specific
	// "don't use this" signal) or the malicious/typosquat checks above,
	// a deprecated module is real and legitimate, just superseded — worth
	// flagging, not the same alarm level as a supply-chain risk.
	if message, deprecated := deprecation(status.LatestModBody); deprecated {
		findings = append(findings, Finding{
			Module:   modPath,
			Severity: SeverityWarn,
			Reason:   "deprecated",
			Detail:   "the module's own go.mod deprecates it (" + strconv.Quote(message) + ") — this still resolves and installs fine, but it's the maintainer's own signal that the module has been superseded; worth double-checking this wasn't suggested from stale training data",
		})
	}

	// Gated on age/existence (added run #55): an established package
	// (multiple versions, older than recentWindow) being a couple of
	// edits from a popular name is weak evidence on its own — real
	// typosquats are almost always both close-in-name *and* new, per
	// the run #52 decision log. Checking this unconditionally is what
	// produced the "gogo/protobuf"-style false positives that
	// genericBaseNames patches around one word at a time; requiring the
	// candidate to also look new or unresolved fixes the same class of
	// false positive structurally instead.
	if match, exact, ok := closestPopularMatch(modPath, BaseName(modPath)); ok {
		switch {
		// Both branches below additionally require !IsMajorVersionBumpOfEstablished:
		// BaseName strips the "/vN" major-version suffix before comparison,
		// so a popular module's own next major-version bump (a brand-new
		// module path per Go's import-compatibility rule, see
		// IsMajorVersionBumpOfEstablished's doc comment) has a base name
		// identical to the popularModules entry for its *previous* major
		// line, and is — by definition, being freshly cut — exactly as
		// thin as an actual impersonation. Without this guard, the real,
		// same-owner github.com/redis/go-redis project simply publishing
		// v10 the day it's released reads as a likely clone of its own v9
		// self (name-collision-exact, this check's highest severity).
		// IsMajorVersionBumpOfEstablished already exists for this exact
		// shape (see the sigs.k8s.io/structured-merge-diff/v7 case below)
		// but, before this fix, was only wired into the new-and-thin/
		// version-flooded switch above, not into this collision check.
		// Checked last in each condition, same as the switch above, so it
		// only ever costs a proxy round-trip when the cheaper checks
		// already flagged something.
		case exact && looksUnestablishedForImpersonation(status) && !proxy.IsMajorVersionBumpOfEstablished(modPath):
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityHigh,
				Reason:   "name-collision-exact",
				Detail:   "name is identical to well-known module " + match + " but this is a different, unestablished path — republishing a popular module's exact name under a new owner is a real, disclosed Go supply-chain impersonation technique; verify this isn't a malicious clone before trusting it",
			})
		case !exact && looksUnestablished(status) && !proxy.IsMajorVersionBumpOfEstablished(modPath):
			findings = append(findings, Finding{
				Module:   modPath,
				Severity: SeverityHigh,
				Reason:   "name-collision-risk",
				Detail:   "name is one or two edits away from well-known module " + match + " — verify this isn't a typosquat before trusting it",
			})
		}
	}

	return findings
}

// toolPrefixWalkCap bounds how many path-slash-separated prefixes
// resolveToolPath will query the proxy for. A `tool` directive names a
// *package* path, not necessarily a module path (e.g.
// golang.org/x/tools/cmd/stringer, whose module is golang.org/x/tools),
// so finding the owning module means walking prefixes from longest to
// shortest. Without a cap, an adversarially deep or long tool path (a
// crafted or corrupted go.mod, this tool's whole threat model — same
// class of concern as the run #109 unbounded-Levenshtein fix) could turn
// into an unbounded number of sequential network round-trips. 8 covers
// every real-world case seen (module paths rarely nest more than a
// handful of segments below the host) while keeping the worst case cheap.
const toolPrefixWalkCap = 8

// resolveToolPath finds the module that owns a tool directive's package
// import path, mirroring what `go` itself does: try the full path first,
// then progressively shorter slash-separated prefixes, until one exists
// (or is private, which the proxy can't distinguish from "doesn't
// exist" but which the caller must not treat as unresolved) on the
// module proxy. Returns the first prefix that resolves, its status (so
// the caller doesn't need to re-fetch it), and resolved=true — or
// ("", ModuleStatus{}, false) if no prefix resolves at all.
//
// A prefix the proxy has explicitly Blocklisted as malicious must stop
// the walk too, the same as Exists/Private — it isn't "doesn't exist
// here, try a shorter prefix," it's the single most confident, most
// actionable signal this whole tool produces. Confirmed live, 2026-09,
// against a real, currently-blocklisted module: proxy.golang.org still
// serves a plain 403 "considers this module to be malicious" body for
// github.com/shopsprint/decimal, and github.com/shopsprint/decimal/cmd/x
// (an invented tool subpackage, no require/replace covering it) 404s at
// the full path exactly like a hallucinated one would, so the walk falls
// through to the blocklisted module's own prefix next. Before this fix,
// the condition below only tested Exists/Private, so a Blocklisted-only
// result (Exists stays false — see Lookup) was treated as "not resolved
// here" and the walk kept going to shorter, unrelated prefixes, which
// 404 too; CheckTools's own caller then discarded the real ModuleStatus
// this function already fetched and fell back to a bare
// ModuleStatus{Exists: false}, reporting "not-found" ("may be a
// hallucinated import") instead of "proxy-blocklisted-malicious" ("do
// not use it") for a `tool` directive pointing straight at a real,
// disclosed malicious module — the exact same module resolves correctly
// via an ordinary `require` line (CheckRequirement's status.Blocklisted
// switch case fires first, unconditionally), so this was a gap specific
// to the tool-directive-with-no-covering-require path, not a general
// blocklist-detection miss.
func resolveToolPath(pkgPath string, proxy *ProxyClient) (modPath string, status ModuleStatus, resolved bool) {
	segs := strings.Split(pkgPath, "/")
	attempts := len(segs)
	if attempts > toolPrefixWalkCap {
		attempts = toolPrefixWalkCap
	}
	for i := 0; i < attempts; i++ {
		prefix := strings.Join(segs[:len(segs)-i], "/")
		if prefix == "" {
			break
		}
		st := proxy.Lookup(prefix)
		if st.Exists || st.Private || st.Blocklisted {
			return prefix, st, true
		}
	}
	return "", ModuleStatus{}, false
}

// CheckTools runs the same heuristics CheckRequirement runs, but against
// the package paths named by go.mod `tool` directives that aren't
// already covered by a `require` entry. A go.mod produced by `go get
// -tool` always pairs a `tool` line with a covering `require`, so those
// are already checked via the normal require scan; this only covers the
// gap a hand-written or AI-generated go.mod can leave — a `tool` line
// with no `require` behind it at all.
//
// declaredReqs must be the *pre-replace* requirement paths (what CheckAll
// receives as its own reqs argument), not the post-replace resolved ones.
// A `tool` directive names an import path, and a replace directive never
// changes the import path packages under the replaced module are
// referenced by — only where the code backing that path comes from (see
// Replacement's doc comment and go.dev/ref/mod#go-mod-file-replace) — so
// a `tool` line paired with a `require`+`replace` pair for the same
// module still declares the *original* path, never the replacement's.
// Matching against resolved paths instead (this function's shape before
// this comment) made every such tool directive look uncovered, sending
// it through resolveToolPath under the stale pre-replace name instead of
// skipping it as already handled. Confirmed live with a concrete false
// positive this produced: `require example.com/oldtool v0.0.0` (a
// placeholder path never published, the normal shape for a full-rename
// fork) + `replace example.com/oldtool => github.com/real-org/realtool
// v1.2.3` (a real, clean, established module — already correctly
// resolved with zero findings via the ordinary require+replace check) +
// `tool example.com/oldtool/cmd/gen` produced a spurious high-severity
// "not-found" on the tool directive, because example.com/oldtool never
// resolves on its own and resolvedReqs no longer contains that path
// (CheckAll had already rewritten it to the replacement's path). Matching
// against the pre-replace path here makes the tool line register as
// covered, same as the require-level check already treats it — and, for
// a *local* replace (require+replace to a filesystem path, where the
// require-level check is itself skipped entirely — see CheckAll's own
// comment), this now consistently skips the tool line too instead of
// resolving it against public infrastructure under a name whose real
// backing code was never fetched from there at all.
//
// reps additionally covers the same false positive one layer further
// out: an *orphan* replace (Old path not named by any `require` line at
// all — see orphanReplacementTargets, legal go.mod syntax the real go
// toolchain honors with zero require line needed) can still be exactly
// what a `tool` directive's package path resolves through. Confirmed
// live with the same shape as the require-covered case above, minus the
// require line entirely: `tool example.com/oldtool/cmd/gen` + a bare
// `replace example.com/oldtool => github.com/real-org/realtool v1.2.3`
// (no `require example.com/oldtool` anywhere) — CheckAll's own
// orphanReplacementTargets already resolves and checks
// github.com/real-org/realtool correctly (it's the New side of an
// undeclared-Old replace), but before this fix CheckTools had no
// visibility into reps at all, so it treated the tool path as uncovered
// and additionally ran it through resolveToolPath under the stale,
// never-published example.com/oldtool name — producing a spurious
// second "not-found" finding even when the real target the tool actually
// resolves to is clean and established. Same matching rule as the
// require case (exact path or a "/"-prefixed subpackage of Old): the
// underlying module is already checked, one way or another, by whichever
// of CheckAll's two replace-resolution paths (require+replace, or
// orphanReplacementTargets) actually covers that Old path — a `tool`
// line matching it must never trigger a second, independent resolution
// of the original name.
//
// modulePath additionally covers a third, fully-local way a `tool`
// directive can need no `require`/`replace` at all: naming a package
// inside the main module itself. Go 1.24's `tool` directive isn't
// restricted to external dependencies — confirmed live: a go.mod with
// `module example.com/mymodule` and a bare `tool example.com/mymodule/
// cmd/gen` line (an internal code-generator kept in the same repo it
// generates for, a normal layout) builds, vets, and runs `go tool gen`
// cleanly with GOPROXY=off, and `go mod tidy` leaves the line untouched —
// no require entry is ever needed or added, since nothing is fetched
// over the network at all. Before this, CheckTools had no way to
// recognize this shape: declaredReqs and reps both come from require/
// replace directives, neither of which this go.mod needs, so the tool
// path fell straight through to resolveToolPath and got checked against
// the public proxy under its own module's (often unregistered,
// intentionally non-public) name — e.g. example.com/mymodule/cmd/gen
// 404s on proxy.golang.org, producing a spurious high-severity
// "not-found" finding on a directive that real go builds and runs with
// zero network access. Matching rule is the same exact-path-or-"/"-
// prefix test used for declaredReqs/reps just above.
func CheckTools(tools []string, declaredReqs []Requirement, reps []Replacement, modulePath string, proxy *ProxyClient) []Finding {
	seen := make(map[string]bool, len(tools))
	var deduped []string
	for _, t := range tools {
		if seen[t] {
			continue
		}
		seen[t] = true
		deduped = append(deduped, t)
	}

	var findings []Finding
	for _, tool := range deduped {
		covered := false
		for _, r := range declaredReqs {
			if tool == r.Path || strings.HasPrefix(tool, r.Path+"/") {
				covered = true
				break
			}
		}
		if !covered {
			for _, rep := range reps {
				if tool == rep.Old || strings.HasPrefix(tool, rep.Old+"/") {
					covered = true
					break
				}
			}
		}
		if !covered && modulePath != "" {
			if tool == modulePath || strings.HasPrefix(tool, modulePath+"/") {
				covered = true
			}
		}
		if covered {
			continue
		}

		if modPath, status, ok := resolveToolPath(tool, proxy); ok {
			findings = append(findings, evaluateModuleStatus(modPath, "", status, proxy)...)
		} else {
			findings = append(findings, evaluateModuleStatus(tool, "", ModuleStatus{Exists: false}, proxy)...)
		}
	}
	return findings
}

// checkConcurrency caps how many CheckRequirement calls (each up to two
// sequential proxy HTTP round-trips) run at once. Found empirically (run
// #52): a real 250+ requirement go.mod (CockroachDB's) ran requirements
// fully sequentially and didn't finish within a minute. 16 is enough to
// turn that into a few seconds without hammering proxy.golang.org.
const checkConcurrency = 16

// orphanReplacementTargets returns one Requirement per distinct remote
// (non-local) replace target among reps whose Old path is not itself
// present in reqs at all — a `replace` directive for a module this go.mod
// never names in its own `require` block.
//
// Real go.mod grammar allows this, and the real go toolchain honors it
// exactly like a covered replace: a `replace` directive applies to
// whatever ends up in the build list, whether that module got there via
// this go.mod's own `require` block or only transitively, through some
// other required module's dependencies — go.dev/ref/mod#go-mod-file-
// replace never says a `replace` needs a covering `require`, and
// overriding a transitive dependency's version without also promoting it
// to a direct one is a normal, common thing to do (e.g. patching a
// transitive security fix). Confirmed live with a three-module scratch
// chain: example.com/top requires only example.com/mid (via a local
// replace for test purposes); example.com/mid requires example.com/leaf;
// top's own go.mod carries a bare `replace example.com/leaf =>
// ../leaf-fork` with no `require example.com/leaf` line anywhere in it.
// Both `go run` and `go list -m all` run inside top resolve
// example.com/leaf straight to the fork (confirmed by the forked
// package's own distinguishing return value showing up in the program's
// actual output), and `go mod tidy` doesn't add a require line for it
// either — real go itself never needed one.
//
// Before this existed, CheckAll only ever applied a replace when its Old
// path matched an entry already in reqs (the `replacements`-keyed loop
// below) — a replace with no covering require was fully parsed by
// ParseGoMod and then silently dropped on the floor, so its New side (a
// network-fetched module path, exactly as hallucinable/typosquattable as
// any `require` entry) was never checked against the proxy at all. That's
// a bigger blind spot than the documented "the full transitive module
// graph isn't walked" limitation: this isn't about walking a dependency's
// *own* requirements, it's about a directive sitting directly in the
// go.mod this tool already reads in full, dropped by CheckAll's own
// require-keyed join rather than by any documented scope limit.
//
// Dedup is keyed on the New+NewVersion pair, not per-Old-path selection
// (the shape selectReplace uses for a covered requirement):
// selectReplace's general-beats-specific precedence exists to pick the
// one replace that applies to a *known* required version, but an orphan
// replace's Old path names a transitive dependency whose actual required
// version this tool never learns — no `require` line names it, and
// determining it would mean walking the module graph, the very thing
// this tool deliberately doesn't do (see above). Rather than guess which
// of several version-specific replaces for the same Old path a real
// build would end up applying, every distinct New target gets checked;
// any one of them could be the one actually used. A local New target is
// still skipped, same rationale as the covered-requirement case just
// below: nothing gets fetched over the network for it.
//
// A replace whose Old path is itself only the New side of a *different*
// replace directive in the same go.mod is excluded too — replace
// directives don't chain. Confirmed live against the real go toolchain:
// `require example.com/a v1.0.0` + `replace example.com/a => rsc.io/quote
// v1.5.2` + `replace rsc.io/quote => github.com/totally-fake-module
// v1.9.9`, with a program that only imports "example.com/a" (never
// rsc.io/quote directly), builds clean using the real rsc.io/quote —
// `go list -m all` shows only "example.com/a => rsc.io/quote v1.5.2",
// with no trace of the second replace ever firing, and no attempt to fetch
// the fake module. rsc.io/quote is never independently present in the
// required module graph — it only exists in this go.mod as the
// resolution target of the first replace — and a replace only takes
// effect against a path that's genuinely required (directly or
// transitively), never against another replace's resolved output. (A
// second, separate live test confirmed the contrast: when the middle
// module's own package *is* imported directly — making it genuinely,
// independently required — the second replace does fire. modslop only
// ever sees the go.mod, never the source code doing the importing, so it
// can't tell these two cases apart; treating "Old matches another
// replace's New" as evidence of the non-chaining case, the one just
// verified as the default, avoids checking a module the real go command
// will never fetch on the go.mod's own more common shape.) Before this,
// orphanReplacementTargets treated rsc.io/quote => fake as an ordinary
// orphan and checked the fake module — a spurious finding (or, just as
// easily, a spurious clean bill) about a module real go never touches.
func orphanReplacementTargets(reqs []Requirement, reps []Replacement) []Requirement {
	declared := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		declared[r.Path] = true
	}
	// chainedAway holds every path that is itself the New side of some
	// replace directive — i.e. only reachable, per this go.mod, as
	// another replace's resolution target, never as a genuinely required
	// path. See the chaining explanation above.
	chainedAway := make(map[string]bool, len(reps))
	for _, r := range reps {
		if !r.IsLocal() {
			chainedAway[r.New] = true
		}
	}
	seen := make(map[string]bool, len(reps))
	var out []Requirement
	for _, rep := range reps {
		if declared[rep.Old] || rep.IsLocal() || chainedAway[rep.Old] {
			continue
		}
		key := rep.New + "@" + rep.NewVersion
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Requirement{Path: rep.New, Version: rep.NewVersion})
	}
	return out
}

// checkDuplicateRequires flags a module path named by more than one
// require directive at different versions in the same go.mod — a second
// self-contradictory go.mod shape, alongside checkExcludedRequirements's
// require+exclude contradiction, that the real go toolchain refuses to
// build on at all rather than silently resolving.
//
// Confirmed live (2026-09, GOPROXY=off included to rule out any network
// dependency): a go.mod carrying
//
//	require (
//		github.com/pkg/errors v0.8.0
//		github.com/pkg/errors v0.9.1
//	)
//
// makes both `go build` and `go vet` fail immediately with "go: updates
// to go.mod needed; to update it: go mod tidy" — under the real
// toolchain's default `-mod=readonly` mode, Minimal Version Selection's
// own "highest version wins" resolution never even runs on a file shaped
// like this; it only applies after `go mod tidy` (or -mod=mod) has
// already rewritten the file down to a single line, at which point the
// duplicate is gone. This still fires with a `replace` directive present
// for the same module path (confirmed live) — replace never rescues it.
// A prior rotation (v0.2.43, reverted — see that commit's message)
// mistakenly assumed the opposite: that MVS silently picks the higher
// version and never queries the proxy for the loser. Live testing
// disproved that; this check's premise is the corrected one.
//
// Two require lines naming the exact same (path, version) pair, by
// contrast, build and resolve just fine (confirmed live — go silently
// treats them as one), so this only fires when the same path carries more
// than one *distinct* version — matching checkExcludedRequirements's own
// exact-match-only precedent for a different go.mod self-contradiction.
//
// Before this existed, a go.mod like the one above reported "nothing
// flagged" (each duplicate line was checked independently, on its own
// individual freshness/existence merits, with no notion that the pair
// together makes the file unbuildable) — the same class of blind spot
// checkExcludedRequirements closed for require+exclude contradictions,
// just for a different, plausible AI-assistant (or bad-merge) mistake:
// adding a new version requirement to an existing go.mod without noticing
// or removing the old line.
func checkDuplicateRequires(reqs []Requirement) []Finding {
	versionsByPath := make(map[string]map[string]bool, len(reqs))
	var order []string
	for _, r := range reqs {
		set, ok := versionsByPath[r.Path]
		if !ok {
			set = make(map[string]bool)
			versionsByPath[r.Path] = set
			order = append(order, r.Path)
		}
		set[r.Version] = true
	}

	var findings []Finding
	for _, path := range order {
		set := versionsByPath[path]
		if len(set) < 2 {
			continue
		}
		versions := make([]string, 0, len(set))
		for v := range set {
			versions = append(versions, v)
		}
		sort.Strings(versions)
		findings = append(findings, Finding{
			Module:   path,
			Severity: SeverityHigh,
			Reason:   "duplicate-require",
			Detail: "this module is named by more than one require directive at different versions (" +
				strings.Join(versions, ", ") +
				") in the same go.mod — the go command refuses to build this at all (\"updates to go.mod needed\"), regardless of whether either version actually exists; this is a self-contradictory go.mod, not a heuristic",
		})
	}
	return findings
}

// checkExcludedRequirements flags a require directive whose exact
// (path, version) pair is also named by an exclude directive in the same
// go.mod — a self-contradictory config the real go toolchain refuses to
// build on at all, not a heuristic. Per go.dev/ref/mod#go-mod-file-
// exclude, "the go command will never use a module version that matches
// an exclude directive"; confirmed live (2026-09, GOPROXY=off included to
// rule out any network dependency): a go.mod with `require
// github.com/pkg/errors v0.9.1` and `exclude github.com/pkg/errors
// v0.9.1` makes both `go build` and `go list -m all` fail immediately
// with "go: ignoring requirement on excluded version github.com/pkg/
// errors v0.9.1" / "go: updates to go.mod needed; to update it: go mod
// tidy" — a hard, deterministic failure, not a maybe. A *different*
// excluded version of the same module (e.g. exclude v0.9.0 while
// requiring v0.9.1) has no effect at all — confirmed by the same live
// test — so this only fires on an exact match, matching real go's own
// per-version exclusion semantics exactly rather than a same-module
// approximation.
//
// This deliberately checks the pre-replace requirement, not any
// replace-resolved path/version: confirmed live that even a `replace
// github.com/pkg/errors v0.9.1 => github.com/pkg/errors v0.9.1` sitting
// alongside the same require+exclude pair still produces the identical
// build failure — exclude acts on the module graph's own selected
// version before replace ever substitutes anything, so a replace can
// never rescue a self-excluded require.
//
// Before this existed, ParseGoMod dropped every `exclude` directive on
// the floor (see its own doc comment) and modslop had no way to see this
// at all — an AI-generated go.mod excluding the exact version it
// requires (a plausible mistake when trying to "pin away" a bad version
// by adding an exclude instead of bumping the require) reported "nothing
// flagged" for a go.mod the real go command cannot build.
//
// An exact literal-string match isn't the whole story, though: a require
// or exclude directive's version doesn't have to already be a full,
// canonical semver string to be legal go.mod syntax. golang.org/x/mod/
// modfile.Parse accepts an abbreviated version like "v0.9" on either side,
// and both the real go command and the module proxy's own
// @v/<version>.info endpoint (see ProxyClient.ResolveVersion) silently
// resolve it as a version *query* — the highest version matching that
// prefix — not a literal tag name. Confirmed live, 2026-09: `curl
// https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.info` returns
// `{"Version":"v0.9.1",...}`, and a go.mod with `require github.com/pkg/
// errors v0.9` plus `exclude github.com/pkg/errors v0.9.1` makes `go list
// -m all` fail immediately with "go: ignoring requirement on excluded
// version github.com/pkg/errors v0.9.1" — the identical build-breaking
// contradiction as the exact-string case above, just with the require side
// spelled as a query instead of the resolved tag. The reverse (`require
// ... v0.9.1` + `exclude ... v0.9`) fails identically, confirmed live, so
// both sides need resolving, not just one. Before this fix, the map-based
// exact-string check below missed this entirely: "v0.9" and "v0.9.1" are
// different Requirement values, so a go.mod that cannot build at all
// reported "nothing flagged" purely because one side used a plausible
// version shorthand instead of a fully-qualified tag. checkDuplicateRequires
// doesn't need the equivalent fallback: two require lines for the same path
// at "v0.9" and "v0.9.1" are already caught there today, since the real go
// command refuses to build that go.mod too, under the default
// -mod=readonly, independent of any exclude directive — only the
// require/exclude *pairing* here was keyed on an exact literal match
// instead of "same path, same resolved version."
//
// The resolution round trip only runs for a require path that's also named
// by some exclude directive and doesn't already match one of its versions
// literally — bounded by how many paths a go.mod names in both blocks at
// once, which is rare — and stops as soon as one exclude entry for that
// path resolves to the same version, so a path excluded at several
// versions costs at most one extra lookup per exclude entry, not a
// combinatorial blowup.
func checkExcludedRequirements(reqs []Requirement, excludes []Requirement, proxy *ProxyClient) []Finding {
	excluded := make(map[Requirement]bool, len(excludes))
	excludesByPath := make(map[string][]string, len(excludes))
	for _, e := range excludes {
		excluded[e] = true
		excludesByPath[e.Path] = append(excludesByPath[e.Path], e.Version)
	}

	var findings []Finding
	for _, r := range reqs {
		conflict := excluded[r]
		if !conflict {
			if versions, ok := excludesByPath[r.Path]; ok {
				if resolvedReq, ok := proxy.ResolveVersion(r.Path, r.Version); ok {
					for _, ev := range versions {
						if ev == r.Version {
							continue // already covered by the exact map check above
						}
						if resolvedEx, ok := proxy.ResolveVersion(r.Path, ev); ok && resolvedEx == resolvedReq {
							conflict = true
							break
						}
					}
				}
			}
		}
		if !conflict {
			continue
		}
		findings = append(findings, Finding{
			Module:   r.Path,
			Severity: SeverityHigh,
			Reason:   "excluded-requirement",
			Detail:   "this exact version is both required and excluded in the same go.mod — the go command refuses to build this at all (\"ignoring requirement on excluded version\"), regardless of whether the module or version actually exists; this is a self-contradictory go.mod, not a heuristic",
		})
	}
	return findings
}

// checkAmbiguousComparisonQueries flags a require or exclude directive
// whose version is a "<=" or ">" comparison query (go.dev/ref/mod#version-
// queries) with an incomplete ("prefix") operand — bare major ("v1") or
// major.minor ("v1.2"), missing its patch component. See
// isAmbiguousComparisonQuery's own doc comment for the live confirmation
// that real cmd/go Fatals on exactly this shape, at go.mod parse time,
// before ever contacting the network — a third self-contradictory,
// unbuildable go.mod shape alongside checkDuplicateRequires's and
// checkExcludedRequirements's, and, like both of those, purely local: no
// proxy round-trip is needed to know this go.mod can't build.
//
// Deduplicated on (path, version) across both reqs and excludes — the
// identical literal query string appearing as both a require and an
// exclude entry for the same module (or repeated across several require
// lines) is still just one distinct unbuildable shape worth reporting once,
// the same dedup rationale checkDuplicateRequires's own version set uses.
func checkAmbiguousComparisonQueries(reqs, excludes []Requirement) []Finding {
	var findings []Finding
	seen := make(map[Requirement]bool)
	check := func(r Requirement) {
		if !isAmbiguousComparisonQuery(r.Version) {
			return
		}
		if seen[r] {
			return
		}
		seen[r] = true
		findings = append(findings, Finding{
			Module:   r.Path,
			Severity: SeverityHigh,
			Reason:   "ambiguous-version-query",
			Detail:   "version \"" + r.Version + "\" is a \"<=\"/\">\" comparison query with an incomplete (major, or major.minor only) operand — the go command refuses to build this at all (\"ambiguous semantic version\"), regardless of whether the module or any matching version actually exists; this is a self-contradictory go.mod, not a heuristic",
		})
	}
	for _, r := range reqs {
		check(r)
	}
	for _, e := range excludes {
		check(e)
	}
	return findings
}

// checkReplaceMissingVersion flags a replace directive whose New side names
// a remote module (not a local filesystem path, per Replacement.IsLocal)
// but supplies no version for it. Per go.dev/ref/mod#go-mod-file-replace,
// "if the path on the right side of the arrow is not a filesystem path, it
// must be a valid module path, and a specific version must be provided in
// that case" — confirmed live (2026-09, go1.24.4): a go.mod with `replace
// github.com/pkg/errors => golang.org/x/text` (no version on the new side)
// fails go.mod PARSING itself — `go build`/`go list -m all` both Fatal
// immediately with "replacement module without version must be directory
// path (rooted or starting with . or ..)", before any network call, and
// this holds regardless of whether the Old path is covered by any require
// line at all (confirmed live for a bare, uncovered `replace golang.org/
// x/text => rsc.io/quote` too) — the identical "unbuildable, not a
// heuristic" class as checkDuplicateRequires, checkExcludedRequirements,
// and checkAmbiguousComparisonQueries.
//
// Before this existed, this exact contradiction had no finding of its own:
// CheckAll's own require+replace resolution loop (see its own comment on
// NewVersion) deliberately falls back to the stale, pre-replace
// requirement's version when NewVersion is "" — a documented choice for a
// malformed go.mod, but one that left the real defect invisible. That
// fallback version can coincidentally resolve on the replacement module
// (silently "nothing flagged", the same false-negative shape the other
// three self-contradictory checks exist to close), or it can simply not
// exist there — a misleading "version-not-found"/"hallucinated version"
// finding pinned on the *replacement* module, when the real defect is the
// go.mod itself, not that module's version history. Confirmed live:
// `github.com/pkg/errors => golang.org/x/text` with a stale v0.9.1 carried
// over from the require line reports "version-not-found" against
// golang.org/x/text — a module whose real v0.9.1 tag simply never
// existed, for reasons entirely unrelated to this go.mod's actual defect.
// An orphan replace (Old not covered by any require — see
// orphanReplacementTargets) hits the false-negative side even more
// directly: it produces a Requirement with Version=="", and
// evaluateModuleStatus's version-specific checks all no-op when version is
// "", so the go.mod reported "nothing flagged" outright.
//
// Deduplicated the same way checkAmbiguousComparisonQueries is: the
// identical malformed replace line can never appear twice with different
// meaning, but a go.mod could repeat it (e.g. inside vs. outside a block)
// and this should still report the contradiction once per distinct
// directive.
//
// reps must be the audited go.mod's own replace directives exactly as
// ParseGoMod returned them — CheckAll passes gomodReps here, never the
// go.work-overlay-merged reps it uses for ordinary replace resolution.
// This Fatal happens while golang.org/x/mod/modfile parses the go.mod
// file's own bytes, a step that runs (and fails) independently of, and
// before, any workspace-level module-graph resolution — so a go.work
// replace for the identical Old path can never rescue it. Confirmed
// live, 2026-09-30, go1.24.4: a two-module workspace where the member's
// own go.mod carries this exact malformed replace, and go.work
// separately carries a well-formed *general* replace for the same Old
// path (e.g. to a local fork) — the shape mergeReplaces exists to prefer
// — still Fatals identically, from both the workspace root and the
// member's own directory: "errors parsing member/go.mod: ...
// replacement module without version must be directory path ...". Before
// this fix, checkReplaceMissingVersion was called with the merged reps
// (main's `reps = mergeReplaces(reps, goWorkReplaces(...))`), and
// mergeReplaces' own correct-for-ordinary-resolution rule — drop every
// go.mod-level entry for a path once go.work carries a general entry for
// it (see mergeReplaces' own doc comment) — silently dropped the
// malformed entry right along with it, so this exact unbuildable go.mod
// reported "nothing flagged" the instant it was part of a workspace,
// despite `go build`/`go list -m all` refusing to load it under any
// circumstances, workspace or not. Confirmed via GOWORK=off on the same
// file that modslop's own finding reappears once the workspace overlay
// is out of the picture — the bug was specific to the merge silently
// eating a malformed entry, not to the check itself.
func checkReplaceMissingVersion(reps []Replacement) []Finding {
	var findings []Finding
	seen := make(map[Replacement]bool, len(reps))
	for _, r := range reps {
		if r.IsLocal() || r.NewVersion != "" {
			continue
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		findings = append(findings, Finding{
			Module:   r.Old,
			Severity: SeverityHigh,
			Reason:   "replace-missing-version",
			Detail: "the replace directive's target \"" + r.New +
				"\" is a remote module path with no version — the go command refuses to build this at all (\"replacement module without version must be directory path\"), regardless of whether either module actually exists; this is a self-contradictory go.mod, not a heuristic",
		})
	}
	return findings
}

// malformedDirectiveUsage gives the real go command's own Fatal message
// (golang.org/x/mod/modfile's rule.go, confirmed live against go1.24.4,
// GOPROXY=off to rule out any network dependency) for each directive
// MalformedDirective covers, keyed by its own field-count grammar:
// require/exclude take exactly two fields (module path, version) and
// Fatal with a "usage: ... v1.2.3" message when the version is missing;
// tool/module take exactly one field and Fatal with a differently-worded
// message (tool's own message carries no "usage:" prefix at all — ported
// verbatim, not paraphrased, from rule.go's own errorf calls) when the
// line has zero or more than one; replace takes the arrow-separated shape
// documented on parseReplaceLine and Fatals with its own two-line "usage:
// replace ..." message (also ported verbatim from rule.go) when no "=>"
// is found or either side has the wrong field count. See
// checkMalformedDirectives and parseToolLine's/parseReplaceLine's own doc
// comments.
var malformedDirectiveUsage = map[string]string{
	"require": "usage: require module/path v1.2.3",
	"exclude": "usage: exclude module/path v1.2.3",
	"tool":    "tool directive expects exactly one argument",
	"module":  "usage: module module/path",
	"replace": "usage: replace module/path [v1.2.3] => other/module v1.4\n\t or replace module/path [v1.2.3] => ../local/directory",
}

// checkMalformedDirectives flags a require, exclude, tool, module, or
// replace directive line that ParseGoMod recognized the keyword for but
// couldn't extract a well-formed argument list from (see ParseGoMod's
// sixth return value and MalformedDirective) — in practice today, a
// require/exclude line naming a module path with no version field at all,
// a tool/module line with zero or more than one argument, or a replace
// line with no "=>" arrow at all (or the wrong field count on either side
// of it). Per go.dev/ref/mod#go-mod-file-require, #go-mod-file-exclude,
// and #go-mod-file-replace, require/exclude are grammatically exactly two
// fields (module path, version); tool/module are exactly one
// (go.dev/ref/mod#go-mod-file-tool, #go-mod-file-module); replace is the
// arrow-separated shape parseReplaceLine documents. Confirmed live (2026-09,
// go1.24.4, GOPROXY=off to rule out any network dependency) for all five: a
// go.mod with a bare `require github.com/pkg/errors` (no version),
// `exclude github.com/pkg/errors` (same), a bare `tool` or `module` (no
// argument at all), `tool golang.org/x/tools/cmd/stringer extra` (an extra
// trailing field), or a bare `replace github.com/pkg/errors` (no arrow) all
// make `go build`/`go list -m all` fail immediately at go.mod PARSE time —
// see malformedDirectiveUsage for each one's exact message — before any
// network call, the identical "self-contradictory, unbuildable go.mod, not
// a heuristic" class as checkDuplicateRequires, checkExcludedRequirements,
// checkAmbiguousComparisonQueries, and checkReplaceMissingVersion.
//
// Before the tool/module cases were added here, this same "recognized the
// keyword, couldn't parse a valid directive out of it" gap already existed
// for those two, one level upstream: parseToolLine (gomod.go) silently
// discarded any extra trailing field after a tool/module line's first
// token instead of rejecting the line, and ParseGoMod's four require/
// exclude call sites already surfaced their own equivalent gap into this
// same finding — see ParseGoMod's own doc comment for why a go.mod written
// this way (a plausible mistake: a copy-pasted or hand-edited tool/module
// line with a stray trailing word, or a dependency line missing its
// version field entirely — equally easy for a human or an AI assistant to
// produce) reported "checked N requirement(s), nothing flagged" despite
// being a go.mod the real go command refuses to build under any
// circumstances. The replace case had the identical gap — parseReplaceLine
// already rejected a malformed replace line, but ParseGoMod's two replace
// call sites just discarded the line instead of recording it here, the one
// directive family left out when this finding was first added — found and
// closed by this real-world-testing pass.
//
// checkReplaceMissingVersion (above) is a distinct, narrower check: it only
// ever sees replace directives parseReplaceLine already accepted as
// well-formed (a remote target that parsed fine but carries no version),
// so it never had any visibility into a replace line parseReplaceLine
// rejected outright — this check's replace case is the only place that gap
// is covered.
//
// Deduplicated on (Directive, Path) the same way checkAmbiguousComparisonQueries
// dedupes on (path, version): the identical malformed line repeated (e.g.
// inside vs. outside a block, or the same mistake made twice) is still one
// distinct unbuildable shape worth reporting once.
func checkMalformedDirectives(malformed []MalformedDirective) []Finding {
	var findings []Finding
	seen := make(map[MalformedDirective]bool, len(malformed))
	for _, m := range malformed {
		if seen[m] {
			continue
		}
		seen[m] = true
		module := m.Path
		if module == "" {
			module = "(unparseable " + m.Directive + " line)"
		}
		usage := malformedDirectiveUsage[m.Directive]
		findings = append(findings, Finding{
			Module:   module,
			Severity: SeverityHigh,
			Reason:   "malformed-" + m.Directive,
			Detail: "this " + m.Directive + " directive is malformed — the go command refuses to build this at all (\"" + usage +
				"\"), regardless of whether the module actually exists; this is a self-contradictory go.mod, not a heuristic",
		})
	}
	return findings
}

// CheckAll resolves replace directives against requirements and runs
// CheckRequirement over the result, concurrently (each call hits the
// module proxy over the network, so doing this sequentially doesn't
// scale to real dependency trees — see checkConcurrency). A requirement
// replaced with a local filesystem path is skipped entirely — there's
// no network-fetched code or meaningful alias name to check. A
// requirement replaced with another module is checked under that
// module's path, since that's what actually gets fetched and built. Any
// replace directive whose Old path isn't covered by a require entry at
// all is still checked, under its own New target — see
// orphanReplacementTargets. Findings are returned in the same order as
// reqs regardless of which goroutine finishes first, then any findings
// from orphan replacement targets, then any findings from tools (go.mod
// `tool` directive package paths not already covered by a requirement —
// see CheckTools, which is deliberately handed the original pre-replace
// reqs here, not the post-replace resolved list, plus reps itself so it
// can also recognize a tool path covered only by an orphan replace (no
// require line at all) as already handled by orphanReplacementTargets
// above — a `tool` directive names the module's declared, unreplaced
// path, and CheckTools's own doc comment explains the false positives
// that resulted from matching against resolved paths, and from having no
// visibility into reps at all), then finally any findings from exclude
// directives that match one of reqs's own require lines, exactly or via
// proxy-resolved version-query equivalence (see checkExcludedRequirements),
// then finally any findings from two require directives naming the same
// module path at different versions (see checkDuplicateRequires), then
// finally any findings from a require or exclude directive whose version is
// an ambiguous "<="/">" comparison query (see checkAmbiguousComparisonQueries),
// then finally any findings from a replace directive whose remote New side
// carries no version at all (see checkReplaceMissingVersion), then finally
// any findings from a require, exclude, tool, module, or replace directive
// line ParseGoMod recognized the keyword for but couldn't parse a
// well-formed argument list out of — a require/exclude line with no
// version field, a tool/module line with zero or more than one argument,
// or a replace line with no "=>" arrow (or the wrong field count on
// either side) (see checkMalformedDirectives and ParseGoMod's sixth
// return value) — all five
// listed checks are self-contradictory or unparseable go.mod
// shapes the real go command can't build at all, checked first among the
// returned findings' underlying causes but appended last here.
// checkDuplicateRequires, checkAmbiguousComparisonQueries,
// checkReplaceMissingVersion, and checkMalformedDirectives never need a
// proxy round-trip; checkExcludedRequirements usually doesn't either (only
// a require path that's also named by some exclude directive costs one),
// so all five are still cheap enough to run after the concurrent
// requirement scan rather than inside it.
//
// CheckTools's own findings are run through suppressForkOfDeclaredPopular
// too, same as every resolved requirement above — a tool directive that
// resolves to a legitimate fork of a popular module the go.mod already
// requires directly deserves the identical suppression a require line for
// that same fork would get; see the call site's own comment for why.
//
// checkReplaceMissingVersion is deliberately called with gomodReps, not
// reps, below — see its own doc comment for why the malformed-replace
// check needs the go.mod's own, pre-go.work-merge directive list.
//
// modulePath is the audited go.mod's own `module` directive value (see
// ParseGoMod's fifth return value), passed straight through to CheckTools
// so it can recognize a `tool` directive naming a package inside the main
// module itself as needing no proxy lookup — see CheckTools's own doc
// comment. malformed is ParseGoMod's sixth return value, passed straight
// through to checkMalformedDirectives.
//
// gomodReps is the audited go.mod's own replace directives, exactly as
// ParseGoMod returned them, *before* main's go.work overlay merge
// (mergeReplaces) — see checkReplaceMissingVersion's own call below for
// why that check needs this raw, unmerged list rather than reps (which,
// by the time CheckAll runs, may already have had a go.mod-level entry
// dropped in favor of an overlapping go.work-level one).
func CheckAll(reqs []Requirement, reps []Replacement, gomodReps []Replacement, tools []string, excludes []Requirement, modulePath string, malformed []MalformedDirective, proxy *ProxyClient) []Finding {
	replacements := make(map[string][]Replacement, len(reps))
	for _, r := range reps {
		replacements[r.Old] = append(replacements[r.Old], r)
	}

	// declared is the set of every require line's own literal path, before
	// any replace resolution — see isForkOfDirectlyDeclaredPopular's doc
	// comment for why this also needs to cover a fork required directly,
	// with no replace directive involved at all.
	declared := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		declared[r.Path] = true
	}

	var resolved []Requirement
	// replacedFrom[i] is the pre-replace Old path resolved[i] was
	// substituted in for via a require+replace pair, or "" if resolved[i]
	// is unreplaced (or reached via orphanReplacementTargets, which has no
	// covering require at all). suppressForkOfDeclaredPopular also checks
	// declared (below) independently of this, so a fork's Old path being ""
	// here doesn't by itself mean no suppression can apply — see
	// isForkOfDirectlyDeclaredPopular's own doc comment.
	var replacedFrom []string
	for _, r := range reqs {
		from := ""
		if rep, ok := selectReplace(replacements[r.Path], r.Path, r.Version, proxy); ok {
			if rep.IsLocal() {
				continue
			}
			from = r.Path
			r.Path = rep.New
			// A remote-target replace always pins an exact version of the
			// replacement module (go.dev/ref/mod#go-mod-file-replace); use
			// it in place of the original requirement's version, which
			// names a version of a different module once replaced — see
			// parseReplaceLine's NewVersion doc comment. NewVersion is only
			// ever "" here for a malformed go.mod missing the
			// otherwise-mandatory new-side version, in which case falling
			// back to the stale original version is still strictly better
			// than the alternative of checking retraction against a
			// version string that was never a version of this module at
			// all.
			if rep.NewVersion != "" {
				r.Version = rep.NewVersion
			}
		}
		resolved = append(resolved, r)
		replacedFrom = append(replacedFrom, from)
	}
	orphanTargets := orphanReplacementTargets(reqs, reps)
	for range orphanTargets {
		replacedFrom = append(replacedFrom, "")
	}
	resolved = append(resolved, orphanTargets...)

	results := make([][]Finding, len(resolved))
	sem := make(chan struct{}, checkConcurrency)
	var wg sync.WaitGroup
	for i, r := range resolved {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, r Requirement) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = CheckRequirement(r, proxy)
		}(i, r)
	}
	wg.Wait()

	var all []Finding
	for i, fs := range results {
		all = append(all, suppressForkOfDeclaredPopular(fs, replacedFrom[i], declared)...)
	}
	// A tool directive's resolved module gets the same fork-of-declared-
	// popular suppression as an ordinary requirement — see
	// suppressForkOfDeclaredPopular's own doc comment for why a fork
	// required directly alongside its genuine upstream must not be flagged
	// as name-collision-exact, and CheckAll's own comment above for why
	// this call passes "" for replacedFrom, same as an orphan replacement
	// target: a `tool` directive's resolved module is never itself the
	// New side of a require+replace pair (resolveToolPath walks the public
	// proxy directly, independent of any replace directive), so only the
	// declared (directly-required) fallback in suppressForkOfDeclaredPopular
	// can ever apply here, never isReplacementOfExactPopularMatch. Before
	// this fix, CheckTools's findings were appended raw, so the exact same
	// legitimate-fork shape isForkOfDirectlyDeclaredPopular exists to
	// suppress for a require line reappeared, unsuppressed, whenever the
	// fork was instead reached only through an uncovered `tool` directive
	// (a `tool` line with no covering require — CheckTools's own documented
	// reason for existing) — confirmed live: a go.mod requiring
	// github.com/bradfitz/gomemcache directly and carrying `tool
	// github.com/grafana/gomemcache/cmd/x` (no require/replace for the fork
	// at all) reported name-collision-exact against github.com/grafana/
	// gomemcache — the real, disclosed `"fork":true` fork run #474 already
	// fixed this exact false positive for, just reached one call site over.
	all = append(all, suppressForkOfDeclaredPopular(CheckTools(tools, reqs, reps, modulePath, proxy), "", declared)...)
	all = append(all, checkExcludedRequirements(reqs, excludes, proxy)...)
	all = append(all, checkDuplicateRequires(reqs)...)
	all = append(all, checkAmbiguousComparisonQueries(reqs, excludes)...)
	all = append(all, checkReplaceMissingVersion(gomodReps)...)
	all = append(all, checkMalformedDirectives(malformed)...)
	return all
}

// isReplacementOfExactPopularMatch reports whether newPath's base name is
// an exact-case-insensitive match of a popularModules entry whose full
// path is literally oldPath — i.e. newPath is a replace directive's New
// side substituted in for a require of exactly that well-known module.
func isReplacementOfExactPopularMatch(newPath, oldPath string) bool {
	if oldPath == "" {
		return false
	}
	match, exact, ok := closestPopularMatch(newPath, BaseName(newPath))
	return ok && exact && match == oldPath
}

// isForkOfDirectlyDeclaredPopular reports whether newPath's base name is an
// exact-case-insensitive match of a popularModules entry that the same
// go.mod also requires directly — declared, the set of every require
// line's own literal path (see CheckAll), independent of any replace
// directive at all.
//
// This is the same real, common, documented pattern
// suppressForkOfDeclaredPopular's own doc comment already covers for a
// require+replace pair (cockroachdb/cockroach's prometheus/client_golang
// => cockroachdb/client_golang, thanos-io/thanos's bradfitz/gomemcache =>
// themihai/gomemcache): a maintainer's own patched or improved fork,
// published as its own module — just required directly, side by side with
// the genuine upstream project, instead of swapped in via `replace`.
// Confirmed live against a third real, current, popular project's actual
// go.mod, 2026-09: grafana/grafana requires both github.com/bradfitz/
// gomemcache (the genuine, popular, established client whose base name
// this matches) *and* github.com/grafana/gomemcache directly — two
// ordinary require lines, no replace directive joining them at all.
// github.com/grafana/gomemcache has never been tagged on the proxy
// (VersionCount==0), so it clears looksUnestablishedForImpersonation; the
// GitHub API confirms it's literally `"fork": true, "source":
// "bradfitz/gomemcache"`, described "Go Memcached client library - forked
// and improved" — a real, deliberate, in-production fork, not an
// impersonation attempt. Before this fix it fired name-collision-exact,
// the tool's highest-severity finding, worded "verify this isn't a
// malicious clone before trusting it" — on a completely legitimate
// dependency of a major, actively-maintained open-source project.
// suppressForkOfDeclaredPopular's existing require+replace check
// (isReplacementOfExactPopularMatch) only ever fires when the flagged
// path was reached by replacing the exact same popular Old path; a fork
// required as its own ordinary top-level require line, with no replace
// involved anywhere, fell entirely outside it even though the same
// structural argument applies: the go.mod's author has already,
// separately, correctly named the genuine module elsewhere in the same
// file, so the look-alike require carries none of the "nothing else here
// names the real module" evidence the impersonation check exists to act
// on.
func isForkOfDirectlyDeclaredPopular(newPath string, declared map[string]bool) bool {
	match, exact, ok := closestPopularMatch(newPath, BaseName(newPath))
	return ok && exact && declared[match]
}

// suppressForkOfDeclaredPopular drops a name-collision-exact finding for a
// requirement that was reached by a require+replace pair whose Old side is
// itself, verbatim, a curated popularModules entry — i.e. the go.mod
// already correctly names the real, well-known module via require, and
// separately, deliberately substitutes a different-owner path in its
// place via replace. That shape is a live, real, and common pattern —
// confirmed against two actual, current, popular projects' own go.mod
// files: cockroachdb/cockroach requires github.com/prometheus/
// client_golang and replaces it with github.com/cockroachdb/client_golang
// (a patched fork, the replace directive's own adjacent comment pointing
// at "https://github.com/cockroachdb/client_golang/pulls for merged
// changes"), and thanos-io/thanos requires github.com/bradfitz/gomemcache
// and replaces it with github.com/themihai/gomemcache (a third-party fork,
// commented "Using a 3rd-party branch for custom dialer" with a link to
// the unmerged upstream PR). Both are neither tagged (VersionCount==0 on
// the fork's own module path) nor old enough by pseudo-version commit time
// to clear looksUnestablishedForImpersonation, so before this fix both
// fired name-collision-exact — the tool's highest-severity finding, worded
// "verify this isn't a malicious clone" — against two ordinary, documented
// vendor-fork overrides in widely-used, real-world go.mod files.
//
// This is a materially different situation from the impersonation shape
// name-collision-exact exists to catch (see closestPopularMatch's own
// "Beyond Takedown" citation): there, the *only* place the real module's
// name appears is the attacker-controlled path itself, standing in for
// the genuine module with nothing else in the go.mod to contradict it —
// exactly what an AI hallucinating or a human mistyping an import
// produces. Here, the genuine, correctly-spelled module is separately,
// unambiguously declared via its own require line, and replace's whole
// purpose is to name an alternate source for code otherwise identified by
// that require — the go.mod's author necessarily typed the real module's
// exact path once already to have anything for the replace to apply to.
// A malicious replace redirecting an already-correct require toward a
// look-alike source is a real but categorically different threat (tampering
// with build configuration itself, not a hallucinated dependency name) that
// this tool's scope has never covered — replace's New side already gets every
// other check (not-found, deprecated, retracted, version-flooded, and even
// the near-miss name-collision-risk check, none of which this function
// touches), same as any other requirement.
//
// Deliberately falls back to declared (see isForkOfDirectlyDeclaredPopular)
// rather than treating replacedFrom == "" as "never suppress": that covers
// both orphanReplacementTargets (see CheckAll's replacedFrom, always "" for
// those — an orphan replace's own Old path is never covered by any require
// line, but the go.mod can still separately, directly require the genuine
// module under its own require line with no connection to that particular
// replace at all) and a fork required directly with no replace involved
// anywhere (see isForkOfDirectlyDeclaredPopular's own doc comment for the
// real github.com/grafana/gomemcache case this exists for).
func suppressForkOfDeclaredPopular(findings []Finding, replacedFrom string, declared map[string]bool) []Finding {
	if len(findings) == 0 {
		return findings
	}
	var out []Finding
	for _, f := range findings {
		if f.Reason == "name-collision-exact" &&
			(isReplacementOfExactPopularMatch(f.Module, replacedFrom) || isForkOfDirectlyDeclaredPopular(f.Module, declared)) {
			continue
		}
		out = append(out, f)
	}
	return out
}
