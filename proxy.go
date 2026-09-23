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
func escapeModulePath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r - 'A' + 'a')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
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

// Lookup queries the proxy for a module's existence, version count,
// and the timestamp of its latest release.
func (c *ProxyClient) Lookup(modPath string) ModuleStatus {
	if matchesAnyPattern(modPath, c.PrivatePatterns) {
		return ModuleStatus{Private: true}
	}

	escaped := escapeModulePath(modPath)

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
	if verr == nil && vstatus == 200 {
		lines := strings.FieldsFunc(strings.TrimSpace(string(vbody)), func(r rune) bool { return r == '\n' })
		result.VersionCount = len(lines)

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
			if _, tbody, terr := c.get(fmt.Sprintf("%s/%s/@v/%s.info", c.BaseURL, escaped, lines[0])); terr == nil {
				var tagInfo latestInfo
				if json.Unmarshal(tbody, &tagInfo) == nil {
					if tt, err := time.Parse(time.RFC3339, tagInfo.Time); err == nil {
						result.LatestTime = tt
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
			if _, ebody, eerr := c.get(fmt.Sprintf("%s/%s/@v/%s.info", c.BaseURL, escaped, earliest)); eerr == nil {
				var earliestInfo latestInfo
				if json.Unmarshal(ebody, &earliestInfo) == nil {
					if et, err := time.Parse(time.RFC3339, earliestInfo.Time); err == nil {
						result.EarliestTime = et
					}
				}
			}
		}
	}
	return result
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
// same repo, just a major-version bump. Checking one predecessor major
// version is enough: it's already evidence of an established project,
// and walking further back adds proxy calls without changing the answer.
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

	var predecessor string
	switch {
	case n-1 >= 2 || gopkgIn: // gopkg.in requires ".vN" for all N, even 1
		predecessor = prefix + sep + strconv.Itoa(n-1)
	case n-1 == 1:
		predecessor = prefix // implicit v0/v1, no suffix
	default:
		return false
	}

	status := c.Lookup(predecessor)
	if !status.Exists {
		return false
	}
	return status.VersionCount > 1 || time.Since(status.LatestTime) >= recentWindow
}
