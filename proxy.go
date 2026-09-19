package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const proxyBaseURL = "https://proxy.golang.org"

// ProxyClient talks to a Go module proxy (proxy.golang.org by default)
// to answer two questions a hallucinated or freshly-squatted module
// can't fake: does this path resolve at all, and if so, how long has
// it existed?
type ProxyClient struct {
	BaseURL string
	HTTP    *http.Client
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
	VersionCount int
	LatestTime   time.Time
}

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
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// Lookup queries the proxy for a module's existence, version count,
// and the timestamp of its latest release.
func (c *ProxyClient) Lookup(modPath string) ModuleStatus {
	escaped := escapeModulePath(modPath)

	status, body, err := c.get(fmt.Sprintf("%s/%s/@latest", c.BaseURL, escaped))
	if err != nil {
		return ModuleStatus{Unknown: true}
	}
	if status == 404 || status == 410 {
		return ModuleStatus{Exists: false}
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
	}
	return result
}
