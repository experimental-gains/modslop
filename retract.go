package main

import (
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// retraction reports whether checkVersion is covered by a `retract`
// directive in modBody (the go.mod the proxy serves for the module's
// @latest version — see ProxyClient.Lookup's LatestModBody fetch),
// returning the maintainer's rationale comment when one was given.
//
// A retracted version is not a proxy-availability problem at all:
// proxy.golang.org keeps serving it exactly like any other tagged
// version, and a plain `go install`/`go get`/`go mod download` succeeds
// outright — retraction is advisory only; only `go list -m -u` surfaces
// it. Confirmed live, 2026-09: github.com/mattn/go-sqlite3's go.mod (at
// its latest tag, v1.14.52) carries
//
//	retract (
//		[v2.0.0+incompatible, v2.0.7+incompatible] // Accidental; no major changes or features.
//	)
//
// yet a go.mod requiring github.com/mattn/go-sqlite3 v2.0.3+incompatible
// resolves and fetches cleanly, and modslop (before this check existed)
// reported "nothing flagged" for it — missing the one signal (the
// maintainer's own go.mod) that says "don't use this version," on
// exactly the kind of go.mod entry an AI assistant guessing at a
// plausible-looking "major bump" tag could produce. Ported from
// goproxycheck's identical retraction() (v0.1.25), which found and fixed
// this same gap in a sibling tool first.
func retraction(modBody, checkVersion string) (rationale string, retracted bool) {
	if checkVersion == "" || modBody == "" {
		return "", false
	}
	mf, err := modfile.Parse("go.mod", []byte(modBody), nil)
	if err != nil || mf == nil {
		return "", false
	}
	for _, r := range mf.Retract {
		if r.Low == "" || r.High == "" {
			continue
		}
		// semver.Compare ignores build metadata (the "+incompatible"
		// suffix) for ordering purposes, matching real semantic-versioning
		// precedence rules — confirmed against the go-sqlite3 case above,
		// where the checked version and both interval bounds all carry it.
		if semver.Compare(checkVersion, r.Low) >= 0 && semver.Compare(checkVersion, r.High) <= 0 {
			return r.Rationale, true
		}
	}
	return "", false
}
