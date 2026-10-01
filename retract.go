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
//
// Every matching retract entry is walked, unconditionally — not just the
// first one found — and the retracted bit is ORed across all of them,
// keeping the first non-empty rationale seen. Real cmd/go's own
// CheckRetractions (modload/modfile.go) does exactly this: it iterates
// every retract entry in file order and uses whichever matching entry's
// rationale is non-empty, not necessarily the first matching entry at
// all. A go.mod can carry more than one *separate* top-level retract
// statement covering the same version — not the already-handled "one
// retract block whose leading comment modfile.Parse attributes only to
// its first entry" shape (see the rationale-fallback comment below), but
// two independent statements anywhere in the file, e.g.:
//
//	retract v1.0.0
//
//	retract [v0.9.0, v1.0.0] // superseded, use v1.2.3 instead
//
// both cover v1.0.0. Before this fix, retraction() returned on the first
// matching entry unconditionally (its Low/High bounds, and its
// Rationale, empty or not) — this exact shape, the identical bug
// goproxycheck's own retraction() was found and fixed for (a sibling
// tool's independent go.mod-retraction parser, not shared code) — so a
// go.mod shaped like the example above reported "retracted by module
// author" with no rationale, even though the module's own go.mod plainly
// explains why, just on a second, later retract statement covering the
// same version. Confirmed live, 2026-09-30 (go1.24.4, a from-scratch
// local file-based GOPROXY serving the exact go.mod above): real `go
// list -m -u -retracted -f '{{.Retracted}}'` reports
// "[superseded, use v1.2.3 instead]" — the second statement's rationale
// — never the bare, rationale-less first one.
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
			retracted = true
			if rationale == "" && r.Rationale != "" {
				rationale = r.Rationale
			}
		}
	}
	return rationale, retracted
}
