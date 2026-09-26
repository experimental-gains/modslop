package main

import "golang.org/x/mod/modfile"

// deprecation reports whether modBody's `module` directive carries a
// deprecation notice (a comment paragraph starting "Deprecated:"
// immediately attached to the module directive, per
// go.dev/ref/mod#go-mod-file-module), returning the message with the
// "Deprecated:" prefix already stripped.
//
// Like retraction, this is a whole-module signal read from the module's
// *latest* go.mod (status.LatestModBody), not the checked version's own —
// confirmed live (2026-09-26): github.com/golang/protobuf's go.mod carries
//
//	// Deprecated: Use the "google.golang.org/protobuf" module instead.
//	module github.com/golang/protobuf
//
// only as of its latest tag (v1.5.4); v1.3.0's own go.mod predates the
// comment entirely, yet `go get github.com/golang/protobuf@v1.3.0` still
// prints "go: module github.com/golang/protobuf is deprecated: ...".
// Reading the checked version's own go.mod instead would miss the notice
// for every version published before the maintainer added it. Ported from
// goproxycheck's identical deprecation() (v0.1.31), which found and fixed
// this same gap in a sibling tool first — same reasoning that brought
// retraction() over from goproxycheck originally.
//
// golang.org/x/mod/modfile.Parse already extracts this into
// mf.Module.Deprecated — no custom comment parsing needed.
func deprecation(modBody string) (message string, deprecated bool) {
	if modBody == "" {
		return "", false
	}
	mf, err := modfile.Parse("go.mod", []byte(modBody), nil)
	if err != nil || mf == nil || mf.Module == nil || mf.Module.Deprecated == "" {
		return "", false
	}
	return mf.Module.Deprecated, true
}
