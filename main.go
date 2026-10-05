// Command modslop audits a Go module's dependencies for signs of
// slopsquatting: names that don't exist, names that are suspiciously
// close to a well-known module, and modules that are brand-new with
// no track record. See README.md for the full rationale.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("modslop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "machine-readable output, e.g. for CI")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: modslop [--json] [path/to/go.mod]")
		_, _ = fmt.Fprintln(stderr, "  with no argument, checks ./go.mod")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if fs.NArg() > 1 {
		_, _ = fmt.Fprintf(stderr, "modslop: expected at most one argument (path to go.mod), got %d\n", fs.NArg())
		return 2
	}
	path := "go.mod"
	if fs.NArg() == 1 {
		path = fs.Arg(0)
	}

	reqs, reps, tools, excludes, modulePath, malformed, godebugs, err := LoadGoMod(path)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "modslop:", err)
		return 2
	}
	// go.mod's own directory, not the process's cwd: this tool accepts an
	// explicit path to a go.mod that can live anywhere (a wrapper script
	// auditing several repos in a loop without cd'ing into each one is a
	// normal way to invoke it), but `go env` — and in particular its
	// GOWORK auto-discovery, which walks upward from a directory looking
	// for a go.work — resolves everything relative to the directory it's
	// run in, not any path handed to it (confirmed live: `go env GOWORK`
	// run from a workspace member's own directory finds that workspace's
	// go.work; the identical command run from an unrelated directory,
	// even when passed that member's go.mod as this tool's own CLI
	// argument, finds nothing). Running `go env` with cmd.Dir pinned to
	// modDir instead of the ambient cwd is what makes this tool see
	// exactly the go.work (and any other directory-scoped `go env` state)
	// that a real `go build` run from inside modDir would see — before
	// this fix, auditing a go.mod from outside its own directory silently
	// dropped its workspace's replace directives, which reintroduces the
	// exact "legitimate go.work-satisfied dependency flagged as
	// not-found" false positive goWorkReplaces/mergeReplaces were built to
	// prevent, just via a different code path.
	modDir := filepath.Dir(path)
	// gomodReps keeps the go.mod's own, pre-overlay replace directives
	// around separately from reps (which mergeReplaces below turns into
	// the workspace-resolved list used for ordinary requirement
	// resolution) — CheckAll needs both: see checkReplaceMissingVersion's
	// own doc comment for why a malformed replace directive must be
	// checked against the go.mod's own literal directives, never a list
	// a go.work overlay may have silently dropped it from.
	gomodReps := reps
	// goWorkPath, not a bare goEnv("GOWORK", modDir) call: see its own doc
	// comment below for why GOWORK resolution itself (not just reading the
	// file it names) can be the thing real go Fatals on.
	gowork, goworkResolveErr := goWorkPath(modDir)
	reps = mergeReplaces(reps, goWorkReplaces(gowork))
	// inWorkspace is true exactly when gowork resolves to a real, readable
	// go.work — the same condition the go.work-content block below this
	// gates on. See checkDuplicateRequires/checkExcludedRequirements's own
	// doc comments (check.go) for why CheckAll needs this: both checks
	// flag a go.mod self-contradiction (duplicate require, require+
	// exclude) that real go unconditionally Fatals on when the go.mod is
	// built standalone, but silently tolerates once it's built as a
	// workspace member instead — confirmed live, go1.22.0 and go1.24.4
	// both agree.
	inWorkspace := goworkResolveErr == "" && gowork != "" && gowork != "off"

	proxy := NewProxyClient()
	proxy.PrivatePatterns = goNoProxyPatterns(modDir)
	all := CheckAll(reqs, reps, gomodReps, tools, excludes, modulePath, malformed, godebugs, proxy, inWorkspace)
	// localGoVersion is the toolchain actually selected to run modDir — an
	// environment fact, not something derivable from either file's content
	// alone — resolved once here (rather than queried from deep inside the
	// check layer) and handed to every toolchain-version-gated check below,
	// go.mod-side and go.work-side alike, the same way
	// goNoProxyPatterns/goWorkReplaces's own `go env` results are resolved
	// in main() and handed to pure functions.
	localGoVersion := goEnv("GOVERSION", modDir)
	// checkIgnoreDirectiveTooOld needs the go.mod's raw content (to look
	// for a top-level `ignore` directive and the file's own `go` directive
	// version) plus localGoVersion above. Re-reading path here (LoadGoMod
	// already read it once above) is deliberately best-effort, like every
	// other goEnv-derived lookup in this file: a failure here just means
	// this one check doesn't run, not that the rest of the audit aborts.
	if data, rerr := os.ReadFile(path); rerr == nil {
		// checkGoVersionUnsatisfiable is strictly prior to
		// checkIgnoreDirectiveTooOld and its two siblings just below: it
		// asks whether a toolchain was resolved that satisfies the go.mod's
		// own declared `go` minimum AT ALL, before any of them get to ask
		// their own narrower "is this one verb recognized" question — see
		// its own doc comment in check.go for the two live-verified Fatal
		// shapes this collapses.
		all = append(all, checkGoVersionUnsatisfiable(string(data), localGoVersion)...)
		all = append(all, checkIgnoreDirectiveTooOld(string(data), localGoVersion)...)
		// checkToolDirectiveTooOld/checkGodebugDirectiveTooOld are
		// checkIgnoreDirectiveTooOld's siblings at two other real version
		// boundaries (go1.24 and go1.23, both below `ignore`'s go1.25) —
		// see their own doc comments in check.go.
		all = append(all, checkToolDirectiveTooOld(string(data), localGoVersion)...)
		all = append(all, checkGodebugDirectiveTooOld(string(data), localGoVersion)...)
		// Mirrors checkGoWorkUnknownDirective one file type back: go.mod
		// itself was never checked against its own grammar's known-verb
		// set either, only go.work's narrower one — see
		// goModUnknownDirective's own doc comment.
		all = append(all, checkGoModUnknownDirective(string(data))...)
	}
	// checkGoWorkUnresolvable handles the case where GOWORK can't even be
	// resolved to a path at all (e.g. a relative value) — see its own doc
	// comment in check.go. There's no file to read or checks to run below
	// in that case; goworkResolveErr being set means gowork is always "".
	all = append(all, checkGoWorkUnresolvable(goworkResolveErr)...)
	// Mirrors the check above one file over: checkGoWorkUnknownDirective
	// needs the go.work's own raw content (to look for a top-level verb
	// go.work's grammar doesn't support at all). Same "" / "off" guard
	// goWorkReplaces itself uses — gowork == "off" means GOWORK is
	// explicitly disabled, not a literal filename to read.
	if goworkResolveErr == "" && gowork != "" && gowork != "off" {
		if data, rerr := os.ReadFile(gowork); rerr == nil {
			all = append(all, checkGoWorkUnknownDirective(string(data))...)
			all = append(all, checkGoWorkInvalidQuotedToken(string(data))...)
			all = append(all, checkGoWorkUnterminatedQuotedString(string(data))...)
			// checkGoWorkBlockForm is checkGoWorkUnterminatedQuotedString's
			// sibling for the other real "no block form at all" Fatal
			// shape go.work's `go`/`toolchain` directives share with
			// go.mod's — see its own doc comment in check.go.
			all = append(all, checkGoWorkBlockForm(string(data))...)
			// checkGoWorkUseDirectiveMalformed is this same cluster's
			// `use`-directive-specific sibling — see its own doc comment
			// in check.go for why `use` needed a dedicated scan rather
			// than reuse of the two generic quoting checks just above.
			all = append(all, checkGoWorkUseDirectiveMalformed(string(data))...)
			all = append(all, checkGoWorkReplaceMissingVersion(string(data))...)
			// checkGoWorkVersionUnsatisfiable is checkGoVersionUnsatisfiable's
			// go.work-side port, checked ahead of checkGoWorkGodebugDirectiveTooOld
			// just below for the identical "strictly prior" reason
			// checkGoVersionUnsatisfiable's own call site above is ordered
			// ahead of checkIgnoreDirectiveTooOld and its siblings — see its
			// own doc comment in check.go.
			all = append(all, checkGoWorkVersionUnsatisfiable(string(data), localGoVersion)...)
			// checkGoWorkGodebugDirectiveTooOld is checkGodebugDirectiveTooOld's
			// go.work-side port — a go.work carrying its own `godebug`
			// directive is gated on the identical go1.23 toolchain boundary
			// as go.mod's, using the same localGoVersion computed above.
			// See its own doc comment in check.go for the live
			// verification.
			all = append(all, checkGoWorkGodebugDirectiveTooOld(string(data), localGoVersion)...)
		} else {
			// checkGoWorkUnreadable: unlike the best-effort os.ReadFile
			// guards elsewhere in this function (re-reading a go.mod/
			// go.work this tool has already successfully located), a
			// resolved-but-unreadable GOWORK path is itself exactly as
			// fatal to the real go command as every other
			// "self-contradictory, not a heuristic" finding in this file
			// — see its own doc comment in check.go.
			all = append(all, checkGoWorkUnreadable(gowork, rerr)...)
		}
	}

	if *jsonOut {
		// encoding/json marshals a nil slice as the JSON literal "null",
		// not "[]" — Go's own nil-slice-vs-empty-slice distinction leaking
		// into the wire format. CheckAll returns nil (never an allocated
		// empty slice) whenever nothing was flagged, since every finding
		// list it aggregates from (evaluateModuleStatus, CheckTools,
		// checkExcludedRequirements) is built with the idiomatic `var
		// findings []Finding` and never explicitly emptied. That's the
		// common case in practice — most go.mod files flag nothing — so
		// `modslop --json` on a clean go.mod prints literal `null`, not
		// `[]`, despite the README documenting --json as "machine-readable
		// output, e.g. for CI". Confirmed live: `json.loads(out)` in Python
		// on that output yields None, and code a CI script would naturally
		// write (`for f in json.loads(out): ...`) raises "TypeError:
		// 'NoneType' object is not iterable" on the clean-repo case
		// specifically — the one case that's actually common. Normalizing
		// here, at the JSON-encoding boundary, keeps CheckAll's internal
		// nil-slice-is-idiomatic-Go return value untouched for every
		// in-process caller (CheckAll's own tests all compare len(), never
		// nil-ness) while guaranteeing the machine-readable contract always
		// emits a JSON array.
		if all == nil {
			all = []Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(all); err != nil {
			_, _ = fmt.Fprintln(stderr, "modslop:", err)
			return 2
		}
	} else {
		// checkedDesc always names every directive kind CheckAll can ever
		// source a finding from, not just requirement(s) — a go.mod can be
		// flagged purely via a `tool` directive with zero `require` lines
		// at all (CheckTools's whole reason to exist: see its own doc
		// comment on the require-less gap a hand-written or AI-generated
		// go.mod can leave), so reporting only len(reqs) produced the
		// self-contradictory "1 finding(s) across 0 requirement(s)" —
		// confirmed live with `tool example.com/nonexistent-org/fake-tool`
		// and no require block at all. Appending the tool count whenever
		// any tool directives exist keeps the common, tool-less case's
		// message unchanged.
		checkedDesc := fmt.Sprintf("%d requirement(s)", len(reqs))
		if len(tools) > 0 {
			checkedDesc += fmt.Sprintf(", %d tool(s)", len(tools))
		}
		if len(all) == 0 {
			_, _ = fmt.Fprintf(stdout, "modslop: checked %s, nothing flagged\n", checkedDesc)
		} else {
			for _, f := range all {
				_, _ = fmt.Fprintf(stdout, "[%s] %s: %s (%s)\n", f.Severity, f.Module, f.Detail, f.Reason)
			}
			_, _ = fmt.Fprintf(stdout, "\nmodslop: %d finding(s) across %s\n", len(all), checkedDesc)
		}
	}

	if len(all) > 0 {
		return 1
	}
	return 0
}

// goNoProxyPatterns reads the local `go` command's effective GONOPROXY
// via `go env` rather than os.Getenv, so a value persisted with `go env
// -w` or defaulted from GOPRIVATE (GONOPROXY falls back to GOPRIVATE when
// unset — confirmed live: `go env GONOPROXY` already returns the resolved
// GOPRIVATE value in that case, no separate fallback needed here) is
// picked up too, not just an explicit env var — `go env` is the
// authoritative source either way, same rationale as goproxycheck's
// localGoproxyOff.
func goNoProxyPatterns(dir string) []string {
	return splitPatterns(goEnv("GONOPROXY", dir))
}

// goEnv returns the effective value of a `go env` variable, or "" if the
// `go` command isn't available or the lookup otherwise fails (best-effort:
// don't block the real check on this). dir is the directory `go env` runs
// in — see the modDir comment in main for why that must be the audited
// go.mod's own directory rather than whatever directory this process
// happens to be started from.
func goEnv(name, dir string) string {
	cmd := exec.Command("go", "env", name)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// goWorkPath is goEnv("GOWORK", dir)'s dedicated GOWORK variant: unlike
// every other `go env` variable this tool looks up (GOVERSION, GONOPROXY),
// a failure of the `go env GOWORK` command itself can mean real go would
// Fatal unconditionally, not just "no value, nothing to check here."
//
// Real cmd/go's FindGoWork (modload/init.go) requires an explicitly-set
// GOWORK — anything other than "", "auto", or "off" — to be an absolute
// path, and Fatals immediately ("invalid GOWORK: not an absolute path")
// otherwise, before resolving a single module. `go env GOWORK` itself
// hits the identical Fatal, since it calls the same resolution
// internally. Confirmed live, 2026-10-04, go1.24.4: a relative GOWORK
// value makes both `go list -m all` and `go env GOWORK` fail with that
// exact message. goEnv's own blanket "any command failure means empty
// string" contract (correct for every other variable it's used for here)
// would make this indistinguishable from "no GOWORK set at all" — the
// genuinely clean case — so goWorkPath instead reports the command's
// stderr text as resolveErr whenever it fails, leaving path empty, so a
// caller can tell "no workspace" and "GOWORK itself is broken" apart.
//
// This only covers resolution failure; a GOWORK value that resolves fine
// but names an unreadable path (missing, a directory, permission-denied)
// is a separate, later failure — see checkGoWorkUnreadable's own doc
// comment for that case, live-verified the same day.
func goWorkPath(dir string) (path, resolveErr string) {
	cmd := exec.Command("go", "env", "GOWORK")
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", msg
		}
		return "", err.Error()
	}
	return strings.TrimSpace(string(out)), ""
}
