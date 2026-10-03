// Command modslop audits a Go module's dependencies for signs of
// slopsquatting: names that don't exist, names that are suspiciously
// close to a well-known module, and modules that are brand-new with
// no track record. See README.md for the full rationale.
package main

import (
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
	gowork := goEnv("GOWORK", modDir)
	reps = mergeReplaces(reps, goWorkReplaces(gowork))

	proxy := NewProxyClient()
	proxy.PrivatePatterns = goNoProxyPatterns(modDir)
	all := CheckAll(reqs, reps, gomodReps, tools, excludes, modulePath, malformed, godebugs, proxy)
	// checkIgnoreDirectiveTooOld needs the go.mod's raw content (to look
	// for a top-level `ignore` directive and the file's own `go` directive
	// version) plus the toolchain actually selected to run it — an
	// environment fact, not something derivable from the file alone — so
	// it's composed here rather than threaded through CheckAll's own
	// signature, the same way goNoProxyPatterns/goWorkReplaces's `go env`
	// results are resolved in main() and handed to pure functions rather
	// than queried from deep inside the check layer. Re-reading path here
	// (LoadGoMod already read it once above) is deliberately best-effort,
	// like every other goEnv-derived lookup in this file: a failure here
	// just means this one check doesn't run, not that the rest of the
	// audit aborts.
	if data, rerr := os.ReadFile(path); rerr == nil {
		all = append(all, checkIgnoreDirectiveTooOld(string(data), goEnv("GOVERSION", modDir))...)
	}
	// Mirrors the check above one file over: checkGoWorkUnknownDirective
	// needs the go.work's own raw content (to look for a top-level verb
	// go.work's grammar doesn't support at all), read directly here for
	// the same best-effort-only reason every other goEnv-derived lookup
	// in this file is: a failure here just means this one check doesn't
	// run, not that the rest of the audit aborts. Same "" / "off" guard
	// goWorkReplaces itself uses — gowork == "off" means GOWORK is
	// explicitly disabled, not a literal filename to read.
	if gowork != "" && gowork != "off" {
		if data, rerr := os.ReadFile(gowork); rerr == nil {
			all = append(all, checkGoWorkUnknownDirective(string(data))...)
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
