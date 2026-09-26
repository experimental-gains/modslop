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

	reqs, reps, tools, err := LoadGoMod(path)
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
	reps = mergeReplaces(reps, goWorkReplaces(goEnv("GOWORK", modDir)))

	proxy := NewProxyClient()
	proxy.PrivatePatterns = goNoProxyPatterns(modDir)
	all := CheckAll(reqs, reps, tools, proxy)

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(all); err != nil {
			_, _ = fmt.Fprintln(stderr, "modslop:", err)
			return 2
		}
	} else {
		if len(all) == 0 {
			_, _ = fmt.Fprintf(stdout, "modslop: checked %d requirement(s), nothing flagged\n", len(reqs))
		} else {
			for _, f := range all {
				_, _ = fmt.Fprintf(stdout, "[%s] %s: %s (%s)\n", f.Severity, f.Module, f.Detail, f.Reason)
			}
			_, _ = fmt.Fprintf(stdout, "\nmodslop: %d finding(s) across %d requirement(s)\n", len(all), len(reqs))
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
