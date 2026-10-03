package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunHelpFlag is the regression test for a real bug found via a live
// `brew install` + manual invocation (run #351): unlike goproxycheck and
// goprivaudit, which both parse args with the stdlib flag package and so
// get -h/--help for free, modslop hand-rolled its own arg loop that
// treated *any* unrecognized argument — including "-h" and "--help" — as
// the go.mod path to audit. Asking for help silently tried to open a file
// literally named "-h" and failed with a confusing "no such file or
// directory" error instead of printing usage. Fixed by switching to
// flag.FlagSet (matching the other two tools' established pattern), which
// makes this both fixed and trivially testable without spawning a real
// process.
func TestRunHelpFlag(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{flag}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("run([%q]) = %d, want 2", flag, code)
		}
		if !strings.Contains(stderr.String(), "usage: modslop") {
			t.Errorf("run([%q]) stderr = %q, want it to contain usage text", flag, stderr.String())
		}
	}
}

func TestRunChecksGivenPath(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run([%q]) = %d, stderr = %q, want 0", gomod, code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "nothing flagged") {
		t.Errorf("run([%q]) stdout = %q, want it to report nothing flagged", gomod, stdout.String())
	}
}

// TestRunJSONCleanRepoIsArrayNotNull is the regression test for a real
// bug: encoding/json marshals a nil slice as the JSON literal "null", and
// CheckAll returns nil (not an allocated empty slice) whenever nothing
// gets flagged — the common case for any healthy go.mod, and exactly the
// case a clean CI run hits every time. `modslop --json` printed literal
// "null" for it instead of "[]", despite the README documenting --json as
// machine-readable CI output. Confirmed live: `json.loads(out)` in Python
// on the pre-fix output yields None, and the natural CI consumer code
// (`for f in json.loads(out): ...`) raises "TypeError: 'NoneType' object
// is not iterable" on precisely the clean-repo case. See main.go's
// json.Encoder call site for the fix.
func TestRunJSONCleanRepoIsArrayNotNull(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--json", gomod}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run([\"--json\", %q]) = %d, stderr = %q, want 0", gomod, code, stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	if got != "[]" {
		t.Errorf("run([\"--json\", %q]) stdout = %q, want the JSON array \"[]\", not the null literal a nil-slice encode produces", gomod, got)
	}
}

// TestRunTooManyArgsFails is the regression test for a real bug: the
// stdlib flag package stops parsing at the first non-flag argument, so
// "modslop go.mod --json" (a flag placed after the path — a natural
// ordering, and the only one the pre-run-#351 hand-rolled parser
// supported) left "--json" as a second positional argument rather than a
// parsed flag. The pre-fix code picked fs.Arg(fs.NArg()-1) — the *last*
// positional argument — as the go.mod path, so it silently tried to open
// a file literally named "--json" and failed with a confusing "no such
// file or directory" error instead of a clear one. goproxycheck (the
// sibling tool with the same optional-single-positional-arg shape)
// already rejects more than one positional argument outright; this ports
// that behavior here instead of guessing which argument is the path.
func TestRunTooManyArgsFails(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod, "--json"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("run([%q, \"--json\"]) = %d, want 2", gomod, code)
	}
	if strings.Contains(stderr.String(), "no such file or directory") {
		t.Errorf("run([%q, \"--json\"]) stderr = %q, want a clear too-many-args error, not a confusing file-not-found one", gomod, stderr.String())
	}
}

func TestRunUnknownFlagFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--nope"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("run([\"--nope\"]) = %d, want 2", code)
	}
}

// TestRunToolOnlyFindingReportsToolCount is the regression test for a real
// bug: a go.mod can be flagged purely via a `tool` directive with zero
// `require` lines at all (a legal, if unusual, shape — see CheckTools's own
// doc comment on the require-less gap it exists to cover), and the summary
// line used len(reqs) alone as its denominator, printing the
// self-contradictory "1 finding(s) across 0 requirement(s)" — a reader has
// no way to tell from that message how a finding could exist against zero
// checked requirements. Fixed by naming the tool count too whenever any
// tool directives are present.
func TestRunToolOnlyFindingReportsToolCount(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	src := "module example.com/foo\n\ngo 1.24\n\ntool example.com/nonexistent-org/fake-tool-xyz\n"
	if err := os.WriteFile(gomod, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stderr = %q, want 1 (the tool directive should be flagged)", gomod, code, stderr.String())
	}
	got := stdout.String()
	if strings.Contains(got, "across 0 requirement(s)\n") {
		t.Errorf("run([%q]) stdout = %q, want it not to claim 0 requirement(s) were checked with nothing else named, when the finding actually came from a tool directive", gomod, got)
	}
	if !strings.Contains(got, "1 tool(s)") {
		t.Errorf("run([%q]) stdout = %q, want it to name the 1 tool directive that was actually checked", gomod, got)
	}
}

// TestGoEnvGOWORK_UsesGivenDirNotProcessCwd is the regression test for a
// real bug: main() previously called goEnv("GOWORK") with no directory
// argument at all, so the underlying `go env GOWORK` call — which
// auto-discovers a go.work by walking upward from *the directory it runs
// in* (confirmed live: `go env GOWORK` run from inside a workspace
// member's own directory finds that workspace's go.work; run from any
// other directory it finds nothing, even when that other directory is
// where this process happens to have been started from) — resolved
// relative to this process's ambient cwd instead of the go.mod file
// modslop was actually told to audit. modslop's own CLI explicitly
// accepts a path to a go.mod anywhere on disk (a wrapper script auditing
// several repos in a loop without cd'ing into each one is a normal way to
// invoke it), so "cwd happens to match the audited go.mod's directory"
// isn't a safe assumption — when it doesn't hold, the workspace's replace
// directives were silently dropped, which reintroduces exactly the
// "legitimate go.work-satisfied dependency flagged as not-found" false
// positive goWorkReplaces/mergeReplaces exist to prevent (see
// TestCheckAll_GoWorkOnlyLocalReplaceSuppressesRequirementCheck in
// check_test.go), just via a different code path: main() never even
// finding the go.work in the first place, rather than mishandling one it
// did find.
//
// This test proves goEnv itself resolves per the dir argument by running
// go env GOWORK from a *different* directory than the one containing the
// go.work, passing the workspace member's own directory explicitly —
// exactly how main() now calls it (dir = filepath.Dir(path), not the
// process's cwd).
func TestGoEnvGOWORK_UsesGivenDirNotProcessCwd(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	root := t.TempDir()
	workPath := filepath.Join(root, "go.work")
	memberDir := filepath.Join(root, "member")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workPath, []byte("go 1.22\n\nuse ./member\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(memberDir, "go.mod"),
		[]byte("module example.com/member\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The test binary's own cwd is unrelated to root/memberDir, so this
	// only passes if goEnv actually runs `go env` with cmd.Dir set to the
	// directory we hand it, not the ambient process cwd.
	got := goEnv("GOWORK", memberDir)
	want, err := filepath.EvalSymlinks(workPath)
	if err != nil {
		t.Fatal(err)
	}
	gotResolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("goEnv(\"GOWORK\", %q) = %q, which doesn't resolve: %v", memberDir, got, err)
	}
	if gotResolved != want {
		t.Errorf("goEnv(\"GOWORK\", %q) = %q, want %q (go.work was not discovered relative to the given dir)", memberDir, got, want)
	}

	// Sanity check on the other side of the fix: a directory with no
	// go.work anywhere above it must not find this one.
	elsewhere := t.TempDir()
	if got := goEnv("GOWORK", elsewhere); got != "" {
		t.Errorf("goEnv(\"GOWORK\", %q) = %q, want \"\" (this dir has no go.work of its own)", elsewhere, got)
	}
}

// TestRunGoWorkUnknownDirectiveFlagged is the end-to-end regression test
// for a real bug (run #672): a go.work file's own grammar
// (golang.org/x/mod/modfile's WorkFile.add) only recognizes
// go/toolchain/godebug/use/replace — a strict subset of go.mod's own
// grammar — but goWorkReplaces reused go.mod's parser to read go.work
// content with no awareness of that restriction. A go.work carrying a
// `require` line (not valid go.work grammar at all) made real
// `go build`/`go list -m all`, run from inside the workspace member,
// Fatal immediately with "unknown directive: require" before resolving
// a single module — including the replace directive sitting right next
// to it in the same file (live-verified, go1.24.4/go1.26.8, GOPROXY=off).
// Before this fix, modslop's run() reported "nothing flagged" for this
// exact go.mod, silently trusting a go.work the real go command refuses
// to build at all. See goWorkUnknownDirective's own doc comment in
// gomod.go for the full detail.
func TestRunGoWorkUnknownDirectiveFlagged(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	root := t.TempDir()
	memberDir := filepath.Join(root, "member")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workSrc := "go 1.24\n\nuse ./member\n\nrequire example.com/bogus v1.0.0\n\nreplace example.com/bogus => ./nowhere\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(workSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(memberDir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/member\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (the broken go.work should be flagged)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-unknown-directive") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the go.work's unsupported 'require' directive", gomod, got)
	}
}
