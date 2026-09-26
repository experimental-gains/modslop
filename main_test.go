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
