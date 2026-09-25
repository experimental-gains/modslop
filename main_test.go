package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

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
