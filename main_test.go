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

// TestRunGoWorkInvalidQuotedTokenFlagged is the end-to-end regression test
// for a backtick-wrapped go.work replace target: real `go build`/`go list
// -m all` Fatals immediately with "invalid quoted string: unquoted string
// cannot contain quote" (live-verified, go1.24.4/go1.26.8, GOPROXY=off),
// before resolving a single module in the workspace. Before this fix,
// modslop's goWorkReplaces extracted and trusted that same replace
// directive regardless, so a member's own otherwise-hallucinated
// requirement it was meant to redirect locally reported a plain
// "not-found" with no hint the workspace itself can't build at all.
func TestRunGoWorkInvalidQuotedTokenFlagged(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	root := t.TempDir()
	memberDir := filepath.Join(root, "member")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workSrc := "go 1.24\n\nuse ./member\n\nreplace example.com/bogus => `./nowhere`\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(workSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(memberDir, "go.mod")
	gomodSrc := "module example.com/member\n\ngo 1.24\n\nrequire example.com/bogus v1.0.0\n"
	if err := os.WriteFile(gomod, []byte(gomodSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (the broken go.work should be flagged)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-invalid-quoted-token") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the go.work's backtick-wrapped replace target", gomod, got)
	}
}

// TestRunGoWorkReplaceMissingVersionFlagged is the end-to-end regression
// test for a real bug: a go.work replace directive redirecting a module to
// a remote (non-local) target with no version makes real `go build`/`go
// list -m all` Fatal immediately with "replacement module without version
// must be directory path (rooted or starting with . or ..)" — live-
// verified, go1.24.4/go1.26.8, GOPROXY=off, from both the workspace root
// and the member's own directory — before resolving a single module,
// regardless of whether the member's own go.mod requires the Old path at
// all (see checkGoWorkReplaceMissingVersion's own doc comment in check.go).
//
// Before this fix, main's `reps = mergeReplaces(reps, goWorkReplaces(
// gowork))` merged this exact malformed replace straight into the ordinary
// resolution list, carrying its empty NewVersion forward: CheckAll's
// require+replace loop fell back to the stale, pre-replace requirement's
// own version (v0.9.1 below), so modslop reported only a misleading
// "version-not-found" finding against golang.org/x/text — a module that
// never needed to have a v0.9.1 at all — with no hint the real, root-cause
// defect sits in go.work itself. That misleading finding is a pre-existing,
// documented side effect this fix doesn't change (checkReplaceMissingVersion
// has the identical property for go.mod's own malformed replaces, per its
// own doc comment) — the bug this test guards against is the *absence* of
// the real root-cause finding alongside it, not the misleading one's
// presence.
func TestRunGoWorkReplaceMissingVersionFlagged(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	root := t.TempDir()
	memberDir := filepath.Join(root, "member")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workSrc := "go 1.24\n\nuse ./member\n\nreplace github.com/pkg/errors => golang.org/x/text\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(workSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(memberDir, "go.mod")
	gomodSrc := "module example.com/member\n\ngo 1.24\n\nrequire github.com/pkg/errors v0.9.1\n"
	if err := os.WriteFile(gomod, []byte(gomodSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (the broken go.work should be flagged)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-replace-missing-version") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the go.work's unversioned remote replace target with the real root-cause finding", gomod, got)
	}
}

// TestRunGoWorkGodebugDirectiveTooOldFlagged is the end-to-end regression
// test for technique #198: a go.work carrying its own top-level `godebug`
// directive shares go.mod's identical go1.23 toolchain-version gate (see
// checkGoWorkGodebugDirectiveTooOld's own doc comment in check.go for the
// live-verification detail against real go1.21.0/go1.22.0/go1.23.0,
// downloaded via golang.org/dl), but main's go.work-handling block never
// checked it, only go.mod's own godebug directive via
// checkGodebugDirectiveTooOld's call site. Before this fix, a hallucinated
// require planted in the workspace member's go.mod reported a plain
// "not-found" finding when the real go command, run under the identical
// too-old toolchain, Fatals parsing go.work itself before resolving a
// single requirement.
//
// This test doesn't rely on whatever toolchain happens to be installed in
// the sandbox running it (unlike the ambient-`go`-dependent tests above):
// it builds a one-entry PATH pointing at a real downloaded go1.22.0 (see
// /root/sdk/go1.22.0, already present on this box) so goEnv's own `go env
// GOVERSION`/`go env GOWORK` calls deterministically resolve through that
// exact toolchain, the same way this bug was live-verified manually.
func TestRunGoWorkGodebugDirectiveTooOldFlagged(t *testing.T) {
	const oldGo = "/root/sdk/go1.22.0/bin/go"
	if _, err := os.Stat(oldGo); err != nil {
		t.Skipf("real go1.22.0 not available at %s (download via golang.org/dl to re-run this test): %v", oldGo, err)
	}

	fakeBin := t.TempDir()
	if err := os.Symlink(oldGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOTOOLCHAIN", "local")

	root := t.TempDir()
	memberDir := filepath.Join(root, "app")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workSrc := "go 1.20\n\ngodebug http2client=0\n\nuse ./app\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(workSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(memberDir, "go.mod")
	gomodSrc := "module example.com/app\n\ngo 1.20\n\nrequire github.com/totally-nonexistent-org/doesnotexist v1.2.3\n"
	if err := os.WriteFile(gomod, []byte(gomodSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-godebug-directive-too-old") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the go.work's 'godebug' directive as too old for go1.22.0", gomod, got)
	}
	if !strings.Contains(got, "(go.work)") {
		t.Errorf("run([%q]) stdout = %q, want the finding attributed to (go.work), not (go.mod)", gomod, got)
	}
}

// TestRunGoWorkGodebugDirectiveModernToolchainStillLeaks is
// TestRunGoWorkGodebugDirectiveTooOldFlagged's companion, proving the fix
// doesn't overreach: the identical go.work/go.mod pair audited under a
// toolchain that DOES recognize `godebug` (go1.23+) must not flag
// go-work-godebug-directive-too-old, leaving the real not-found finding as
// the only one reported.
func TestRunGoWorkGodebugDirectiveModernToolchainStillLeaks(t *testing.T) {
	const modernGo = "/root/sdk/go1.23.0/bin/go"
	if _, err := os.Stat(modernGo); err != nil {
		t.Skipf("real go1.23.0 not available at %s (download via golang.org/dl to re-run this test): %v", modernGo, err)
	}

	fakeBin := t.TempDir()
	if err := os.Symlink(modernGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOTOOLCHAIN", "local")

	root := t.TempDir()
	memberDir := filepath.Join(root, "app")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workSrc := "go 1.20\n\ngodebug http2client=0\n\nuse ./app\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(workSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(memberDir, "go.mod")
	gomodSrc := "module example.com/app\n\ngo 1.20\n\nrequire github.com/totally-nonexistent-org/doesnotexist v1.2.3\n"
	if err := os.WriteFile(gomod, []byte(gomodSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if strings.Contains(got, "go-work-godebug-directive-too-old") {
		t.Errorf("run([%q]) stdout = %q, want it NOT to flag go-work-godebug-directive-too-old under go1.23.0 (which recognizes 'godebug')", gomod, got)
	}
	if !strings.Contains(got, "not-found") {
		t.Errorf("run([%q]) stdout = %q, want the real hallucinated-require finding still reported", gomod, got)
	}
}

// TestRunGoVersionUnsatisfiableFlagged_GOTOOLCHAINAuto is the end-to-end
// regression test for technique #206's GOTOOLCHAIN=auto failure shape: a
// go.mod declaring `go 1.99.0` (not a real release) makes a real go
// toolchain Fatal entirely offline trying to download a toolchain to
// satisfy it ("toolchain not available") before resolving a single
// module — live-verified, 2026-10-05, under both GOPROXY=off and a real
// reachable GOPROXY (the version isn't real, so no proxy can ever serve
// it; GOPROXY=off used here to keep the test offline and deterministic).
// `go env GOVERSION` itself Fatals identically, which is exactly what
// makes checkGoVersionUnsatisfiable's localGoVersion parameter resolve to
// "". Before this fix, modslop sailed straight past this and reported a
// plain "not-found" finding for a planted hallucinated require — live-
// reproduced below — when the real go command, run against that same
// go.mod, never gets far enough to resolve a single requirement.
func TestRunGoVersionUnsatisfiableFlagged_GOTOOLCHAINAuto(t *testing.T) {
	realGo := "/usr/bin/go"
	if _, err := os.Stat(realGo); err != nil {
		t.Skipf("real go not available at %s: %v", realGo, err)
	}
	fakeBin := t.TempDir()
	if err := os.Symlink(realGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOPROXY", "off")

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	content := "module example.com/toolchk\n\ngo 1.99.0\n\nrequire github.com/totally-nonexistent-org/doesnotexist v1.2.3\n"
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-version-unsatisfiable") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the unsatisfiable go directive", gomod, got)
	}
	if !strings.Contains(got, "(go.mod)") {
		t.Errorf("run([%q]) stdout = %q, want the finding attributed to (go.mod)", gomod, got)
	}
}

// TestRunGoVersionUnsatisfiableFlagged_GOTOOLCHAINLocal is technique
// #206's other live-verified failure shape: a realistic pinned-CI setup
// (GOTOOLCHAIN=local/path) never attempts a download at all, so `go env
// GOVERSION` succeeds and reports the real running toolchain — but that
// toolchain is older than the go.mod's own declared minimum, and `go
// list -m`/`go build` Fatal immediately with "go.mod requires go >=
// 1.99.0 (running go 1.21.0; GOTOOLCHAIN=local)", live-verified against a
// real go1.21.0 downloaded via golang.org/dl. Before this fix, that exact
// scenario sailed past every check in this file and into modslop's
// ordinary proxy-resolution audit, reporting a plain "not-found" finding
// for a planted hallucinated require that real go, under this identical
// environment, never gets far enough to resolve.
func TestRunGoVersionUnsatisfiableFlagged_GOTOOLCHAINLocal(t *testing.T) {
	const oldGo = "/root/sdk/go1.21.0/bin/go"
	if _, err := os.Stat(oldGo); err != nil {
		t.Skipf("real go1.21.0 not available at %s (download via golang.org/dl to re-run this test): %v", oldGo, err)
	}

	fakeBin := t.TempDir()
	if err := os.Symlink(oldGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	content := "module example.com/toolchk\n\ngo 1.99.0\n\nrequire github.com/totally-nonexistent-org/doesnotexist v1.2.3\n"
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-version-unsatisfiable") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the unsatisfiable go directive", gomod, got)
	}
	if !strings.Contains(got, "go1.21.0") {
		t.Errorf("run([%q]) stdout = %q, want the Detail to name the real running toolchain", gomod, got)
	}
}

// TestRunGoVersionSatisfiable_NoFalsePositive is
// TestRunGoVersionUnsatisfiableFlagged_GOTOOLCHAINLocal's companion,
// proving the fix doesn't overreach: the identical kind of go.mod, but
// with a declared `go` minimum the real running toolchain actually
// satisfies, must not flag go-version-unsatisfiable, leaving the real
// not-found finding as the only one reported.
func TestRunGoVersionSatisfiable_NoFalsePositive(t *testing.T) {
	const modernGo = "/root/sdk/go1.23.0/bin/go"
	if _, err := os.Stat(modernGo); err != nil {
		t.Skipf("real go1.23.0 not available at %s (download via golang.org/dl to re-run this test): %v", modernGo, err)
	}

	fakeBin := t.TempDir()
	if err := os.Symlink(modernGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	content := "module example.com/toolchk\n\ngo 1.20\n\nrequire github.com/totally-nonexistent-org/doesnotexist v1.2.3\n"
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if strings.Contains(got, "go-version-unsatisfiable") {
		t.Errorf("run([%q]) stdout = %q, want it NOT to flag go-version-unsatisfiable under a toolchain that satisfies the declared minimum", gomod, got)
	}
	if !strings.Contains(got, "not-found") {
		t.Errorf("run([%q]) stdout = %q, want the real hallucinated-require finding still reported", gomod, got)
	}
}

// TestRunGoBlockFormFlagged is the end-to-end regression test for a real
// bug: a go.mod with a `go (` block — real go has no block form for the
// `go` directive at all, so `go build`/`go list -m all` Fatal immediately
// with "unknown block type: go", identically under both GOTOOLCHAIN=auto
// and =local, before resolving a single module (live-verified,
// go1.24.4). Before this fix, `go env GOVERSION` succeeds fine for this
// exact shape (it doesn't need to parse the `go` directive's value), so
// checkGoVersionUnsatisfiable's fail-closed branch never caught it either
// — modslop reported a clean "nothing flagged" (exit 0) for a go.mod the
// real go command refuses to parse at all.
func TestRunGoBlockFormFlagged(t *testing.T) {
	realGo := "/usr/bin/go"
	if _, err := os.Stat(realGo); err != nil {
		t.Skipf("real go not available at %s: %v", realGo, err)
	}
	fakeBin := t.TempDir()
	if err := os.Symlink(realGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOPROXY", "off")

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	content := "module example.com/goblock\n\ngo (\n\t1.21\n)\n"
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (a `go (` block should be flagged, not silently ignored)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-block-form") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the go-block-form go.mod", gomod, got)
	}
}

// TestRunToolchainBlockFormFlagged_GOTOOLCHAINLocal is
// TestRunGoBlockFormFlagged's `toolchain`-directive sibling, specifically
// under GOTOOLCHAIN=local: real go Fatals `go build`/`go list -m all`
// with "unknown block type: toolchain" (live-verified, go1.24.4), but
// unlike GOTOOLCHAIN=auto (where `go env GOVERSION` also Fatals, so
// checkGoVersionUnsatisfiable's fail-closed branch coincidentally also
// fires), under =local `go env GOVERSION` succeeds fine — before this
// fix, modslop reported a clean "nothing flagged" (exit 0) for this mode
// specifically.
func TestRunToolchainBlockFormFlagged_GOTOOLCHAINLocal(t *testing.T) {
	realGo := "/usr/bin/go"
	if _, err := os.Stat(realGo); err != nil {
		t.Skipf("real go not available at %s: %v", realGo, err)
	}
	fakeBin := t.TempDir()
	if err := os.Symlink(realGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	content := "module example.com/toolchainblock\n\ngo 1.21\n\ntoolchain (\n\tgo1.21.0\n)\n"
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (a `toolchain (` block should be flagged, not silently ignored)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "toolchain-block-form") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the toolchain-block-form go.mod", gomod, got)
	}
}

// TestRunGoWorkToolchainBlockFormFlagged_GOTOOLCHAINLocal is
// TestRunToolchainBlockFormFlagged_GOTOOLCHAINLocal's go.work-side
// counterpart: a workspace go.work carrying a `toolchain (` block,
// auto-discovered the same way TestRunGoWorkVersionUnsatisfiableFlagged's
// setup is (no explicit GOWORK env, go.work sits in the member's parent
// directory).
func TestRunGoWorkToolchainBlockFormFlagged_GOTOOLCHAINLocal(t *testing.T) {
	realGo := "/usr/bin/go"
	if _, err := os.Stat(realGo); err != nil {
		t.Skipf("real go not available at %s: %v", realGo, err)
	}
	fakeBin := t.TempDir()
	if err := os.Symlink(realGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")

	root := t.TempDir()
	memberDir := filepath.Join(root, "app")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workSrc := "use ./app\n\ngo 1.21\n\ntoolchain (\n\tgo1.21.0\n)\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(workSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(memberDir, "go.mod")
	gomodSrc := "module example.com/app\n\ngo 1.21\n"
	if err := os.WriteFile(gomod, []byte(gomodSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (a go.work `toolchain (` block should be flagged, not silently ignored)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-toolchain-block-form") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the go.work's toolchain-block-form", gomod, got)
	}
	if !strings.Contains(got, "(go.work)") {
		t.Errorf("run([%q]) stdout = %q, want the finding attributed to (go.work)", gomod, got)
	}
}

// TestRunGoWorkVersionUnsatisfiableFlagged is
// TestRunGoVersionUnsatisfiableFlagged_GOTOOLCHAINLocal's go.work-side
// counterpart: a workspace go.work declaring `go 1.99.0` makes a real
// go1.21.0 (GOTOOLCHAIN=local) Fatal `go list -m` immediately with "go:
// ../go.work requires go >= 1.99.0 (running go 1.21.0; GOTOOLCHAIN=local)"
// — naming the go.work path, not go.mod — before resolving a single
// requirement in the workspace, live-verified 2026-10-05. Before this
// fix, that exact scenario sailed past every check in this file and into
// modslop's ordinary proxy-resolution audit for the member's own planted
// hallucinated require.
func TestRunGoWorkVersionUnsatisfiableFlagged(t *testing.T) {
	const oldGo = "/root/sdk/go1.21.0/bin/go"
	if _, err := os.Stat(oldGo); err != nil {
		t.Skipf("real go1.21.0 not available at %s (download via golang.org/dl to re-run this test): %v", oldGo, err)
	}

	fakeBin := t.TempDir()
	if err := os.Symlink(oldGo, filepath.Join(fakeBin, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")

	root := t.TempDir()
	memberDir := filepath.Join(root, "app")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workSrc := "go 1.99.0\n\nuse ./app\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(workSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(memberDir, "go.mod")
	gomodSrc := "module example.com/app\n\ngo 1.20\n\nrequire github.com/totally-nonexistent-org/doesnotexist v1.2.3\n"
	if err := os.WriteFile(gomod, []byte(gomodSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-version-unsatisfiable") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the go.work's unsatisfiable go directive", gomod, got)
	}
	if !strings.Contains(got, "(go.work)") {
		t.Errorf("run([%q]) stdout = %q, want the finding attributed to (go.work), not (go.mod)", gomod, got)
	}
}

// TestRunGoWorkUnresolvableFlagged is the end-to-end regression test for
// technique #203: an explicitly-set, relative GOWORK value can't be
// resolved to a path at all — real cmd/go's FindGoWork Fatals immediately
// with "invalid GOWORK: not an absolute path" before resolving a single
// module, live-verified go1.24.4 (both `go list -m all` and `go env
// GOWORK` itself fail identically, since the latter calls the same
// resolution internally). Before this fix, goEnv("GOWORK", ...)'s blanket
// "any `go env` failure means empty string" contract made this
// indistinguishable from "no workspace at all," so modslop reported
// "nothing flagged" for a go.mod the real go command can never build
// under this exact environment, regardless of whether it has any
// suspicious requirements — confirmed with none at all here, the
// strongest form of the false negative.
func TestRunGoWorkUnresolvableFlagged(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", "relative.work")

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (an unresolvable GOWORK should be flagged even with zero requirements)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-unresolvable") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the unresolvable relative GOWORK value", gomod, got)
	}
}

// TestRunGoWorkUnreadableFlagged_Directory is the end-to-end regression
// test for technique #203's other shape: GOWORK resolves to a real,
// absolute path, but that path is a directory, not a file. Real cmd/go
// Fatals immediately with "read <path>: is a directory" (confirmed live,
// go1.24.4) before resolving a single module. Before this fix, both
// goWorkReplaces and main's go.work-handling block treated the
// os.ReadFile failure identically to "no workspace," so modslop reported
// "nothing flagged" for a go.mod the real go command can never build.
func TestRunGoWorkUnreadableFlagged_Directory(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workAsDir := filepath.Join(dir, "fake.work")
	if err := os.Mkdir(workAsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", workAsDir)

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (a directory-as-GOWORK should be flagged)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-unreadable") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the unreadable (directory) GOWORK path", gomod, got)
	}
}

// TestRunGoWorkUnreadableFlagged_Missing is
// TestRunGoWorkUnreadableFlagged_Directory's sibling for the other real
// os.ReadFile failure mode cmd/go itself hits differently (via
// modload.ReadWorkFile's "reading go.work: open <path>: no such file or
// directory" wrapping rather than the early toolchain-selection path's
// bare "read <path>: is a directory") but with the identical outcome:
// Fatal before resolving a single module, live-verified go1.24.4.
func TestRunGoWorkUnreadableFlagged_Missing(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", filepath.Join(dir, "does-not-exist.work"))

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (a missing GOWORK target should be flagged)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-unreadable") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the unreadable (missing) GOWORK path", gomod, got)
	}
}

// TestRunGoWorkUnresolvableOrUnreadable_NoFalsePositive is the negative
// control for all three TestRunGoWork{Unresolvable,Unreadable}* tests
// above: GOWORK=off (explicitly disabled) and an unset GOWORK (no
// workspace at all) are both genuinely clean cases and must not trip
// either new check, proving the fix doesn't overreach into the ordinary,
// much more common no-workspace path.
func TestRunGoWorkUnresolvableOrUnreadable_NoFalsePositive(t *testing.T) {
	for _, gowork := range []string{"off", ""} {
		t.Run("GOWORK="+gowork, func(t *testing.T) {
			dir := t.TempDir()
			gomod := filepath.Join(dir, "go.mod")
			if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.21\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GOWORK", gowork)

			var stdout, stderr bytes.Buffer
			code := run([]string{gomod}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 0 (clean)", gomod, code, stdout.String(), stderr.String())
			}
			got := stdout.String()
			if strings.Contains(got, "go-work-unresolvable") || strings.Contains(got, "go-work-unreadable") {
				t.Errorf("run([%q]) stdout = %q, want neither new check to fire on a genuinely clean GOWORK setting", gomod, got)
			}
		})
	}
}

// TestRunGoWorkUseDirectiveMalformedFlagged is the end-to-end regression
// test for a real bug: a go.work `use` directive carrying anything other
// than exactly one well-formed argument made real `go build`/`go list -m
// all` Fatal immediately with "usage: use local/dir" (live-verified,
// go1.24.4, GOPROXY=off) — before resolving a single module in the
// workspace — while modslop silently dropped the line entirely (`use`
// was never dispatched on by any existing check) and reported "checked 0
// requirement(s), nothing flagged". See goWorkUseDirectiveMalformed's own
// doc comment in gomod.go for the full live-verification detail across
// all three malformed shapes this covers.
func TestRunGoWorkUseDirectiveMalformedFlagged(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gowork := filepath.Join(dir, "go.work")
	if err := os.WriteFile(gowork, []byte("go 1.21\n\nuse ./foo ./bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", gowork)

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (a malformed go.work use directive should be flagged)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-work-use-malformed") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the malformed go.work use directive", gomod, got)
	}
}

// TestRunGoWorkUseDirectiveMalformed_NoFalsePositive is the negative
// control: an ordinary, well-formed `use` directive (the common case —
// every real go.work this tool parses correctly today) must not trip the
// new check.
func TestRunGoWorkUseDirectiveMalformed_NoFalsePositive(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/foo\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gowork := filepath.Join(dir, "go.work")
	if err := os.WriteFile(gowork, []byte("go 1.21\n\nuse ./foo\nuse ./bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", gowork)

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 0 (clean, well-formed use directives)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if strings.Contains(got, "go-work-use-malformed") {
		t.Errorf("run([%q]) stdout = %q, want the new check not to fire on well-formed use directives", gomod, got)
	}
}

// TestRunGoModUnknownDirectiveFlagged is the end-to-end regression test
// for a real bug (run #677): a go.mod carrying a top-level line whose
// leading keyword isn't one of go.mod's own recognized directives
// (module/go/toolchain/require/exclude/replace/retract/tool/godebug/
// ignore) made real `go build`/`go list -m all` Fatal immediately with
// "unknown directive: <verb>" — before resolving a single requirement,
// including an ordinary, well-formed require line sitting right next to
// it in the same file (live-verified, go1.24.4/go1.26.8, GOPROXY=off; see
// goModUnknownDirective's own doc comment in gomod.go). Before this fix,
// modslop's run() silently dropped the unrecognized line and reported
// "nothing flagged" for a go.mod the real go command refuses to parse at
// all.
func TestRunGoModUnknownDirectiveFlagged(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	content := "module example.com/foo\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n\nbogusverb oops\n"
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (the unknown directive should be flagged)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "go-mod-unknown-directive") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the go.mod's unrecognized 'bogusverb' directive", gomod, got)
	}
}

// TestRunGoModInvalidQuotedTokenFlagged is the end-to-end regression test
// for a backtick-wrapped `require` argument: real `go build`/`go list -m
// all` Fatals immediately with "invalid quoted string: unquoted string
// cannot contain quote" (live-verified, go1.24.4/go1.26.8, GOPROXY=off),
// before resolving a single requirement. Before this fix, ParseGoMod's own
// firstField/leadingQuotedString extracted the backtick-wrapped text as an
// ordinary (garbage) module path and modslop checked it against the live
// proxy, reporting a misleading high-severity "not-found" hallucination
// finding for a go.mod that can never build at all, for a completely
// unrelated reason.
func TestRunGoModInvalidQuotedTokenFlagged(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	content := "module example.com/foo\n\ngo 1.21\n\nrequire `github.com/pkg/errors` v0.9.1\n"
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{gomod}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run([%q]) = %d, stdout = %q, stderr = %q, want 1 (the invalid quoted token should be flagged)", gomod, code, stdout.String(), stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "invalid-quoted-token") {
		t.Errorf("run([%q]) stdout = %q, want it to flag the backtick-wrapped require argument", gomod, got)
	}
	if strings.Contains(got, "not-found") {
		t.Errorf("run([%q]) stdout = %q, want it NOT to also report the mangled token as a hallucinated not-found import", gomod, got)
	}
}
