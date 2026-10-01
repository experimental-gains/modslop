package main

import "testing"

// TestRetraction is modeled on a real, live-verified case (2026-09):
// github.com/mattn/go-sqlite3's go.mod (at its latest tag, v1.14.52)
// retracts the version range [v2.0.0+incompatible, v2.0.7+incompatible]
// with the rationale "Accidental; no major changes or features." —
// confirmed live that every version in that range still resolves and
// installs cleanly via proxy.golang.org with no warning anywhere.
func TestRetraction(t *testing.T) {
	const modBody = "module github.com/mattn/go-sqlite3\n\ngo 1.21\n\nretract (\n\t[v2.0.0+incompatible, v2.0.7+incompatible] // Accidental; no major changes or features.\n)\n"

	rationale, retracted := retraction(modBody, "v2.0.3+incompatible")
	if !retracted {
		t.Fatal("expected v2.0.3+incompatible to be reported retracted (it's inside the retracted range)")
	}
	if rationale != "Accidental; no major changes or features." {
		t.Errorf("rationale = %q, want the retract directive's comment", rationale)
	}
}

// TestRetraction_RangeBoundsAreInclusive checks both endpoints of a
// retract interval, not just a version strictly inside it.
func TestRetraction_RangeBoundsAreInclusive(t *testing.T) {
	const modBody = "module example.com/mod\n\ngo 1.21\n\nretract [v1.0.0, v1.2.0]\n"

	for _, v := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		if _, retracted := retraction(modBody, v); !retracted {
			t.Errorf("retraction(%q) = false, want true (bound is inclusive)", v)
		}
	}
}

// TestRetraction_VersionOutsideRangeNotRetracted is the negative case: a
// go.mod with a retract directive that exists but doesn't cover the
// checked version (the common case for any module with retractions at
// all — e.g. go-sqlite3's own latest v1.14.52, which isn't in its
// retracted v2.x range) must not be reported retracted.
func TestRetraction_VersionOutsideRangeNotRetracted(t *testing.T) {
	const modBody = "module github.com/mattn/go-sqlite3\n\ngo 1.21\n\nretract (\n\t[v2.0.0+incompatible, v2.0.7+incompatible] // Accidental; no major changes or features.\n)\n"

	if _, retracted := retraction(modBody, "v1.14.52"); retracted {
		t.Fatal("v1.14.52 is outside the retracted range and must not be flagged")
	}
}

// TestRetraction_NoRationale covers a retract directive with no trailing
// comment — the real go.mod grammar allows this, and the finding message
// (see check.go) falls back to different wording depending on whether a
// rationale was given, so an empty-but-retracted result must be
// distinguishable from "not retracted at all."
func TestRetraction_NoRationale(t *testing.T) {
	const modBody = "module example.com/mod\n\ngo 1.21\n\nretract v1.0.0\n"

	rationale, retracted := retraction(modBody, "v1.0.0")
	if !retracted {
		t.Fatal("expected v1.0.0 to be retracted")
	}
	if rationale != "" {
		t.Errorf("rationale = %q, want empty (no comment was given)", rationale)
	}
}

// TestRetraction_SeparateStatementsOrNonEmptyRationale is modeled on a
// real, live-verified case (2026-09-30, go1.24.4, a from-scratch local
// file-based GOPROXY): a go.mod carrying two entirely separate top-level
// retract statements (not one retract block with a shared leading
// comment — see TestRetraction_NoRationale for that already-handled
// case) that both cover the same version, where only the second one
// carries a rationale. Real `go list -m -u -retracted` surfaces the
// second statement's rationale; retraction() must not short-circuit on
// the first (rationale-less) matching entry and miss it — the identical
// bug shape goproxycheck's own retraction() was independently found and
// fixed for first (a sibling tool's separate go.mod-retraction parser).
func TestRetraction_SeparateStatementsOrNonEmptyRationale(t *testing.T) {
	const modBody = "module example.com/retracttest\n\ngo 1.21\n\nretract v1.0.0\n\nretract [v0.9.0, v1.0.0] // superseded, use v1.2.3 instead\n"

	rationale, retracted := retraction(modBody, "v1.0.0")
	if !retracted {
		t.Fatal("expected v1.0.0 to be retracted (covered by the second statement)")
	}
	if rationale != "superseded, use v1.2.3 instead" {
		t.Errorf("rationale = %q, want the second retract statement's rationale, not the first (rationale-less) matching entry", rationale)
	}
}

// TestRetraction_FirstStatementRationaleKeptWhenLaterOneIsEmpty is the
// mirror case: when the *first* matching statement already carries a
// rationale, a later matching-but-rationale-less statement must not
// blank it out.
func TestRetraction_FirstStatementRationaleKeptWhenLaterOneIsEmpty(t *testing.T) {
	const modBody = "module example.com/retracttest\n\ngo 1.21\n\nretract [v0.9.0, v1.0.0] // superseded, use v1.2.3 instead\n\nretract v1.0.0\n"

	rationale, retracted := retraction(modBody, "v1.0.0")
	if !retracted {
		t.Fatal("expected v1.0.0 to be retracted")
	}
	if rationale != "superseded, use v1.2.3 instead" {
		t.Errorf("rationale = %q, want the first statement's non-empty rationale kept", rationale)
	}
}

func TestRetraction_EmptyInputsNoOp(t *testing.T) {
	const modBody = "module example.com/mod\n\ngo 1.21\n\nretract v1.0.0\n"

	if _, retracted := retraction(modBody, ""); retracted {
		t.Error("retraction with an empty checkVersion (e.g. a tool directive with no version) must not fire")
	}
	if _, retracted := retraction("", "v1.0.0"); retracted {
		t.Error("retraction with an empty modBody (fetch failed or module has no @latest) must not fire")
	}
}

func TestRetraction_MalformedModBodyNoOp(t *testing.T) {
	if _, retracted := retraction("this is not a go.mod at all {{{", "v1.0.0"); retracted {
		t.Error("a go.mod that fails to parse must not produce a false retraction finding")
	}
}
