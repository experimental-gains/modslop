# modslop

[![Go Reference](https://pkg.go.dev/badge/github.com/experimental-gains/modslop.svg)](https://pkg.go.dev/github.com/experimental-gains/modslop)
[![License: MIT](https://img.shields.io/github/license/experimental-gains/modslop)](LICENSE)
[![Latest release](https://img.shields.io/github/v/tag/experimental-gains/modslop)](https://github.com/experimental-gains/modslop/releases)

Catch slopsquatted and hallucinated Go module names in your `go.mod`.

LLM coding assistants occasionally invent import paths that sound
plausible but don't exist — "package hallucination." For most
registries that's just an install failure. Go modules are different:
because a module path is just a VCS location, anyone can stand up a
real repo at the exact path an LLM hallucinated and it will resolve
and build. That's "slopsquatting" applied to Go specifically, and it's
a live risk (the [`bpoorman/uuid`](https://socket.dev/blog/malicious-go-packages-impersonate-googles-uuid-library-and-exfiltrate-data)
maintainer-name typosquat, live and installable for over four years, is
a real example of the same underlying weakness — no registry operator
anywhere in the loop to catch or remove it). Full writeup with sources:
[`docs/SLOPSQUATTING.md`](docs/SLOPSQUATTING.md).

`modslop` reads a `go.mod` and flags requirements that look risky:

- **proxy-blocklisted-malicious** — the Go module proxy itself has
  explicitly flagged this exact path as malicious and refuses to serve
  it (a distinct `403` with a "considers this module to be malicious"
  body, not a generic fetch error). Highest severity: this isn't a
  heuristic guess, it's the proxy operator's own confirmed verdict.
  Verified against real, publicly reported malicious Go modules,
  including a `shopspring/decimal` typosquat and a `boltdb/bolt`
  typosquat carrying an RCE backdoor.
- **not-found** — the path doesn't resolve via the Go module proxy at
  all. If nothing pulled it in before, this is worth a hard look —
  possibly a hallucinated import that was never real. Skipped for a
  path covered by your local `GOPRIVATE`/`GONOPROXY` (read via `go env
  GONOPROXY`, same as the real `go` command resolves it) — those are
  fetched directly from VCS, never through the public proxy, so a miss
  there is expected and carries no signal.
- **name-collision-risk** — the module's name is one or two edits away
  from a well-known module (e.g. `logrusx` vs. `logrus`), the classic
  typosquat/slopsquat shape. Only raised when the module itself also
  looks unproven — brand new, single-version, or unresolved — since an
  established package sharing a generic word or short string with a
  popular one by chance (e.g. `errors`, `protobuf`) isn't evidence of
  anything on its own.
- **name-collision-exact** — the module's name is *identical* to a
  well-known module (not a typo), published at a different, unproven
  path. This is the impersonation technique documented in a real,
  disclosed, active Go supply-chain campaign — attackers republish a
  popular module's exact name under a new, attacker-controlled owner
  instead of misspelling it (Bae & Yagemann, ["Beyond Takedown: Measuring
  Malicious Go Module Persistence in the
  Wild"](https://arxiv.org/abs/2606.26291), 2026 — disclosure led to 684
  GitHub takedowns and 1,377 proxy-cached versions remediated by the Go
  team). Gated on the same unproven-path check as `name-collision-risk`,
  so a long-lived, publicly known fork that deliberately kept the
  original name isn't flagged just for existing.
- **new-and-thin** — the module exists, but has exactly one published
  version, released in the last 30 days. Could be a legitimate new
  project. Could also be a name registered specifically to catch
  whoever's AI assistant suggests it.

## If you hit "no required module provides package" or "cannot find module"

Those are Go's own `go build` / `go mod tidy` errors for exactly this
situation — an import (yours or a dependency's) points at a module path
that doesn't resolve, or resolves to something nobody vetted. Verified
against a real hallucinated import:

```
main.go:4:2: no required module provides package github.com/nonexistent-org/some-pkg; to add it:
	go get github.com/nonexistent-org/some-pkg
```

```
go: cannot find module providing package github.com/nonexistent-org/some-pkg: module github.com/nonexistent-org/some-pkg: git ls-remote -q origin in ...: exit status 128
```

The error text can't tell you whether that's a typo you'll fix in ten
seconds or an LLM-hallucinated path that happens to already resolve
because someone registered it first. `modslop` checks everything
already sitting in `go.mod` — including requirements that *did*
resolve — for the signals (not-found, near-miss-of-a-popular-name,
brand-new-and-thin) that a human skim of the error message won't catch.

## How this differs from existing tools

[`pkgtwist`](https://pkg.go.dev/gitlab.com/michenriksen/pkgtwist) and
[`typo-scanner`](https://pkg.go.dev/github.com/dsm0014/typo-scanner)
generate permutations of a name you already trust and check whether an
attacker has squatted the variants. `modslop` runs the other
direction: given a `go.mod` you already have (possibly AI-generated,
possibly reviewed by nobody), it checks whether any of *these specific
imports* look hallucinated or freshly squatted. Point one at a
dependency list you're not sure was written by a careful human.

A related experiment on where this actually happens for PyPI/npm is
in [Finding #2 of agent-bootstrap-log](https://github.com/experimental-gains/agent-bootstrap-log#finding-2-where-llm-package-hallucination-actually-clusters):
88 LLM-generated dependency names checked against the real registries,
misses clustering in fast-moving/niche domains.

## Install

No registry signup needed — `go install` fetches directly from the
module proxy and GitHub:

```bash
go install github.com/experimental-gains/modslop@latest
```

Or via Homebrew:

```bash
brew install experimental-gains/tap/modslop
```

Or build from source:

```bash
git clone https://github.com/experimental-gains/modslop.git
cd modslop && go build .
```

## Usage

```bash
# check ./go.mod
modslop

# check a specific file
modslop path/to/go.mod

# machine-readable output, e.g. for CI
modslop --json
```

Exit code is `1` if anything was flagged, `0` otherwise.

## Use as a GitHub Action

```yaml
- uses: experimental-gains/modslop@v0.2.6
```

With arguments:

```yaml
- uses: experimental-gains/modslop@v0.2.6
  with:
    args: --json
```

A non-zero exit (something flagged) fails the step, so this is
CI-gateable as-is — no extra `run:` glue needed.

## Use with pre-commit

```yaml
repos:
  - repo: https://github.com/experimental-gains/modslop
    rev: v0.2.6
    hooks:
      - id: modslop
```

Runs on any commit that touches `go.mod`. `pre-commit` builds the hook
via `go install` the first time (needs Go available, no other setup).

## Limitations

- Checks `go.mod`'s own `require`/`replace`/`tool` directives — a
  `replace` target is checked in place of the original path (since
  that's what actually gets fetched and built), and a `tool` path not
  already covered by a `require` entry is resolved to its owning module
  and checked the same way, but the full transitive module graph (what
  those dependencies themselves require) isn't walked.
- Private/internal modules covered by your `GOPRIVATE`/`GONOPROXY` are
  exempted from `not-found`/`new-and-thin` (see above) but still get
  checked for `name-collision-risk` against the popular-module list —
  if that ever produces noise on a real internal naming scheme, it's
  worth an issue.
- The "well-known module" list (`popular.go`) is a curated ~130 names,
  not exhaustive. A near-miss against a module that isn't on the list
  won't be caught by `name-collision-risk` (the `not-found` and
  `new-and-thin` checks don't depend on the list, though).
- `new-and-thin` is a heuristic, not proof. Every real project was new
  once.

## Support

This project is free and open source. If it's useful to you, tips are
welcome via [Liberapay](https://liberapay.com/experimental-gains/) or
this ETH address (self-custody, no KYC, no obligation):
`0x87053a1898994043e7476800cB5d4BDB423eADD7`

## License

MIT
