# Go module slopsquatting: what it is, why Go is exposed, how to defend

A reference doc for anyone who landed here from a search for "slopsquatting,"
"AI hallucinated Go import," or similar — not a `modslop` feature list (see
the [README](../README.md) for that).

## The term

"Slopsquatting" was coined by Seth Larson (Python Software Foundation) and
amplified by Andrew Nesbitt — a portmanteau of "AI slop" and "typosquatting."
It describes attackers registering package names that LLMs *hallucinate*,
rather than names a human would mistype. The mechanism: a coding assistant
confidently suggests `import "some/plausible/package"` that doesn't exist;
an attacker who's watched enough model output registers that exact name
first; the next developer (or agent) who trusts the suggestion pulls
attacker-controlled code.

This isn't a hypothetical failure mode. A USENIX Security 2025 study found
**19.7% of packages recommended by major LLMs across common coding prompts
don't exist** on the registry the code targets. A separate paper ("We Have a
Package for You! A Comprehensive Analysis of Package Hallucinations by Code
Generating LLMs," May 2025) found the hallucinations aren't random noise:
**58% of hallucinated names reappeared across repeated runs of the same
prompt, and 43% showed up in all ten of ten repeated attempts** — meaning an
attacker doesn't need to guess, they can query the same models researchers
did and pre-register the names that come up reliably.

## Why Go modules are structurally more exposed than npm or PyPI

On npm or PyPI, a package name is an entry in a centralized namespace that a
registry operator controls. Slopsquatting there still works (see incidents
below), but registering the name is the *only* step — the attacker doesn't
need to also stand up working, resolvable infrastructure.

Go modules skip the centralized namespace entirely: a module path **is** a
VCS location. `go get github.com/someuser/somepkg` resolves by fetching
`someuser/somepkg` directly from GitHub (or wherever), through
`proxy.golang.org` as a caching layer. There is no separate "claim this
name" step to squat — an attacker just needs to create a real repo at the
exact path a model hallucinated, and it becomes a legitimate, resolvable,
buildable Go module the moment they push to it. The hallucination *is* the
squat target, with zero intermediate registration friction.

## Documented incidents

**On npm/PyPI (not Go, but the same underlying failure — a developer or
agent trusting an unverified AI-suggested package name):**

- `huggingface-cli` on PyPI: a real, working, but unofficial package that
  accumulated 30,000+ downloads in three months after a well-known
  organization's AI-assisted documentation included the install command
  without verifying the name was official (research by Bar Lanyado).
- `unused-imports` on npm: models trained on `eslint-plugin-unused-imports`
  hallucinate the shorter `unused-imports` name; the malicious package was
  still live and recording installs as of early 2026.
- `react-codeshift` on npm: a hallucinated name claimed in January 2026 that
  then spread to 237 GitHub repositories via copied/cloned agent
  instructions, with install attempts traceable to agent tooling rather
  than humans typing the name by hand.

**On Go specifically:** the clearest fully-documented case so far is
`github.com/bpoorman/uuid` — a malicious module that impersonated
`github.com/pborman/uuid` (and, transitively, the naming pattern of
`google/uuid`) by swapping the maintainer username (`pborman` → `bpoorman`)
while keeping the familiar `/uuid` suffix developers expect from tutorials.
It shipped a hidden `Valid` function that AES-encrypted whatever data was
passed to it and exfiltrated it to a paste-bin API. Published May 2021, it
stayed live and installable for **over four years** before Socket's
December 2025 writeup — nobody was checking. This particular case is
typosquatting on a maintainer name rather than a confirmed LLM hallucination,
but it demonstrates the exact structural weakness slopsquatting exploits in
Go: there is no registry operator anywhere in the loop who could have
caught or removed it.

Given the 19.7% hallucination rate measured across registries generally and
Go's total absence of a name-claiming gatekeeper, a module path that an LLM
hallucinates *and someone squats* is a strictly easier and more durable
attack in Go than in npm or PyPI — a squatted Go path doesn't need to be
reported and taken down by a registry, because there's no registry to
report it to. No fully-confirmed "attacker pre-registered a path an LLM
hallucinates" Go incident is publicly documented yet as of this writing —
that's a gap in public reporting, not a claim the risk is smaller than
recorded npm/PyPI cases represent it to be.

## Detecting it

Three signals catch most of this without needing a central registry to
police it:

1. **Resolution check** — does the path even exist? A `go build` or
   `go mod tidy` failure ("no required module provides package," "cannot
   find module providing package") is Go telling you either you have a
   typo to fix, or an import that was never real and hasn't been squatted
   *yet* — worth removing rather than leaving as a landmine for whoever
   requests that path next.
2. **Name-proximity check** — is this one or two character edits away from
   a well-known module (`logrusx` vs. `logrus`, `bpoorman/uuid` vs.
   `pborman/uuid`)? Classic typosquat/slopsquat shape, catchable with
   simple edit-distance comparison against a list of popular modules.
3. **Freshness check** — does the module have exactly one published
   version, released recently? Not proof of anything on its own (every
   real project starts this way), but combined with the other two signals
   it's a useful tie-breaker: a brand-new, thinly-versioned module that's
   also a near-miss of a popular name is a specific, checkable pattern.

[`modslop`](../README.md) runs all three checks against an existing
`go.mod`, specifically to catch imports that already resolve — the ones a
plain `go build` failure won't flag, because a squatted path builds fine.

## Sources

- [Socket: Malicious Go packages impersonate Google's UUID library and exfiltrate data](https://socket.dev/blog/malicious-go-packages-impersonate-googles-uuid-library-and-exfiltrate-data) (Dec 2025)
- [Socket: The Rise of Slopsquatting](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [Wikipedia: Slopsquatting](https://en.wikipedia.org/wiki/Slopsquatting)
- "We Have a Package for You! A Comprehensive Analysis of Package
  Hallucinations by Code Generating LLMs" (May 2025) — 58%/43% recurrence
  findings
- USENIX Security 2025 — 19.7% non-existent-package recommendation rate
