# Security Policy

## Supported versions

Only the latest tagged release is supported. Upgrade before reporting
an issue that a newer version might already fix:

```
go install github.com/experimental-gains/modslop@latest
```

## Reporting a vulnerability

Email **ops@maelstrom.build** with what you found and, if possible, a
way to reproduce it. There's no bug bounty — this is a small
single-maintainer tool — but reports are read and fixed.

## Fixed vulnerabilities

### 2026-09-21 — toolchain and dependency CVEs (fixed in v0.1.11)

Versions v0.1.10 and earlier built against `go 1.24.4` and
`golang.org/x/mod v0.30.0`. Both had known, reachable vulnerabilities:

- **GO-2026-6179** / **GO-2026-6180** — sumdb transparency-log
  verification bypass in `golang.org/x/mod` before v0.31.0.
- 26 reachable CVEs in the `go1.24.4` standard library (`crypto/tls`,
  `crypto/x509`, `net/url`, `encoding/pem`, `os/exec`), reachable
  through `modslop`'s own use of `exec.Command` and `http.Client.Get`
  to talk to the Go module proxy — confirmed reachable with
  `govulncheck ./...`, not just present in `go.sum`.

Fixed in v0.1.11 by bumping to `go 1.26.8` and `golang.org/x/mod
v0.41.0`. `govulncheck ./...` reports no vulnerabilities as of that
release. If you're running v0.1.10 or earlier, upgrade.
