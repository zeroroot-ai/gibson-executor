# Contributing to `gibson-executor`

This is the in-guest execution agent: it runs security tooling and the MCP bridge INSIDE a Setec microVM, and reports results back to the platform.

If anything here is unclear, open an issue rather than guessing — an unclear
contributing guide is a bug in this file.

## Prerequisites

- Go 1.26+
- `docker` (the image bundles the security tools)
- Access to `github.com/zeroroot-ai/sdk`

## Build and test

```sh
make test
make image
```

## The merge gate

The image bundles third-party security tools (nuclei, httpx, naabu, subfinder,
tlsx, dnsx) built from source rather than downloaded as release zips.

`tools/recon` declares **security floors** for shared transitive dependencies,
and minimal version selection takes the maximum across the build, so the floor
wins over whatever a tool asks for. A post-build assertion then reads what
actually LINKED with `go version -m` and fails below the floor — because
trusting go.mod is not enough: a future tool bump could require a newer but
still-vulnerable line, and the only place that shows up is the shipped binary.

Every pull request runs it. A red gate is a real signal: **do not** disable a
guard to get a PR through. If a guard is wrong, fix the guard in the same PR
and say why — a guard that needs re-pinning after an unrelated edit is a defect
in the guard.

## Pull requests

- **Conventional Commits in the PR title** — `feat:`, `fix:`, `chore:`,
  `docs:`, `ci:`, `test:`, `refactor:`. The subject must start lowercase;
  `pr-title-lint` enforces both.
- **One root cause per PR.** Two unrelated fixes are two pull requests.
- **Rebase, never merge.** `git fetch origin && git rebase origin/main`
- Releases are automatic via release-please. Never hand-tag, never hand-edit a
  version.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

**Elastic License 2.0** — see [LICENSE](LICENSE). Read it, download it, run it, modify it; do not offer it to third parties as a hosted or managed service. GitHub shows this repo as "NOASSERTION" because ELv2 is not OSI-approved. The surface you build against — [`sdk`](https://github.com/zeroroot-ai/sdk) and [`adk`](https://github.com/zeroroot-ai/adk) — is Apache-2.0.
