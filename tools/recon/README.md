# `tools/recon` — how the shipped scanning tools get their dependencies

This module exists to build the five ProjectDiscovery tools the executor image
ships: `httpx`, `nuclei`, `subfinder`, `dnsx`, `naabu`. It builds nothing of our
own. It is a separate module from the repo root on purpose — the executor binary
must not inherit a scanner's dependency graph.

## The problem it solves

`Dockerfile` used to build these with `go install <pkg>@<version>`. That was
already an improvement on downloading upstream release zips (#122): the release
zips are built by ProjectDiscovery with an older Go, so they carry stdlib CVEs
that no pin of ours can clear, and compiling here picks up the current
toolchain's stdlib.

It only fixed half the problem. **`go install pkg@version` deliberately ignores
the surrounding module** and resolves the build purely from the *tool's own*
`go.mod`. So the stdlib was current and everything else was whatever the tool
last happened to require:

| tool | linked `x/crypto` | linked `x/net` | linked `x/text` |
|---|---|---|---|
| naabu 2.6.1 | v0.46.0 | v0.48.0 | v0.32.0 |
| subfinder 2.15.0 | — | v0.55.0 | v0.37.0 |
| dnsx 1.3.0 | — | v0.55.0 | v0.37.0 |

That was 19 HIGH and 7 MEDIUM findings on the published image, including an SSH
authorization bypass and a `knownhosts` revocation bypass in `x/crypto` (#368).

Issue #368 recorded that "a consumer cannot override without a fork or a
`replace` directive (forbidden org-wide)". That turned out not to be true, and
this module is the counter-example.

## How it works

Building from a module we own puts the tools inside *our* build list, so
**minimal version selection** applies across all of it. MVS selects the
**maximum** of every requirement, so an explicit `require golang.org/x/crypto
v0.52.0` here wins over naabu's `v0.46.0` — no `replace`, no fork, nothing the
`no-monorepo-shortcuts` ruleset objects to.

`tools.go` carries blank imports of the five commands behind a `tools` build
tag. Without them `go mod tidy` would drop every requirement in `go.mod` as
unused.

`go.mod` therefore has two kinds of requirement, and they are maintained
differently:

- **The tool pins** — the five `github.com/projectdiscovery/...` lines. These
  track the parser's expected CLI (see below), not "latest".
- **The security floors** — `golang.org/x/crypto`, `golang.org/x/net`,
  `golang.org/x/text`. These exist only to raise what the tools would otherwise
  drag in. Raise them freely; never lower one to make a build pass.

The Dockerfile asserts the floors held by reading `go version -m` on each
**built binary** and failing the build if anything linked below its floor.
Checking `go.mod` would not be equivalent: a future tool bump could require a
newer-but-still-vulnerable line, MVS would take it, and the first place that
shows up is the shipped artifact.

## Bumping a tool pin

**Read the matching parser's `buildArgs` first.** Every parser under
`parsers/<tool>/` hard-codes an output flag. A major bump that renames or drops
that flag turns a working tool into a silently broken one: the tool runs, emits
a shape the parser cannot decode, and the mission fails with a parse error
rather than an obvious "no such flag". This is not hypothetical — it is why
`parsers/amass` was removed in #370.

Known couplings:

- **`nuclei` is 3.x on purpose.** `parsers/nuclei` builds `-jsonl`, which only
  exists from v3; v2 spelled it `-json`.
- `httpx`, `subfinder`, `dnsx`, `naabu` use the long-stable `-json -silent`
  pair. Treat that as convention, not guarantee — ProjectDiscovery has renamed
  output flags across majors before, which is exactly how the nuclei coupling
  arose.

Then:

```sh
cd tools/recon
go get github.com/projectdiscovery/naabu/v2/cmd/naabu@v<new>
go mod tidy
go build ./... # or let the image build do it
```

If `go mod tidy` lowers a floor because nothing needs it any more, leave the
floor. It costs nothing and it is what stops a future bump from silently
regressing.

## Raising a floor

Find the fixed version from the alert, then:

```sh
cd tools/recon
go get golang.org/x/crypto@v<fixed>
go mod tidy
```

and update the matching `floor=` line in `Dockerfile`. The two are checked
against each other by the build, so they cannot drift apart quietly.

## `amass` is not here

`parsers/amass` was removed in #370. No shippable amass version accepts the argv
it built: v3 has the `-json` flag but the oldest dependency tree, v4 dropped
JSON output entirely and only fails at flag parsing, and v5 removed the embedded
engine this one-shot exec model needs. Removing it also cleared 44 Trivy
findings including two CRITICALs.
