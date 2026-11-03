# `tools/kubectl` — how the shipped kubectl gets its dependencies

This module builds the one `kubectl` binary the executor image ships. It builds
nothing of our own. kube-bench's audit scripts exec `kubectl`, and so does
`parsers/kubebench` to read the cluster answers before it runs anything
(`kubectl config view --raw -o json` and `kubectl get --raw /version`).

## The problem it solves

`Dockerfile` used to download kubectl from the upstream release archive and
verify it by SHA-256. That binary links whatever the k8s release team built it
with. kubectl v1.37.2, the newest release, links `golang.org/x/net v0.57.0` and
`golang.org/x/text v0.40.0`. Both are below the fix for CVE-2026-78669 and
CVE-2026-56851, so both are fixable HIGH findings. The publish gate blocks an
image with a fixable HIGH finding and has no opt-out, so the executor image
could not publish. No published kubectl release links a newer x/net, so no
version bump could clear it.

This is the same upstream-binary exposure that moved `trivy` (#69) and
`kube-bench` into their own modules. kubectl is the third case.

## Why this reverses the earlier choice

The earlier `Dockerfile` comment said kubectl "cannot be built as a dependency:
it lives in k8s.io/kubernetes, whose go.mod depends on a long list of replace
directives that only apply when it is the main module." That is true of
`k8s.io/kubernetes`. It is not true of `k8s.io/kubectl`, the staging module that
publishes the same command library with no replace directives.

`kubectl.go` is a small `main` that calls `cmd.NewDefaultKubectlCommand()` from
`k8s.io/kubectl/pkg/cmd`, the same entry point upstream `cmd/kubectl` uses. It
builds a working kubectl as an ordinary dependency, with no `replace` and no
fork.

## How it works

Building from a module we own puts kubectl in *our* build list, so minimal
version selection applies across all of it. MVS selects the maximum of every
requirement, so the explicit `golang.org/x/net` and `golang.org/x/text` floors
here win over what `k8s.io/kubectl` asks for. The pinned Go toolchain
(`golang:1.27.3` in `Dockerfile`, `GOTOOLCHAIN=local`) gives a current stdlib,
which clears the four stdlib CVEs the older release binary carried.

`go.mod` has two kinds of requirement:

- **The tool pin** — `k8s.io/kubectl`. It tracks the kubectl release the image
  ships. `k8s.io/kubectl v0.MINOR.PATCH` maps to kubectl `v1.MINOR.PATCH`.
- **The security floors** — `golang.org/x/net`, `golang.org/x/text`. These
  exist only to raise what kubectl would otherwise link. Raise them freely.
  Never lower one to make a build pass.

`floors.go` carries blank imports of the floor packages behind a `tools` build
tag. The tag keeps them out of the binary. Without them `go mod tidy` would mark
the floors `// indirect`, where they read as resolver noise and invite deletion.

The Dockerfile asserts the floors held by reading `go version -m` on the built
binary and failing the build if x/net or x/text linked below its floor. Checking
`go.mod` would not be equivalent: a future `k8s.io/kubectl` bump could require a
newer-but-still-vulnerable line, MVS would take it, and the first place that
shows up is the shipped artifact.

## Bump procedure

1. Change the `k8s.io/kubectl` requirement in `go.mod` to the new version.
2. Change `KUBECTL_VERSION` in `Dockerfile` to the same version. The build
   asserts they agree.
3. Run `go mod tidy` in this directory.
4. Build the image. If a floor check fires, raise that requirement in `go.mod`
   to a version the advisory it names lists as patched.
5. If a floor in `go.mod` is now below what `k8s.io/kubectl` itself requires,
   raise the floor to match. A floor below the tool's own requirement is dead
   text.
