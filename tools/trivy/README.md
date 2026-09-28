# `tools/trivy` — how the shipped trivy gets its dependencies

This module exists to build the one `trivy` binary the executor image ships. It
builds nothing of our own. It is a separate module from `tools/recon` on
purpose: trivy links a container runtime, several package-manager parsers and
cloud SDKs, and in one module with the scanners every bump of either side could
move the other's dependencies. Two modules keep the two resolutions apart.

## The problem it solves

`Dockerfile` used to install trivy from the upstream release archive. That
binary links whatever trivy's own `go.mod` asks for. trivy v0.74.0 asks for
`google.golang.org/grpc v1.82.1`, which carries two fixable HIGH findings. The
publish gate blocks an image with a fixable HIGH finding, so no executor image
published between 2026-09-16 and 2026-09-28 (#69). No newer trivy release
existed, so no pin bump could clear it.

Building here fixes it the same way `tools/recon` fixes the scanners: this
module requires the tool and declares the security floor as a direct
requirement. Minimal version selection takes the maximum of every requirement
in the build, so the floor wins. No `replace` directive and no fork.

`Dockerfile` reads what actually got linked with `go version -m` and fails the
build if grpc is below the floor. It also fails when the linked containerd
version changes, because that one is an accepted risk that must be revisited
when upstream moves it.

## Bump procedure

1. Change the `github.com/aquasecurity/trivy` requirement in `go.mod`.
2. Change `TRIVY_VERSION` in `Dockerfile` to the same version. The build asserts
   they agree.
3. Run `GOEXPERIMENT=jsonv2 go mod tidy` in this directory.
4. Build the image. If the containerd tripwire fires, follow its message.
5. If a floor in `go.mod` is now below what trivy itself requires, raise the
   floor to match. A floor below the tool's own requirement is dead text.

`GOEXPERIMENT=jsonv2` is what upstream sets in its own release build. trivy
imports `encoding/json/v2` and does not compile without it.
