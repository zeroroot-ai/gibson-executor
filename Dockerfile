# syntax=docker/dockerfile:1.7
# gibson-executor — one image hosting every CLI parser compiled into the
# Go binary. The image ships on debian:trixie-slim (not Kali) and installs
# only the tools the registered parsers exec. Adding a tool means one new
# apt/curl/go-install line here + a parser file in ./parsers/.
#
# Build:
#   docker build -t ghcr.io/zeroroot-ai/gibson-executor:<tag> .
#
# Run (smoke):
#   docker run --rm -e GIBSON_TOOL_INPUT_B64=... -e GIBSON_TOOL_NAME=nmap \
#     ghcr.io/zeroroot-ai/gibson-executor:<tag>

# Both base images are pinned by digest (gibson-executor#339). A floating
# tag makes the build non-reproducible and lets the runtime base drift
# silently between rebuilds, which is what Scorecard's PinnedDependencies
# check flags. Every pin below is a direct `FROM <image>:<tag>@sha256:...`
# line — tag AND digest together, on the FROM line itself, not behind an
# `ARG` and not digest-only:
#
#   - Dependabot's Docker ecosystem parses `FROM` lines but does not
#     resolve `FROM ${ARG}` against an `ARG` default, so a pin hidden
#     behind an indirection is a pin nothing ever refreshes (#353).
#   - A digest with no accompanying tag is not left alone either:
#     dependabot-core explicitly resolves a tag-less digest pin against
#     the `latest` tag, so `golang@sha256:...` would get bumped against
#     `golang:latest`, not `golang:1.26.8-bookworm` — a silent switch to a
#     different image, not just a refreshed one (#362). Keeping the tag
#     inline is what keeps the automated bump on the same tag lineage.

########################
# Stage 1 — build binary
########################
FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
# The builder image carries exactly the Go that go.mod names, and the org
# guard (check-go-toolchain.sh, .github#22) fails a PR where they differ.
# GOTOOLCHAIN=local makes a mismatch fail the build instead of downloading a
# toolchain, so the pinned base is the toolchain that built the binary.
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}

WORKDIR /src

# This image depends on the public `github.com/zeroroot-ai/sdk` module plus
# community libraries. Every module comes from the public Go proxy.

# Dependencies first for layer caching.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# tools/recon is a separate module (see tools/recon/README.md) whose dependency
# graph is enormous — the five ProjectDiscovery tools between them pull in most
# of the Go security ecosystem. Download it here, keyed on its go.mod/go.sum
# alone, so that editing any source file in this repo does not re-resolve it.
COPY tools/recon/go.mod tools/recon/go.sum ./tools/recon/
RUN --mount=type=cache,target=/go/pkg/mod \
    cd tools/recon && go mod download
COPY tools/trivy/go.mod tools/trivy/go.sum ./tools/trivy/
RUN --mount=type=cache,target=/go/pkg/mod \
    cd tools/trivy && go mod download
COPY tools/kubebench/go.mod tools/kubebench/go.sum ./tools/kubebench/
RUN --mount=type=cache,target=/go/pkg/mod \
    cd tools/kubebench && go mod download

# Source.
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/gibson-runner \
        ./cmd/gibson-runner

# ProjectDiscovery tools — compiled FROM SOURCE with this stage's Go toolchain,
# out of the `tools/recon` module, NOT with `go install <pkg>@<version>`.
#
# Building from source (#122) fixed the stdlib half of the problem: the
# published release zips are built by ProjectDiscovery with an older Go, so
# they carry stdlib CVEs that no version bump of ours can clear. It did not fix
# the other half. `go install pkg@version` deliberately ignores the surrounding
# module and resolves purely from the TOOL's own go.mod, so naabu kept shipping
# `x/crypto v0.46.0` and `x/net v0.48.0` even though it was compiled here with a
# current toolchain — 19 HIGH and 7 MEDIUM findings across naabu, subfinder and
# dnsx (#368).
#
# tools/recon is a small module that requires the five tool commands AND
# declares security floors for the shared transitive dependencies. Minimal
# version selection takes the maximum of every requirement in the build, so the
# floors win over what the tools ask for. This needs no `replace` directive and
# no fork — see tools/recon/README.md for the reasoning and the bump procedure,
# including the parser/CLI-flag coupling that governs the tool pins themselves.
#
# Cross-compiled and native builds both land where -o says, so there is no
# GOPATH/bin arch-subdirectory dance any more.
ARG TARGETARCH=amd64

# The floor assertion after the builds reads what actually got LINKED, with
# `go version -m`, and fails the build if any of it is below the floor. Trusting
# go.mod would not be enough: a future tool bump could require a newer-but-still
# -vulnerable line and MVS would happily take it, and the only place that shows
# up is the shipped binary. Failing here beats finding it in a scan of a
# published image.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    cd tools/recon; \
    for t in \
        "github.com/projectdiscovery/httpx/cmd/httpx httpx" \
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei nuclei" \
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder subfinder" \
        "github.com/projectdiscovery/dnsx/cmd/dnsx dnsx" \
        "github.com/projectdiscovery/naabu/v2/cmd/naabu naabu" \
        "github.com/projectdiscovery/tlsx/cmd/tlsx tlsx"; \
    do \
        set -- $t; \
        CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
            go build -trimpath -ldflags="-s -w" -o "/out/$2" "$1"; \
    done; \
    for bin in /out/httpx /out/nuclei /out/subfinder /out/dnsx /out/naabu /out/tlsx; do \
        go version -m "$bin"; \
    done \
    | awk '$1 == "dep" && $2 ~ /^golang\.org\/x\/(crypto|mod|net|text)$/ { print $2, $3 }' \
    | sort -u > /tmp/linked-deps; \
    cat /tmp/linked-deps; \
    while read -r mod ver; do \
        case "$mod" in \
            golang.org/x/crypto) floor=v0.56.0 ;; \
            golang.org/x/mod)    floor=v0.40.0 ;; \
            golang.org/x/net)    floor=v0.56.0 ;; \
            golang.org/x/text)   floor=v0.39.0 ;; \
            *)                   continue ;; \
        esac; \
        lowest=$(printf '%s\n%s\n' "$floor" "$ver" | sort -V | head -1); \
        if [ "$lowest" != "$floor" ]; then \
            echo "FAIL: $mod linked at $ver, below the $floor security floor" >&2; \
            exit 1; \
        fi; \
    done < /tmp/linked-deps

# trivy — built from source out of its own module, tools/trivy, for the same
# reason the ProjectDiscovery tools are built out of tools/recon: the upstream
# release archive links whatever trivy's own go.mod asks for. v0.74.0 asks for
# grpc v1.82.1, which carries two fixable HIGH findings, and the publish gate
# blocked every image from 2026-09-16 to 2026-09-28 because of it (#69). No
# newer trivy release existed. tools/trivy declares the grpc floor as a direct
# requirement, minimal version selection takes the maximum, so the floor wins
# without a replace directive or a fork.
#
# It is a separate module from tools/recon on purpose: trivy links a container
# runtime, several package-manager parsers and cloud SDKs, and in one module
# with the scanners every bump of either side could move the other's
# dependencies. Two modules keep the two resolutions apart. See
# tools/trivy/README.md for the bump procedure.
#
# GOEXPERIMENT=jsonv2 is what upstream sets in its own release build
# (goreleaser.yml); trivy imports encoding/json/v2 and does not compile
# without it.
#
# TRIVY_VERSION is asserted against tools/trivy/go.mod so the two cannot drift:
# bump both in one commit.
ARG TRIVY_VERSION=0.74.0
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    cd tools/trivy; \
    grep -qE "^\s+github.com/aquasecurity/trivy v${TRIVY_VERSION}$" go.mod || { \
        echo "FAIL: TRIVY_VERSION=${TRIVY_VERSION} but tools/trivy/go.mod requires a different trivy" >&2; \
        exit 1; \
    }; \
    CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" GOEXPERIMENT=jsonv2 \
        go build -trimpath \
            -ldflags="-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}" \
            -o /out/trivy github.com/aquasecurity/trivy/cmd/trivy

# What trivy links, read from the binary with `go version -m`, not trusted
# from go.mod. Two checks:
#
#   grpc — a FLOOR. The reason tools/trivy exists. A future trivy bump that
#   requires a newer-but-still-vulnerable grpc would pass MVS and only show up
#   in the shipped binary. Failing here beats finding it in a scan of a
#   published image.
#
#   containerd — a TRIPWIRE, not a gate. containerd v2.3.3 carries
#   CVE-2026-53495 with no fixed release. Owner decision 2026-09-16: accept it
#   and dismiss the alert with that reason. An accepted risk that nobody
#   revisits is just an unaccepted one with better paperwork, so the build
#   fails when the linked version CHANGES in either direction. A newer trivy
#   that moves containerd breaks this build on purpose, and whoever fixes it
#   revisits the dismissal in the same change.
ARG TRIVY_GRPC_FLOOR=v1.83.2
ARG TRIVY_ACCEPTED_CONTAINERD=v2.3.3
RUN set -eux; \
    linked() { go version -m /out/trivy | awk -v m="$1" '$1 == "dep" && $2 == m { print $3 }' | head -1; }; \
    got_grpc="$(linked google.golang.org/grpc)"; \
    got_cd="$(linked github.com/containerd/containerd/v2)"; \
    echo "trivy links grpc=${got_grpc} containerd=${got_cd}"; \
    lowest="$(printf '%s\n%s\n' "${TRIVY_GRPC_FLOOR}" "${got_grpc}" | sort -V | head -1)"; \
    if [ -z "${got_grpc}" ] || [ "${lowest}" != "${TRIVY_GRPC_FLOOR}" ]; then \
        echo "FAIL: trivy links grpc ${got_grpc}, below the ${TRIVY_GRPC_FLOOR} security floor." >&2; \
        echo "Raise the google.golang.org/grpc requirement in tools/trivy/go.mod." >&2; \
        exit 1; \
    fi; \
    if [ "${got_cd}" != "${TRIVY_ACCEPTED_CONTAINERD}" ]; then \
        echo "" >&2; \
        echo "TRIVY CONTAINERD MOVED: accepted ${TRIVY_ACCEPTED_CONTAINERD}, linked ${got_cd}." >&2; \
        echo "This is the tripwire working, not a defect. Do BOTH, in one commit:" >&2; \
        echo "  1. Update TRIVY_ACCEPTED_CONTAINERD above." >&2; \
        echo "  2. If the new version clears CVE-2026-53495, DISMISS-REVERSE the" >&2; \
        echo "     matching code-scanning alert. The acceptance was only ever valid" >&2; \
        echo "     while upstream had no fix." >&2; \
        exit 1; \
    fi

# kube-bench — built from source out of its own module, tools/kubebench, for the
# same reason trivy is: the upstream release archive links whatever kube-bench's
# own go.mod asks for, and no pin bump of ours can clear a finding in it.
# KUBE_BENCH_VERSION is asserted against tools/kubebench/go.mod so the two cannot
# drift: bump both in one commit.
#
# The benchmark definitions (cfg/) are not in the binary. They are copied out of
# the module cache at the same version, so the controls that run are exactly the
# ones the pinned release shipped. The runtime stage installs them at
# /etc/kube-bench/cfg and parsers/kubebench passes that path explicitly.
ARG KUBE_BENCH_VERSION=0.16.0
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    cd tools/kubebench; \
    grep -qE "^require github.com/aquasecurity/kube-bench v${KUBE_BENCH_VERSION}$" go.mod || { \
        echo "FAIL: KUBE_BENCH_VERSION=${KUBE_BENCH_VERSION} but tools/kubebench/go.mod requires a different kube-bench" >&2; \
        exit 1; \
    }; \
    CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
        go build -trimpath \
            -ldflags="-s -w -X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=${KUBE_BENCH_VERSION}" \
            -o /out/kube-bench github.com/aquasecurity/kube-bench; \
    mkdir -p /out/kube-bench-cfg; \
    cp -r "$(go list -m -f '{{.Dir}}' github.com/aquasecurity/kube-bench)/cfg/." /out/kube-bench-cfg/; \
    test -f /out/kube-bench-cfg/config.yaml

# kubectl — the one binary here taken from an upstream release rather than built
# from source. kube-bench's policies audit scripts call `kubectl`, and so does
# parsers/kubebench to check the cluster answers before it runs anything.
# kubectl cannot be built as a dependency: it lives in k8s.io/kubernetes, whose
# go.mod depends on a long list of replace directives that only apply when it
# is the main module. So it is pinned by version and verified by SHA-256 per
# architecture. The build fails rather than install something else.
#
# Both sums are from https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/<arch>/kubectl.sha256
ARG KUBECTL_VERSION=1.37.1
ARG KUBECTL_SHA256_AMD64=65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8
ARG KUBECTL_SHA256_ARM64=ff749f4b78d9c4f1ec87307df9b50119ed819e2094aa9810cb9acffc3286c8c7
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) sha="${KUBECTL_SHA256_AMD64}" ;; \
        arm64) sha="${KUBECTL_SHA256_ARM64}" ;; \
        *) echo "FAIL: no kubectl checksum for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 3 -o /out/kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl"; \
    echo "${sha}  /out/kubectl" | sha256sum -c -; \
    chmod 0755 /out/kubectl

########################
# Stage 2 — runtime
########################
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

# Installed tools: curated for the currently-registered parsers. Grow this
# list as parsers land. Keep --no-install-recommends + clean to minimise
# image size and attack surface.
#
#   nmap             — parsers/nmap
#   masscan          — parsers/masscan (the only registered tool Debian
#                      packages; the rest are Go and are built above)
#   ca-certificates  — TLS trust anchors for httpx/nuclei outbound requests.
#                      This is the trust store, NOT a transport: the static
#                      Go binaries dial TLS themselves and need no `curl`.
#
# Deliberately NOT installed (#349):
#
#   curl — nothing in the image execs it. (jq was removed here for the same
#     reason and is back: kube-bench's policies audit scripts pipe through it,
#     so it came back in the change that registered that parser, as the rule
#     below asks. It is the one apt dependency of a tool, not a tool.)
#     The original reasoning, for both: `registry.Parsers` covers
#     dnsx, httpx, masscan, naabu, nmap, nuclei, subfinder, and every one of
#     those `exec.CommandContext`s its own named binary. curl and jq appear
#     only in TOOLS.md's 🟡 "long tail" wish-list, which has no parser and
#     no `raw_exec` fallback behind it. Shipping them cost 40+ Trivy
#     findings (curl, libcurl4t64 and the libldap2 / krb5 / libsasl2 /
#     libpsl chain that only libcurl pulls in), all with FixedVersion:
#     NONE. If a generic-exec parser ever lands, re-add the binary it needs
#     in the same change that registers the parser — and re-triage.
#
#   amass — no shippable version accepts the argv `parsers/amass` built.
#     Removed outright, not gated: #370.
#
# Additional parsers (subfinder, naabu, …) follow the same pattern: either
# apt-installable, or built from source in the build stage above and copied
# in as a static binary.
# `apt-get upgrade` before the install (#349). The base is digest-pinned, which
# fixes the reproducible starting point but says nothing about currency: the
# pinned layer is only as fresh as the last time the base image was rebuilt.
# Measured during the #349 triage — the pinned base carried util-linux 2.41-5
# while trixie-security had already published 2.41.5-0+deb13u1, so 54 findings
# per image existed purely because nothing ever applied the distro's own
# security updates. The pin still decides where the build starts; this line
# closes the gap between there and build time. It does NOT replace refreshing
# the pin — see #353.
# APT_CACHE_BUST — the reason `apt-get upgrade` was not actually running.
#
# Measured 2026-09-16. The layer below is cached by buildx (`cache-from:
# type=gha`), and its cache key is the instruction text plus the base digest.
# Neither changes between builds, so the upgrade ran ONCE, on the day this
# layer was first built, and every build since replayed that layer verbatim.
# The comment above was true about intent and false about effect.
#
# Proof, by accident: on 2026-09-16 a broken step in the org reusable workflow
# dropped `cache-from`/`cache-to` for one build. That image came out with
# perl-base 5.40.1-6+deb13u1, libc6 2.41-12+deb13u4 and gzip 1.13-1+deb13u1 —
# every one patched. The next build, with the cache restored, went back to
# 5.40.1-6, +deb13u3 and 1.13-1, and Trivy went back to 40 findings.
#
# The caller passes a value that changes every run, so this layer and the apt
# install below it rebuild every time. The builder stage is a separate stage
# keyed on go.mod and the sources, so none of its cache is lost — the cost is
# one `apt-get upgrade` per image build, which is the point.
ARG APT_CACHE_BUST=0
RUN echo "apt refresh ${APT_CACHE_BUST}" >/dev/null && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        ca-certificates \
        jq \
    && rm -rf /var/lib/apt/lists/*

# /bin/sh is bash, not dash. kube-bench runs every audit script with
# `/bin/sh` (hard-coded in check/check.go) and the scripts use `[[ ]]`, which
# dash does not have. Measured against the real v0.16.0 binary on this base
# image: control 5.1.1 returned "/bin/sh: 3: [[: not found" as its value and
# was graded as an ordinary result. Nothing else in this image runs a shell
# script, and apt's maintainer scripts have finished by this line.
RUN ln -sf bash /bin/sh

# Go tools — built from source in the build stage (see the go install block
# there, #122/#352) and copied in as static binaries. Every one of these has a
# registered parser that execs it by this name; `gibson-runner --verify-tools`
# checks that correspondence inside a built image, and
# TestDockerfileInstallsEveryCatalogedTool guards it at PR time.
COPY --from=build /out/httpx /usr/local/bin/httpx
COPY --from=build /out/nuclei /usr/local/bin/nuclei
COPY --from=build /out/subfinder /usr/local/bin/subfinder
COPY --from=build /out/dnsx /usr/local/bin/dnsx
COPY --from=build /out/naabu /usr/local/bin/naabu
COPY --from=build /out/tlsx /usr/local/bin/tlsx

# trivy — the one tool here installed from an upstream release archive
# rather than built from `tools/recon`.
#
# It is not in that module on purpose. trivy pulls a dependency tree far
# larger than the five ProjectDiscovery commands combined (it links a
# container runtime, several package-manager parsers and cloud SDKs), and
# adding it there would put all of that into the same MVS resolution as the
# scanners — every future bump of any of them would then be able to move
# trivy's dependencies, and the shared `go.sum` would grow by thousands of
# lines for one binary that shares no code with the rest.
#
# The archive is pinned by version AND verified by SHA-256 per architecture
# in the build stage, so this is reproducible in the same sense the
# digest-pinned base images are: the build fails rather than installing
# something else.
COPY --from=build /out/trivy /usr/local/bin/trivy

# kube-bench and the two things it execs. jq (apt, above) and kubectl are
# dependencies of kube-bench's audit scripts, not tools of their own: no parser
# registers them, so catalog_image_test.go lists them in nonToolPackages. The
# kubectl tool slice (gibson-executor#85) removes kubectl from that list when
# it registers a parser.
COPY --from=build /out/kube-bench /usr/local/bin/kube-bench
COPY --from=build /out/kubectl /usr/local/bin/kubectl
COPY --from=build /out/kube-bench-cfg /etc/kube-bench/cfg

# Runner binary.
COPY --from=build /out/gibson-runner /usr/local/bin/gibson-runner

# Run as an unprivileged user. Setec microVMs already isolate the process,
# but defence in depth: don't exec tools as root inside the guest.
RUN useradd --system --create-home --shell /usr/sbin/nologin runner
USER runner:runner
WORKDIR /home/runner

# The license text travels with the distribution. Apache-2.0 §4(a) and MIT
# both require the notice to reach every recipient, and a published image is
# a distribution. /licenses is the OCI convention. Last in the stage so a
# change here rebuilds nothing else.
COPY LICENSE NOTICE /licenses/

ENTRYPOINT ["/usr/local/bin/gibson-runner"]
