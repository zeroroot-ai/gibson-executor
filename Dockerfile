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
FROM golang:1.27.3-bookworm@sha256:21ade014faf952365b9ecbd8dbdb87176fbacb82fac9fb132d9f2a7b8cc3f132 AS build
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
COPY tools/kubectl/go.mod tools/kubectl/go.sum ./tools/kubectl/
RUN --mount=type=cache,target=/go/pkg/mod \
    cd tools/kubectl && go mod download

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
#
# go-jose/v4 is a FLOOR here too, >= v4.1.6 for CVE-2026-116587. nuclei links it
# through its own auth code. tools/recon/go.mod already requires v4.1.6 (#177),
# but go.mod alone is the same trust the x/* floors reject, so the binary gets
# the same linked check.
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
    | awk '$1 == "dep" && $2 ~ /^(golang\.org\/x\/(crypto|mod|net|text)|github\.com\/go-jose\/go-jose\/v4)$/ { print $2, $3 }' \
    | sort -u > /tmp/linked-deps; \
    cat /tmp/linked-deps; \
    while read -r mod ver; do \
        case "$mod" in \
            golang.org/x/crypto)              floor=v0.56.0 ;; \
            golang.org/x/mod)                 floor=v0.40.0 ;; \
            golang.org/x/net)                 floor=v0.56.0 ;; \
            golang.org/x/text)                floor=v0.39.0 ;; \
            github.com/go-jose/go-jose/v4)    floor=v4.1.6  ;; \
            *)                                continue ;; \
        esac; \
        lowest=$(printf '%s\n%s\n' "$floor" "$ver" | sort -V | head -1); \
        if [ "$lowest" != "$floor" ]; then \
            echo "FAIL: $mod linked at $ver, below the $floor security floor" >&2; \
            echo "Raise the $mod requirement in tools/recon/go.mod." >&2; \
            exit 1; \
        fi; \
    done < /tmp/linked-deps

# nuclei-templates — the detection content nuclei actually runs. The nuclei
# binary is built above but ships no templates, and the runtime sandbox has no
# network egress except to the dispatched target, so nuclei cannot download the
# set on first run and aborts with "no templates provided for scan"
# (gibson-executor#395). Clone a pinned set here, where build-time network IS
# allowed, and COPY it into the runtime image below.
#
# Pinned the same way as everything else in this file: a tag AND the commit the
# tag resolves to. `git clone --branch` follows a tag, and a tag is mutable, so
# the build reads back the checked-out commit with `git rev-parse` and fails if
# it is not NUCLEI_TEMPLATES_COMMIT — the same "fail the build, do not ship the
# surprise" rule the trivy archive SHA check and the digest-pinned bases follow.
# `.git` is removed after the check: the runtime image carries the YAML only.
#
# Size cost: the template set is ~84 MB of YAML (about 14,100 templates) and is
# the largest single addition to the runtime image. It adds no packages, so it
# adds no Trivy package-CVE surface, and the image stays curated for minimal
# findings. The go-git reachability dismissal is updated in the same change
# (docs/code-scanning-dismissals.md Entry 3): the set is local YAML, the runtime
# stage sets NUCLEI_TEMPLATES_DIR to point at it, no config declares a remote
# template repo, and the parser passes -disable-update-check, so the go-git
# clone path stays unreachable from a mission spec.
#
# Bump procedure: change both ARGs together. Find the current commit with
# `git ls-remote https://github.com/projectdiscovery/nuclei-templates.git refs/tags/v<version>`.
ARG NUCLEI_TEMPLATES_VERSION=10.5.1
ARG NUCLEI_TEMPLATES_COMMIT=79fb682760ab3d5b0e22afbb44709353cbebf023
RUN set -eux; \
    git clone --depth 1 --branch "v${NUCLEI_TEMPLATES_VERSION}" \
        https://github.com/projectdiscovery/nuclei-templates.git /out/nuclei-templates; \
    got="$(git -C /out/nuclei-templates rev-parse HEAD)"; \
    if [ "$got" != "${NUCLEI_TEMPLATES_COMMIT}" ]; then \
        echo "FAIL: nuclei-templates v${NUCLEI_TEMPLATES_VERSION} resolved to $got, not the pinned ${NUCLEI_TEMPLATES_COMMIT}" >&2; \
        exit 1; \
    fi; \
    rm -rf /out/nuclei-templates/.git

# trivy — built from source out of its own module, tools/trivy, for the same
# reason the ProjectDiscovery tools are built out of tools/recon: the upstream
# release archive links whatever trivy's own go.mod asks for. The case that
# built this module: v0.74.0 asked for grpc v1.82.1, which carries two fixable
# HIGH findings, and the publish gate blocked every image from 2026-09-16 to
# 2026-09-28 because of it (#69), with no newer trivy release to move to.
# tools/trivy declares the grpc floor as a direct requirement, minimal version
# selection takes the maximum, so the floor wins without a replace directive or
# a fork. The floor stays whatever the current trivy asks for.
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
ARG TRIVY_VERSION=0.76.0
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
#   containerd — also a FLOOR, since 2026-10-01. It was an exact-match tripwire
#   while upstream had no fix for CVE-2026-53495 and the owner accepted the risk
#   on 2026-09-16. Upstream has since published fixes for both open containerd
#   advisories, so there is no accepted risk left to revisit:
#
#     CVE-2026-53495 / GHSA-7jxh-36q5-gcqv  ExecSync goroutine leak, node DoS
#                                           fixed in 2.3.5 on the 2.3 line
#     CVE-2026-53493 / GHSA-pg57-6jwg-q645  OCI index graph amplification
#                                           fixed in 2.4.1 on the 2.4 line
#
#   trivy v0.75.0 links v2.4.1, which clears both. The tripwire had to be
#   re-pinned on every trivy bump that moved containerd, in either direction,
#   whether or not security changed. A floor asserts the thing that matters and
#   never needs re-pinning on a forward move.
#
#   go-jose/v4 — also a FLOOR, >= v4.1.6 for CVE-2026-116587. trivy links it as
#   an indirect dependency. tools/trivy/go.mod was bumped to v4.1.6 (#179), but
#   go.mod alone is the same trust this block already rejects for grpc, so the
#   linked binary gets the same check.
ARG TRIVY_GRPC_FLOOR=v1.83.2
ARG TRIVY_CONTAINERD_FLOOR=v2.4.1
ARG TRIVY_GOJOSE_FLOOR=v4.1.6
RUN set -eux; \
    linked() { go version -m /out/trivy | awk -v m="$1" '$1 == "dep" && $2 == m { print $3 }' | head -1; }; \
    got_grpc="$(linked google.golang.org/grpc)"; \
    got_cd="$(linked github.com/containerd/containerd/v2)"; \
    got_jose="$(linked github.com/go-jose/go-jose/v4)"; \
    echo "trivy links grpc=${got_grpc} containerd=${got_cd} go-jose=${got_jose}"; \
    lowest="$(printf '%s\n%s\n' "${TRIVY_GRPC_FLOOR}" "${got_grpc}" | sort -V | head -1)"; \
    if [ -z "${got_grpc}" ] || [ "${lowest}" != "${TRIVY_GRPC_FLOOR}" ]; then \
        echo "FAIL: trivy links grpc ${got_grpc}, below the ${TRIVY_GRPC_FLOOR} security floor." >&2; \
        echo "Raise the google.golang.org/grpc requirement in tools/trivy/go.mod." >&2; \
        exit 1; \
    fi; \
    lowest_cd="$(printf '%s\n%s\n' "${TRIVY_CONTAINERD_FLOOR}" "${got_cd}" | sort -V | head -1)"; \
    if [ -z "${got_cd}" ] || [ "${lowest_cd}" != "${TRIVY_CONTAINERD_FLOOR}" ]; then \
        echo "FAIL: trivy links containerd ${got_cd}, below the ${TRIVY_CONTAINERD_FLOOR} security floor." >&2; \
        echo "That version is vulnerable to CVE-2026-53495 or CVE-2026-53493." >&2; \
        echo "Raise the github.com/containerd/containerd/v2 requirement in tools/trivy/go.mod." >&2; \
        exit 1; \
    fi; \
    lowest_jose="$(printf '%s\n%s\n' "${TRIVY_GOJOSE_FLOOR}" "${got_jose}" | sort -V | head -1)"; \
    if [ -z "${got_jose}" ] || [ "${lowest_jose}" != "${TRIVY_GOJOSE_FLOOR}" ]; then \
        echo "FAIL: trivy links go-jose ${got_jose}, below the ${TRIVY_GOJOSE_FLOOR} security floor." >&2; \
        echo "That version is vulnerable to CVE-2026-116587." >&2; \
        echo "Raise the github.com/go-jose/go-jose/v4 requirement in tools/trivy/go.mod." >&2; \
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

# kubectl — built from source out of its own module, tools/kubectl, for the
# same reason trivy and kube-bench are. kube-bench's policies audit scripts call
# `kubectl`, and so does parsers/kubebench to check the cluster answers before
# it runs anything.
#
# This used to be the one binary taken from an upstream release. That choice held
# that kubectl could not be built as a dependency, because its main lives in
# k8s.io/kubernetes, whose go.mod carries replace directives that apply only
# when it is the main module. The reason it is built here now: the published
# release binary links whatever the k8s release team built it with, and the
# publish gate blocks a fixable HIGH with no opt-out. kubectl v1.37.2, the
# newest release, still links golang.org/x/net v0.57.0 and golang.org/x/text
# v0.40.0 — both below the fix for CVE-2026-78669 and CVE-2026-56851 — and no
# published kubectl release links a newer x/net, so no pin bump could clear it.
# This is the same recurring upstream-binary exposure that moved trivy (#69) and
# kube-bench into their own modules.
#
# The replace-directive problem does not apply to the staging module
# k8s.io/kubectl, which publishes the same command library with no replace
# directives. A small main (tools/kubectl/kubectl.go) calls
# cmd.NewDefaultKubectlCommand() and builds a working kubectl as an ordinary
# dependency. Building it here puts kubectl in our build list, so minimal
# version selection takes the x/net and x/text floors in tools/kubectl/go.mod,
# and the pinned toolchain gives a current stdlib. See tools/kubectl/README.md.
#
# KUBECTL_VERSION is the k8s.io/kubectl module version (0.MINOR.PATCH, which
# maps to kubectl 1.MINOR.PATCH). It is asserted against tools/kubectl/go.mod so
# the two cannot drift: bump both in one commit.
ARG KUBECTL_VERSION=0.37.2
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    cd tools/kubectl; \
    grep -qE "^\s+k8s.io/kubectl v${KUBECTL_VERSION}$" go.mod || { \
        echo "FAIL: KUBECTL_VERSION=${KUBECTL_VERSION} but tools/kubectl/go.mod requires a different k8s.io/kubectl" >&2; \
        exit 1; \
    }; \
    CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
        go build -trimpath \
            -ldflags="-s -w \
                -X k8s.io/client-go/pkg/version.gitVersion=v1.${KUBECTL_VERSION#0.} \
                -X k8s.io/component-base/version.gitVersion=v1.${KUBECTL_VERSION#0.}" \
            -o /out/kubectl .

# What kubectl links, read from the binary with `go version -m`, not trusted
# from go.mod. x/net and x/text are FLOORS: the published kubectl release links
# versions below the CVE fixes, and a future module bump that moved either one
# backward would pass MVS and only show up in the shipped binary. Failing here
# beats finding it in a scan of a published image. The stdlib is current by the
# pinned builder toolchain (GOTOOLCHAIN=local), so it needs no separate check.
ARG KUBECTL_XNET_FLOOR=v0.61.0
ARG KUBECTL_XTEXT_FLOOR=v0.43.0
RUN set -eux; \
    linked() { go version -m /out/kubectl | awk -v m="$1" '$1 == "dep" && $2 == m { print $3 }' | head -1; }; \
    got_net="$(linked golang.org/x/net)"; \
    got_text="$(linked golang.org/x/text)"; \
    echo "kubectl links x/net=${got_net} x/text=${got_text}"; \
    lowest_net="$(printf '%s\n%s\n' "${KUBECTL_XNET_FLOOR}" "${got_net}" | sort -V | head -1)"; \
    if [ -z "${got_net}" ] || [ "${lowest_net}" != "${KUBECTL_XNET_FLOOR}" ]; then \
        echo "FAIL: kubectl links x/net ${got_net}, below the ${KUBECTL_XNET_FLOOR} security floor." >&2; \
        echo "Raise the golang.org/x/net requirement in tools/kubectl/go.mod." >&2; \
        exit 1; \
    fi; \
    lowest_text="$(printf '%s\n%s\n' "${KUBECTL_XTEXT_FLOOR}" "${got_text}" | sort -V | head -1)"; \
    if [ -z "${got_text}" ] || [ "${lowest_text}" != "${KUBECTL_XTEXT_FLOOR}" ]; then \
        echo "FAIL: kubectl links x/text ${got_text}, below the ${KUBECTL_XTEXT_FLOOR} security floor." >&2; \
        echo "Raise the golang.org/x/text requirement in tools/kubectl/go.mod." >&2; \
        exit 1; \
    fi

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

# nuclei-templates — the pinned set cloned in the build stage, placed where the
# runner user can read it and pointed at explicitly. NUCLEI_TEMPLATES_DIR is
# nuclei's own env override for the scan template directory, so the path does
# not depend on how the runtime resolves $HOME. HOME is set for the same
# determinism: nuclei writes its config and ignore file under $HOME/.config.
# parsers/nuclei passes -disable-update-check, so nuclei loads this set and
# never tries to download or update it inside the egress-restricted sandbox.
# Owned by runner so the unprivileged process can read every template.
ENV HOME=/home/runner \
    NUCLEI_TEMPLATES_DIR=/home/runner/nuclei-templates
COPY --from=build --chown=runner:runner /out/nuclei-templates /home/runner/nuclei-templates

# The license text travels with the distribution. Apache-2.0 §4(a) and MIT
# both require the notice to reach every recipient, and a published image is
# a distribution. /licenses is the OCI convention. Last in the stage so a
# change here rebuilds nothing else.
COPY LICENSE NOTICE /licenses/

ENTRYPOINT ["/usr/local/bin/gibson-runner"]
