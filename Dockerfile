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
#     `golang:latest`, not `golang:1.26-bookworm` — a silent switch to a
#     different image, not just a refreshed one (#362). Keeping the tag
#     inline is what keeps the automated bump on the same tag lineage.

########################
# Stage 1 — build binary
########################
FROM golang:1.26-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build
# The golang base image ships GOTOOLCHAIN=local. go.mod names the toolchain
# (go 1.26.8 after the stdlib fix) and moves faster than the mirrored image tag,
# so let the Go toolchain download the version go.mod asks for. Same rule as
# gibson's Dockerfile.
ENV GOTOOLCHAIN=auto

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
    | awk '$1 == "dep" && $2 ~ /^golang\.org\/x\/(crypto|net|text)$/ { print $2, $3 }' \
    | sort -u > /tmp/linked-deps; \
    cat /tmp/linked-deps; \
    while read -r mod ver; do \
        case "$mod" in \
            golang.org/x/crypto) floor=v0.55.0 ;; \
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

# trivy comes from its upstream release archive, verified by SHA-256 for the
# architecture being built. Bump = change the version and BOTH sums together,
# taken from that release's own checksums.txt. A mismatch fails the build.
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_SHA256_AMD64=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
ARG TRIVY_SHA256_ARM64=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) asset="Linux-64bit";  want="${TRIVY_SHA256_AMD64}" ;; \
        arm64) asset="Linux-ARM64";  want="${TRIVY_SHA256_ARM64}" ;; \
        *) echo "FAIL: no pinned trivy checksum for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${asset}.tar.gz"; \
    curl -fsSL --retry 3 -o /tmp/trivy.tar.gz "$url"; \
    got="$(sha256sum /tmp/trivy.tar.gz | cut -d' ' -f1)"; \
    if [ "$got" != "$want" ]; then \
        echo "FAIL: trivy ${TRIVY_VERSION} ${asset} sha256 $got, expected $want" >&2; \
        exit 1; \
    fi; \
    tar -xzf /tmp/trivy.tar.gz -C /tmp trivy; \
    install -m 0755 /tmp/trivy /out/trivy; \
    rm -f /tmp/trivy.tar.gz /tmp/trivy; \
    /out/trivy --version

########################
# Stage 2 — runtime
########################
FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

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
#   curl, jq — nothing in the image execs either. `registry.Parsers` covers
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
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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

# Runner binary.
COPY --from=build /out/gibson-runner /usr/local/bin/gibson-runner

# Run as an unprivileged user. Setec microVMs already isolate the process,
# but defence in depth: don't exec tools as root inside the guest.
RUN useradd --system --create-home --shell /usr/sbin/nologin runner
USER runner:runner
WORKDIR /home/runner

ENTRYPOINT ["/usr/local/bin/gibson-runner"]
