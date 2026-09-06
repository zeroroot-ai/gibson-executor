# Code-scanning dismissals — gibson-executor

Every dismissed code-scanning alert on this repo is recorded here, with the
reasoning that justified the dismissal and the condition that would reverse it.

The GitHub API caps `dismissed_comment` at **280 characters**, which is far too
short for a real reachability argument. Each dismissal therefore carries a short
comment that names the CVE, gives the one-line reason, and cites this file. This
document is the substantive record; the API comment is the pointer.

**This file is version-controlled on purpose.** A dismissal that lives only in
the GitHub UI is invisible to review, invisible to `git log`, and impossible to
re-audit when the threat model changes.

## One image, one surface

This repo builds **one** image today. The SARIF category is still the first
thing to read on any alert, because the ledger below covers a period when the
repo built two.

| SARIF category | Dockerfile | What it is | State |
|---|---|---|---|
| `trivy-gibson-executor` | `Dockerfile` | The in-guest agent that execs CLI security tooling (`nmap`, `httpx`, `nuclei`) inside a Setec microVM. | live |
| `trivy-gibson-mcp-bridge-runner` | `Dockerfile.mcp-bridge` | The generic MCP-connector host (ADR-0048). Spawned a package-distributed vendor MCP server via `npx`/`uvx` as a stdio subprocess. | **removed 2026-09-01** |

**The MCP-bridge image is gone.** The sdk deleted its `mcpbridge` runtime and
the `mcp-bridge` runtime mode in zeroroot-ai/sdk#515. MCP is connector-only now
(ADR-0065 R5). This repo therefore deleted `Dockerfile.mcp-bridge`,
`cmd/mcp-bridge-runner`, `internal/bridgerunner` and the `bridge` image job
(#413). Nothing emits the `trivy-gibson-mcp-bridge-runner` category any more.
Its open alerts are stranded by design and someone must close them by hand.
Entries below that name the bridge are history. Read them as history.

The executor image deliberately bundles a large tool payload, so its raw CVE
count is structurally higher than a typical service image.

Per `ADR-0052`, the containment boundary
for untrusted execution is **the microVM, not the process**. A sandbox escape is
a `setec` bug; a cross-tenant leak is a `gibson` bug. This repo owns neither
boundary — it owns the agent that runs *inside* the box.

That is context for **severity**, not a licence to ignore vulnerabilities. It
never justifies dismissing a vulnerability in this component's own
request-handling code, and no entry in this ledger does so.

## Reachability classes

Every alert is assigned to exactly one class before any dismissal decision.

| Class | Scope | Dismissal policy |
|---|---|---|
| **A — agent's own request-handling path** | `cmd/gibson-runner`, `internal/registry`, `internal/policy`, `internal/sandbox`, and the parse/marshal functions in `parsers/*/` | **Never dismissed.** Tool-invocation parsing and result marshalling are this component's runtime code. These get fixed. |
| **B — bundled third-party executables** | `httpx`, `nuclei`, `nmap` — tools that chew on attacker-supplied *target output*. | Dismissable only with an explicit argument about the specific code path, and only when no upgrade exists. |
| **C — OS/distro packages** | Debian base packages | Dismissable when the vendor ships no fix, the image has already taken every fix the vendor *has* shipped, the package cannot be removed, and it is not reachable from a request-handling path. |

A Class-B CVE in a scanner that only ever chews on target responses is a
genuinely different risk class from a Class-A CVE in the agent's own argument
parser. The distinction is stated per entry, never assumed.

**Historical rule, kept because Entry 4 depends on it.** The bridge's launch
toolchain was Class B, not Class C. `npx` fetching and executing a third-party
package was the bridge doing its job, not incidental distro furniture that
happened to be installed. A CVE in the HTTP client that downloads the code the
image is about to run was not a "wait for the distro" finding. Entry 4 is what
that reclassification cost, and what it bought. The bridge image is gone, so
the rule now applies to nothing.

## Before dismissing anything: `FixedVersion: NONE` is not a verdict

It is a claim about the **distro's archive at scan time**, not about the image.
Three questions have to be answered before it justifies a dismissal, in order:

1. **Has the distro since published a fix the image simply has not taken?**
   A digest-pinned base is only as fresh as the last time that base was rebuilt.
   Entry 6 — 54 findings per image sat behind an `apt-get upgrade` nobody ran.
2. **Does the package need to be in the image at all?**
   Entries 4 and 7 — `curl`, `jq` and 168 node-ecosystem findings were removable
   outright, and every one of them had reported `FixedVersion: NONE`.
3. **Only then**: is it unreachable enough to dismiss?

Entry 2 originally stopped at question 3 and treated `FixedVersion: NONE` as
proof the base was current. It was not. That error is corrected in Entry 6.

## Current status of Class A

**Class A is clean, and no Class-A alert has ever been dismissed.**

Verified on images built from `main`, Trivy reports **zero** vulnerabilities in
both Go binaries — `/usr/local/bin/gibson-runner` and
`/usr/local/bin/mcp-bridge-runner`. Neither appears in the scan results at all,
in either image, at any severity. Resolved versions of the packages that
historically carried findings:

| Package | Resolved | Patched at | Status |
|---|---|---|---|
| `golang.org/x/net` | v0.56.0 | 0.56.0 | current |
| `golang.org/x/crypto` | v0.53.0 | 0.52.0 | current |
| `golang.org/x/text` | v0.41.0 | 0.39.0 | current |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | 5.2.2 | current |

Go toolchain is **1.26.6**, which clears the stdlib CVE family (including
CVE-2023-39318) that historically dominated this repo's alert list.

---

# Ledger

## Entry 1 — 339 stale Trivy alerts from a retired analysis stream

**Alerts.** 339 Trivy alerts, all pinned to commit `9d46bfe0` (2026-05-23),
SARIF category `trivy-gibson-tool-runner`, location path
`zero-day-ai/gibson-tool-runner`.

**Dismissed reason.** `won't fix`

**Why.** These alerts describe an artifact that no longer exists, under an
identity that no longer exists, and they cannot be retired by any scan:

1. **Old organisation and old component name.** The location path is
   `zero-day-ai/gibson-tool-runner`. The org is now `zeroroot-ai` and the
   component is `gibson-executor`. Every one of these alerts was raised before
   both renames.
2. **The SARIF category is orphaned.** Code scanning retires an alert when a
   newer analysis *for the same category and ref* comes back without it. The
   image workflow now publishes under `trivy-gibson-executor`. Nothing will ever
   emit `trivy-gibson-tool-runner` again, so these 339 are structurally
   write-once — they can never close on their own, no matter what is fixed.
3. **The underlying findings are already fixed.** 109 of the 339 are Go stdlib
   CVEs against **stdlib v1.21.0 / v1.21.13**. The repo builds with Go 1.26.6,
   and gibson-executor#122 changed the image to compile `httpx`/`nuclei` from
   source instead of shipping upstream release binaries — which is precisely
   what put a Go 1.21 stdlib in the image. Both changes are on `main`.

Composition of the 339: 176 OS/distro packages, 163 Go-module findings inside
the then-bundled upstream tool binaries. Five reference packages that also
appear in this repo's `go.mod` (`golang.org/x/net` at v0.31.0/v0.34.0,
`github.com/golang-jwt/jwt/v5` at v5.2.1) — all superseded by the current
resolved versions in the Class A table above, and all confirmed absent from a
fresh scan of the current image.

**Verification.** A locally built image from `main`, scanned with Trivy
(HIGH+CRITICAL), reports 33 findings — none of them in `gibson-runner` — versus
the 339 frozen in the Security tab. The two sets are not comparable artifacts.

**What would reverse this.** Nothing about these specific alerts; they are
immutable history. The *live* posture is tracked by Entry 2 and Entry 3, which
is what a current scan actually reports.

> **Root cause, tracked separately.** The reason a three-month-old scan is still
> the newest data on `main` is `zeroroot-ai/.github#258`: `vuln-scan` in
> `reusable-image-build.yml` is gated on `if: startsWith(github.ref, 'refs/tags/')`,
> so no Trivy analysis ever targets `refs/heads/main`. Until that is fixed, image
> findings on this repo can be raised but never retired. Dismissing these 339 does
> not fix that — it only clears the phantom backlog.

## Entry 2 — Debian base packages with no vendor fix (Class C)

> **Superseded in part — read Entry 6 first.** This entry's original premise
> was "the base image is already current, pinned by digest, so `FixedVersion:
> NONE` means there is nothing to take." Half of that was wrong: the base was
> current *as published*, but nothing ever applied the distro's own security
> updates on top of it. 54 findings per image were fixable all along. The rows
> below that survived that correction — and survived the package removals in
> Entries 4 and 7 — are the real Class-C set. The dispositions are marked.

**Alerts.** 31 findings against `debian:trixie-slim` packages. Not currently in
the Security tab (see the note above — no main-branch Trivy analysis runs); they
will surface as new alerts once `.github#258` is fixed. Pre-recorded here so the
follow-up is mechanical rather than another investigation.

**Dismissed reason.** `won't fix`

**Why.** Every one carries `FixedVersion: NONE` with Trivy status `affected` or
`fix_deferred`. Debian has shipped no patched package, so there is no upgrade to
take: the base image is already current `trixie-slim`, pinned by digest. This is
a "wait for the distro" set, not a "we declined to upgrade" set.

The **Disposition** column is the post-#349 re-audit. "dismissed" means the row
survived all three questions above and is a genuine Class-C dismissal;
"eliminated" means the package is gone from the image and the alert closed on
its own at the next scan.

| CVE | Severity | Status | Packages | Disposition |
|---|---|---|---|---|
| CVE-2026-13221 | CRITICAL | affected | perl-base | dismissed |
| CVE-2026-42496 | CRITICAL | fix_deferred | perl-base | dismissed |
| CVE-2026-57433 | CRITICAL | affected | perl-base | dismissed |
| CVE-2026-8376 | CRITICAL | affected | perl-base | dismissed |
| CVE-2025-69720 | HIGH | affected | libtinfo6, ncurses-base, ncurses-bin | dismissed |
| CVE-2026-12064 | HIGH | affected | curl, libcurl4t64 | **eliminated** (#351) |
| CVE-2026-41992 | HIGH | affected | gzip | dismissed |
| CVE-2026-42497 | HIGH | fix_deferred | perl-base | dismissed |
| CVE-2026-48962 | HIGH | affected | perl-base | dismissed |
| CVE-2026-53615 | HIGH | affected | bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount, util-linux | dismissed |
| CVE-2026-54369 | HIGH | affected | libacl1 | dismissed |
| CVE-2026-57432 | HIGH | affected | perl-base | dismissed |
| CVE-2026-58050 | HIGH | affected | libssh2-1t64 | dismissed (executor only — nmap Depends) |
| CVE-2026-8286 | HIGH | affected | curl, libcurl4t64 | **eliminated** (#351) |
| CVE-2026-8458 | HIGH | affected | curl, libcurl4t64 | **eliminated** (#351) |
| CVE-2026-8927 | HIGH | affected | curl, libcurl4t64 | **eliminated** (#351) |
| CVE-2026-9538 | HIGH | fix_deferred | perl-base | dismissed |

Not in the original table, and fixable after all — see Entry 6:
CVE-2026-13595, CVE-2026-27456, CVE-2025-14104, CVE-2026-53612, CVE-2026-53613
and CVE-2026-53614 against the nine-package `util-linux` family, plus the
lower-severity tail behind the same update. **Fixed in #354, not dismissed.**

**Reachability.** None of the dismissed packages sits on the agent's
request-handling path. Both binaries are static `CGO_ENABLED=0` Go binaries:
they link no `libcurl`, no `libssh2`, no `ncurses`, no `util-linux` library,
and never invoke `perl`. `perl-base` and the `util-linux` family are pulled in
as Debian essential packages; `libssh2-1t64` is a hard `Depends` of `nmap` in
the executor image and is therefore not removable, unlike `libcurl4t64`, which
only `curl` pulled in and which is now gone. The runner execs only the tools
named in the parser registry, with argv constrained by the per-tool allowlist in
`internal/policy`; the bridge runner execs only `npx`/`uvx`.

The claim that "`curl` is present so go-installed binaries can dial TLS" was
wrong and is retracted — see Entry 7.

**What would reverse this.** Debian shipping a fixed package (then: rebuild, and
these retire on their own — and note that with #354 in place a rebuild now
actually takes such a fix); any of these packages becoming reachable from a
parser's exec path; or a proof-of-concept showing exploitation via tool output
rather than local input.

## Entry 3 — Upstream-pinned dependencies in bundled tools (Class B)

**Alerts.** 7 findings inside bundled scanner binaries — 2 HIGH (below), plus
5 lower-severity ones surfaced for the first time by the #349 scan, which reads
every severity rather than only HIGH/CRITICAL: `golang.org/x/mod` v0.37.0 in
`nuclei` (CVE-2026-56864, CVE-2026-56865, both UNKNOWN, fixed upstream in
0.40.0), `golang.org/x/crypto` in `nuclei` (2, UNKNOWN), and CVE-2026-71557
against `go-git` v5.19.1 (MEDIUM, the same module as the HIGH below).

All 7 share one root cause and one reversal condition: the version is pinned by
the *tool's* own `go.mod`, httpx 1.10.0 and nuclei 3.11.1 are the newest
upstream releases, and `replace` directives are forbidden org-wide. Building
from source (#122) picks up the current Go stdlib but cannot move a dependency
the tool itself pins. **Bump both `HTTPX_VERSION` / `NUCLEI_VERSION` on every
upstream release and re-scan** — that is the only lever this repo has, and #343
showed it works: 1.9.0 → 1.10.0 and 3.11.0 → 3.11.1 took the language-package
HIGH/CRITICAL count from 19 to 2.

**Dismissed reason.** `won't fix`

### CVE-2026-56852 — `golang.org/x/text` v0.38.0 in `httpx` (HIGH)

Denial of service via invalid UTF-8 input. Fixed upstream in x/text 0.39.0.

**Why not upgraded.** The version is pinned by `httpx`'s own `go.mod`. The image
builds httpx from source with `go install httpx@v1.10.0`, which resolves that
module's dependencies by its own MVS graph — a consumer cannot override it
without a fork or a `replace` directive, and `replace` directives are forbidden
org-wide. httpx 1.10.0 is the newest release; the fix needs an upstream bump.

**Reachability.** Class B, and genuinely reachable *within its class*: httpx
decodes HTTP response bodies from scan targets, so a hostile target can serve
invalid UTF-8 and crash the httpx process. The blast radius is one short-lived
subprocess inside a per-mission microVM — a failed tool run, not a containment
failure, no cross-tenant effect, no escape. `gibson-runner` itself is unaffected:
it resolves x/text v0.41.0, past the fix.

**What would reverse this.** An httpx release pulling x/text ≥ 0.39.0 (bump the
pin immediately — this one is a straight upgrade the moment it exists); or any
finding that this DoS can be escalated beyond killing the subprocess.

### CVE-2026-71556 — `github.com/go-git/go-git/v5` v5.19.1 in `nuclei` (HIGH)

Arbitrary file read/write via symbolic-link resolution. Fixed upstream in
go-git 5.19.2.

**Why not upgraded.** Pinned by `nuclei`'s own `go.mod`; nuclei 3.11.1 is the
newest release. Same constraint as above.

**Reachability — unreachable from caller input.** Exploiting this requires
nuclei to clone a git repository. In nuclei, go-git is used for custom
template-repository fetches, reached via `-gtr` / `-github-template-repo` /
`-glr` / `-gitlab-template-repo`, or via a config file declaring template repos.
In this image:

- **None of those flags is in the args allowlist.** `parsers/nuclei/policy.go`
  registers an explicit permit-map; `registry.ApplyPolicy` drops every unknown
  flag with a `tool.flag.denied` log event. The allowlist permits only template
  *selection* (`-t`/`-templates`, behind the `templateRef` validator, which
  rejects absolute paths, `..` traversal and any character outside
  `[A-Za-z0-9/._,-]`), severity/tag/type filters, throughput controls, and a
  set of booleans. No repository flag appears in it.
- **The runner never adds one.** `buildArgs` in `parsers/nuclei/nuclei.go`
  composes a fixed base argv — `-jsonl -silent -target <target>` — plus
  allowlist-filtered options. Both doors into `-t` route through the same
  validator.
- **The image ships no nuclei config and no template directory.** Verified in
  the built image: no `~/.config`, no `~/nuclei-templates`. There is no
  on-disk configuration that could enable a template repo.

So the vulnerable code path cannot be entered from a mission spec. This is
unreachability by allowlist, verified against the code, not an assumption from
the sandbox boundary.

**What would reverse this** — any one of these invalidates the argument and the
dismissal must be revisited:

1. Adding a template-repository flag (`-gtr`, `-glr`, or equivalent) to the
   allowlist in `parsers/nuclei/policy.go`.
2. Shipping a nuclei config file, or mounting one, that declares template repos.
3. Nuclei changing its default template installer to use go-git (it currently
   fetches a zip over HTTP).
4. A nuclei release pulling go-git ≥ 5.19.2 — at which point bump the pin and
   drop this entry entirely.

---

## Entry 4 — `gibson-mcp-bridge-runner`'s first-ever scan: 452 findings, 320 removed at source

**Alerts.** 452 Trivy alerts, SARIF category `trivy-gibson-mcp-bridge-runner`,
raised 2026-08-15 when `.github#258` and #348 together produced the first
`refs/heads/main` analysis this image has ever had. 116 were HIGH/CRITICAL.

**Not dismissed — fixed** in #350. This entry records *why nearly all of them
were removable*, because the shape of the answer is reusable.

**The measurement that decided it.** Every one of the 452 carried
`FixedVersion: NONE`. Under Entry 2's original logic that alone would have
justified dismissing the lot. It was the wrong reading — see the three
questions above. Two sources accounted for 320 of the 452, and both failed
question 2:

**1. Debian's `nodejs` + `npm` (≈168 findings).** Debian trixie freezes Node at
20.19.2 — upstream EOL since 2026-04-30 — with npm 9.2.0, itself EOL. Worse,
Debian de-vendors npm into ~65 separate `node-*` packages plus a
`node-gyp` → `libnode-dev` → `python3.13` chain that exists only to compile
native addons this image never builds. Composition: `node-undici` 22,
`nodejs`/`libnode115`/`libnode-dev` 60, the `python3.13` family 48, and
`node-tar` / `node-postcss` / `node-ajv` / `handlebars` /
`node-brace-expansion` and friends for the rest.

This is **Class B, and genuinely reachable within its class**: `npx` is how the
bridge fetches and executes third-party vendor MCP server code, and
`node-undici` is the HTTP client doing the fetching. A finding in the component
that downloads and runs untrusted code is not a "wait for the distro" finding.

Fixed by moving the runtime base to the official `node:24-trixie-slim`
(digest-pinned): Node 24.19.0, Active LTS, with one bundled npm tree that is
patchable by moving a pin. Deliberately not 26.x (Current) — the vendor MCP
servers this image hosts target LTS engines.

**2. `curl` in the runtime stage (≈40 findings).** It existed for one reason:
to `curl` the `uv` tarball at build time. It dragged `libcurl4t64`,
`libssh2-1t64`, `libldap2`, the krb5 quartet and `libsasl2` in behind it.
Moving that download into the build stage — which already has `curl` — and
copying `uv`/`uvx` in as bare binaries removes every one. Nothing in the image
execs `curl`.

**Two pins moved rather than unpinned**, per the standing rule: `uv`
0.7.13 → 0.12.5, and npm pinned to 12.0.2, ahead of the base image's bundle,
which cleared the CRITICAL in npm's vendored `tar` (7.5.16 → 7.5.19) plus three
`undici` and one `ip-address` finding the base carried.

**Result.**

| | findings | HIGH/CRITICAL | dpkg packages |
|---|---|---|---|
| before (#349 as filed) | 452 | 116 | 485 |
| after #350 | 186 | 25 | 81 |
| after #354 | **132** | **25** | 81 |

**Functional verification** (the base swap is the risky part, so it was proven,
not assumed): `npx -y @modelcontextprotocol/server-everything` fetches and
launches as the unprivileged `bridge` user; `uvx` installs and runs a Python
MCP server using uv's own managed CPython, now that Debian's `python3` is gone.

**The trade-off, stated plainly.** Sourcing Node from the official image instead
of `apt` means Trivy no longer tracks the Node *runtime* as an OS package — a
CVE in Node itself will not raise an alert here the way `nodejs 20.19.2` did.
What is bought: a supported LTS runtime instead of an EOL one, and a patchable
npm. What guards it: the base digest pin, the `# tag:` comment naming the tag
that digest belongs to, and #353, which tracks the fact that nothing currently
refreshes an `ARG`-form digest pin. Until #353 is closed this rests on manual
attention, and that is the weak link in this entry.

**What would reverse this.** Node 24 reaching EOL without the pin moving to the
next LTS; #353 being closed as "won't fix", leaving the base pin with no refresh
path; or the bridge gaining a code path that execs `curl`.

---

## Entry 5 — npm's own bundled dependency tree (Class B)

**Alerts.** 9 findings under `usr/local/lib/node_modules/npm/node_modules/` in
the bridge image: `brace-expansion` 5.0.7 (2 HIGH — CVE-2026-14257,
CVE-2026-69152), `ip-address` 10.2.0 (1 HIGH CVE-2026-69192, 2 MEDIUM),
`tar` 7.5.19 (1 MEDIUM, GHSA-r292-9mhp-454m) and `undici` 6.27.0 (3 MEDIUM).

**Dismissed reason.** `won't fix`

**Why not upgraded.** These are vendored inside npm. The image pins
`npm@12.0.2`, which is the current `latest` — and pinning it is already an
*upgrade*: the base ships an older npm, and moving the pin forward is what
cleared five findings the base carried, including a CRITICAL in `tar`. A
consumer cannot replace a package inside npm's own `node_modules` without
unpacking and repacking npm, which trades a known-version dependency for an
unauditable one. The remaining nine need an npm release.

**Reachability — Class B, bounded.** All four packages sit on npm's
package-resolution path, which is exactly what `npx -y <pkg>` exercises when the
bridge launches a vendor MCP server. They are reachable, and this entry does not
pretend otherwise. What bounds them:

- **The package name is not caller-controlled.** It comes from the connector
  manifest (`GIBSON_CONNECTOR_MANIFEST_B64` / `_PATH`, resolved by
  `internal/bridgerunner`), which the daemon composes from a registered
  connector definition. A mission caller does not get to name an arbitrary npm
  package for `npx` to fetch.
- **The failure modes are denial-of-service and parse confusion, not
  execution.** `brace-expansion` is ReDoS; `ip-address` is address-parse
  confusion; the `tar` and `undici` items are extraction and HTTP-handling
  issues in a process that is about to execute the fetched package *by design*.
  `npx` runs as the unprivileged `bridge` user inside a per-connector microVM,
  so the blast radius is one connector's launch.
- **Nothing under `/usr/local` is writable by `bridge`** — verified on the built
  image — so a write primitive in the extraction path has no system target.

**What would reverse this** — any one of these:

1. An npm release carrying patched `brace-expansion`, `ip-address`, `tar` or
   `undici`: bump `NPM_VERSION` in `Dockerfile.mcp-bridge` immediately and drop
   the corresponding row. A straight upgrade the moment it exists.
2. The connector manifest becoming reachable from mission-caller input, making
   the fetched package name attacker-chosen.
3. Any of these being reclassified from DoS/parse to code execution.
4. `npx` ever running as a user who can write to `/usr/local`.

---

## Entry 6 — pending distro security updates neither image was taking

**Alerts.** 54 per image: CVE-2026-13595, CVE-2026-27456, CVE-2025-14104,
CVE-2026-53612, CVE-2026-53613 and CVE-2026-53614, each against the nine-package
`util-linux` family (`bsdutils`, `libblkid1`, `liblastlog2-2`, `libmount1`,
`libsmartcols1`, `libuuid1`, `login`, `mount`, `util-linux`).

**Not dismissed — fixed** in #354.

**Why they were fixable.** Entry 2 assumed `FixedVersion: NONE` meant the base
image was already current. Only half true: the base digests were current *as
published*, but the base image layer had not been rebuilt since Debian pushed
`util-linux 2.41.5-0+deb13u1` to `trixie-security`, and neither Dockerfile ever
ran `apt-get upgrade`. Confirmed directly:

```
$ docker run --rm debian:trixie-slim sh -c 'apt-get update -qq; apt-cache policy util-linux'
util-linux:
  Installed: 2.41-5
  Candidate: 2.41.5-0+deb13u1
     2.41.5-0+deb13u1 500 http://deb.debian.org/debian-security trixie-security/main
```

Both runtime stages now `apt-get upgrade` after `apt-get update`. The digest pin
still fixes the reproducible starting point; the upgrade closes the gap between
that point and build time. It does **not** replace refreshing the pin — see
#353.

**What would reverse this.** Nothing; this is a fix, recorded so the reasoning
error it corrects does not recur. The general lesson is written up as the three
questions in "Before dismissing anything" above.

---

## Entry 7 — `curl` and `jq` removed from the executor image

**Alerts.** ~61 findings in the `trivy-gibson-executor` category against `curl`,
`libcurl4t64` and the `libldap2` / krb5 / `libsasl2` chain that only `libcurl`
pulled in. 8 were HIGH: CVE-2026-12064, CVE-2026-8286, CVE-2026-8458 and
CVE-2026-8927, each against both `curl` and `libcurl4t64`.

**Not dismissed — fixed** in #351, by deleting both packages.

**Why they were removable.** Nothing execs either. `registry.Parsers` covers
amass, dnsx, httpx, masscan, naabu, nmap, nuclei and subfinder, and every one
`exec.CommandContext`s its own named binary. `curl` and `jq` appear only in
TOOLS.md's 🟡 "long tail" wish-list, which has no parser and no `raw_exec`
fallback behind it.

Entry 2's stated justification — "`curl` is present so go-installed binaries can
dial TLS" — was wrong and is retracted. The static `CGO_ENABLED=0` Go binaries
dial TLS themselves; what they need is the trust store (`ca-certificates`, which
stays), not a transport. A wrong reason in a ledger is worse than no reason: it
gets cited.

`libssh2-1t64` stays. `nmap` hard-`Depends` on it, so it is not removable this
way; it remains a Class-C dismissal under Entry 2.

**What would reverse this.** A generic-exec parser landing (`raw_exec` / `shell`,
TOOLS.md "Generic / long tail"), which would make any binary in the image
caller-reachable. `Dockerfile` now says so inline: re-add the binary a parser
needs in the same change that registers the parser, and re-triage the image.

---

## Entry 8 — Scorecard `PinnedDependenciesID` on the npm pin (self-inflicted)

**Alert.** 1 Scorecard alert, category `supply-chain/local`, MEDIUM:
`score is 8: npmCommand not pinned by hash`, at `Dockerfile.mcp-bridge:116` —
the `RUN npm install -g "npm@${NPM_VERSION}"` line.

**Dismissed reason.** `won't fix`

**Introduced by #350.** This alert did not exist before the bridge-image
rework; it was created the minute that PR merged. Recording it as *ours* rather
than as pre-existing noise is the point of this entry — a fix that trades one
finding for another has to say so.

**Why the line exists.** The npm bump is not optional. It clears a CRITICAL in
npm's vendored `tar` (7.5.16 → 7.5.19) plus `undici` and `ip-address` findings
that the base image carries. There is no base tag that avoids it — checked:
`node:24-trixie-slim` bundles npm 11.17.0 and `node:26-trixie-slim` bundles
11.19.0, neither of which is 12.x. Dropping the bump reintroduces the CRITICAL.

**Why not hash-pin it.** Scorecard wants a content hash rather than a version
spec. Three things argue against manufacturing one here:

1. **The version spec is already effectively a content pin.** npm's registry
   forbids republishing an existing version, so `npm@12.0.2` resolves to fixed
   content.
2. **npm already verifies integrity.** The registry packument carries a SHA-512
   `dist.integrity` for the tarball and npm checks it on install. The install
   is integrity-checked; what it is not is checked against a hash *we* vendored.
3. **A hand-maintained hash is a rot trap.** Hash-pinning means fetching the
   tarball in the build stage and `sha256sum -c`-ing it against a constant that
   must be updated in lockstep with every npm bump. Miss one and the build
   breaks confusingly, or worse, someone deletes the check to unbreak it. It
   also still runs `npm install <spec>`, so it very likely does not clear the
   check anyway.

The honest summary: this is a real supply-chain hygiene signal, the residual
risk is small and already covered by registry-side integrity verification, and
the available "fix" is weaker than what it replaces.

**What would reverse this** — any one of these:

1. npm gaining first-class support for an integrity-pinned global install
   (e.g. an `--integrity` flag honoured for `install -g`): take it immediately.
2. A base image tag shipping an npm whose vendored tree is already clean, which
   removes the need for the line entirely.
3. Evidence that an exact npm version spec can resolve to different content —
   which would invalidate point 1 above and make this urgent, not cosmetic.
4. Scorecard's check learning to accept an exact version spec, at which point
   this retires on its own.

**Not covered by this entry.** The other 5 open `supply-chain/local` Scorecard
alerts predate this work and are untriaged. They are a different stream from
the image findings and need their own pass.

---

## Entry 9 — `amass` removed from the catalog: no shippable version accepts its argv

**Alerts.** 44 findings in the `trivy-gibson-executor` category against
`usr/local/bin/amass`, including both new CRITICALs (`CVE-2026-33815`,
`CVE-2026-33816`, `github.com/jackc/pgx/v5` v5.4.3) and 24 HIGH
(`golang.org/x/crypto` v0.13.0 and `golang.org/x/net` v0.15.0, both 2023-era —
#368).

**Not dismissed — removed** in #371 (parser + catalog registration +
Dockerfile install/`COPY`), same move as Entry 7's `curl`/`jq`.

**Why this is a removal, not a triage.** Entry 3's Class-B framework assumes
the tool at least runs. amass does not: `parsers/amass` built
`enum -passive -json /dev/stdout -d <target>`, and no currently shippable
amass version accepts that argv.

```
$ amass enum -passive -json /dev/stdout -d example.com
flag provided but not defined: -json
```

| version | verdict |
|---|---|
| v3.x | accepts `-json`; oldest dependency tree, worst CVE surface |
| v4.2.0 (what #352 pinned) | no JSON output at all — fails at flag parsing on every call |
| v5.x | client/engine HTTP split, no embedded engine — incompatible with this one-shot exec model (#366) |

So this was never a live Class-B tradeoff (CVE surface vs. capability): the
44 findings bought zero working capability. `--verify-tools` reported `ok
amass` because it only `LookPath`s the binary; the break only surfaces at
`enum` time (#370).

**Measured, both sides, locally built + scanned (`trivy image --scanners vuln`,
all severities), same Debian layer, same day:**

| | total | HIGH/CRITICAL |
|---|---|---|
| before (main, amass present, matches #368) | 217 | 68 |
| after (#371, amass removed) | **173** | **44** |
| delta | **-44** | **-24** |

**What would reverse this.** `parsers/amass` rewritten against v4's `-o`/
`-oA` **text** output instead of the JSON-lines shape this entry's parser
expected — a different format, not a flag fix. Tracked in #370. Until then,
re-adding the binary with no working parser behind it is exactly the
Entry 7 "installed but not catalogued" failure mode this ledger exists to
catch.

---

## Re-audit procedure

**Scan at every severity.** The SARIF upload is not severity-filtered, so the
Security tab carries MEDIUM, LOW and UNKNOWN alerts too. This procedure used to
say `--severity HIGH,CRITICAL`, which is how 225 lower-severity executor alerts
sat untriaged while the ledger read as complete.

1. Build and scan the image:
   ```
   make image
   trivy image --scanners vuln ghcr.io/zeroroot-ai/gibson-executor:dev
   ```
   Local scanning is the reliable signal — the SARIF counts have matched a local
   unfiltered scan exactly on every check so far.
2. Read the SARIF category on any alert first. Only
   `trivy-gibson-executor` is live. An alert under
   `trivy-gibson-mcp-bridge-runner` is stranded history: nothing emits that
   category since #413 removed the bridge image.
3. For each finding, answer the three questions in "Before dismissing anything"
   **in order**. Do not skip to reachability.
4. Diff what remains against Entries 2–7. Anything new is un-triaged and must be
   classified before it is dismissed.
5. Any finding in `/usr/local/bin/gibson-runner` is **Class A** — fix it, do not
   add it here. It is currently clean.
6. When a dismissal's reversal condition is met, reopen the alert
   (`PATCH .../code-scanning/alerts/{n}` with `state=open`) and remove the entry.

### Current baseline (post-#350/#351/#354, locally measured)

| image | findings | HIGH/CRITICAL | Class A | State |
|---|---|---|---|---|
| `gibson-executor` | 143 | 25 | 0 | live |
| `gibson-mcp-bridge-runner` | 132 | 25 | 0 | removed 2026-09-01 (#413) |

Of the 25 HIGH/CRITICAL in the executor image: 23 are Debian packages the distro
has not patched at all (Entry 2), and the remaining 2–3 are dependencies vendored
inside third-party tools (Entries 3 and 5). None is Class A.
