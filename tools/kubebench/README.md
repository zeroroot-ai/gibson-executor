# `tools/kubebench` and `parsers/kubebench`

This module builds the one `kube-bench` binary the executor image ships. It
builds nothing of our own. It is a separate module from `tools/recon` and
`tools/trivy` for the same reason they are separate from each other: kube-bench
links the Kubernetes client, the AWS SDK and a database driver, and one module
for all of them would let a bump of one tool move the dependencies of another.

The parser is `parsers/kubebench`. This file covers what the tool does, what it
does not do, and how the golden fixture was made.

## What a run covers

kube-bench has five targets. Four of them read the machine they run on: files
under `/etc/kubernetes`, the command lines of local processes, file modes. This
tool runs in a sandbox that is not a cluster node. Those four would audit the
sandbox and report its settings as the cluster's. The tool therefore runs
`--targets policies` only. That target is CIS section 5 (RBAC, pod security,
network policy, secrets) and reads the cluster through the Kubernetes API.

The target is fixed. It is not an input. The other four targets need the
executor to run on the node, which is a different tool.

## Input

| field | required | meaning |
|---|---|---|
| `target` | yes | Cluster name, a DNS-style label. It names the result. It never locates the cluster. |
| `kubeconfigSecret` | yes | NAME of the tenant secret holding a kubeconfig for the cluster. A name, never a value. |
| `benchmark` | no | `cis-<major>.<minor>`. Default: chosen from the version the cluster reports. |

`args` is rejected. The tool exposes no kube-bench flag.

### The credential

The mission declares which named tenant secrets its tools may receive
(gibson#485). `kubeconfigSecret` names one of them. The daemon resolves the
name as itself at dispatch and puts the VALUE in the tool's environment, under
the variable `sdk/secretenv` derives — `goat-kubeconfig` arrives as
`GIBSON_SECRET_GOAT_KUBECONFIG`.

The input carries the name, never the value. A tool's input JSON is captured
with the tool call, so a credential written into the input would be stored and
displayed. This tool therefore reads no credential value from its input, and no
path, no ambient environment variable and no default location either.

Two failures, reported differently, because the fix is in a different place:

- `kubeconfigSecret` is absent — the mission named no secret for this tool.
- `kubeconfigSecret` names a secret the environment does not carry — the
  mission named it but did not declare it for this tool, so the daemon handed
  it to something else or to nothing. The message names the variable it looked
  for.

When the kubeconfig is present but wrong, the tool fails and names what is
wrong: unreadable, an exec plugin, a file reference, or a cluster that does not
answer. Every one of these is an error. None is an empty result.

A kubeconfig that needs an exec plugin, `auth-provider`, `tokenFile` or a file
path for a certificate is refused. The kubeconfig is tenant-supplied and each
of those would run a program or read a file of the tenant's choosing.

## Output

| node | count | content |
|---|---|---|
| `BenchmarkRun` | 1 | benchmark, Kubernetes version, counts, and the id of every control not assessed, with the reason |
| `Finding` | one per failed control | title `CIS <id>: <text>`, remediation from kube-bench, severity below |
| `Evidence` | one per Finding | the control's result object exactly as kube-bench printed it |

### What counts as a failed control

kube-bench folds three different things into `FAIL` and `WARN`. The parser
separates them:

| kube-bench says | Meaning | Becomes |
|---|---|---|
| `PASS` | the control conforms | nothing, counted |
| `FAIL` or `WARN`, no reason, value does not match | assessed, did not conform | **Finding** |
| `WARN` with reason "Test marked as a manual test" | kube-bench does not automate it | listed in `not_assessed_manual` |
| `INFO` | the benchmark configuration skips it | listed in `not_assessed_skipped` |
| `FAIL` or `WARN` with any other reason | the audit command failed, or the control has no tests | listed in `not_assessed_errored` |
| the value starts with a known fault line (see below) | the audit script broke | listed in `not_assessed_errored` |

An errored control is not a Finding. A Finding is a claim about the cluster.
An error is a fact about the run. It is not dropped either: it is named on the
`BenchmarkRun` node, `complete` is `false`, and the parse quality is `partial`.

When no control produced a verdict, the tool returns an error and no result.

Almost every control in section 5 is unscored (manual). A failed unscored
control is graded `WARN` by kube-bench. The parser reports it as a Finding with
a lower severity. Without this the policies target would return nothing for a
cluster full of failures.

### Severity

CIS publishes no severity and kube-bench's JSON carries none. The only grading
fields are `status` and `scored`. The parser assigns two tiers from the
strength of the verdict:

- `medium`: a scored control failed.
- `low`: an unscored control did not conform.

There is no per-control table. A table would present a guess as if CIS had
said it.

### Known limit of fault detection

kube-bench merges the audit script's stderr into the value it tests, and a
script whose last command succeeds exits 0. So a broken audit looks like an
ordinary result. The parser detects a short, closed list of fault lines
(`/bin/sh:`, `Error from server (Forbidden)`, `Error from server
(Unauthorized)`, `Unable to connect to the server`, `The connection to the
server`, `error: You must be logged in`). A failure that matches none of them
is reported as a normal result. `Error from server (NotFound)` is deliberately
not on the list: in the recording, control 5.1.6 prints it for one static pod
inside a run that also holds nine real nonconformities.

A credential with less access than the audit needs reaches this path. That is
why `Forbidden` is on the list.

## Image requirements

- `kubectl`: kube-bench's audit scripts call it, and so does the preflight.
  Pinned by version and SHA-256 per architecture in the `Dockerfile`.
- `jq`: the audit scripts pipe through it. Installed from apt.
- `/bin/sh` is bash. kube-bench hard-codes `/bin/sh` and its scripts use
  `[[ ]]`. dash has none. See the `Dockerfile`.
- `/etc/kube-bench/cfg`: the benchmark definitions, copied from the module at
  the pinned version.

## The golden fixture

`parsers/kubebench/testdata/policies.json` is a recording. It is the stdout of
`kube-bench run --targets policies --json` with these parts:

- kube-bench v0.16.0, the upstream `linux_amd64` release binary.
- A throwaway single-node kind cluster, Kubernetes v1.33.1, deleted after the
  run.
- The `debian:trixie-slim` image the executor ships on, with `jq` installed and
  the host's `kubectl` v1.33.13 mounted in.

It was **not** produced by the executor image itself, and it was produced with
`/bin/sh` as dash, before the `bash` fix. That is why control 5.1.1 shows
`/bin/sh: 3: [[: not found` as its value. The recording is kept as it came out
because that is a real faulty control and the parser tests depend on it.

It was not regenerated after the `bash` fix. The cluster was removed. When the
credential path lands, record it again from the shipped image and compare.

## Bump procedure

1. Change the `github.com/aquasecurity/kube-bench` requirement in `go.mod`.
2. Change `KUBE_BENCH_VERSION` in `Dockerfile` to the same version. The build
   asserts they agree.
3. Run `go mod tidy` in this directory.
4. Record a new fixture. A new benchmark version can add, renumber or reword
   controls. The golden test names control ids and counts, so it will fail.
5. Check that the cluster versions you support still map to a benchmark in the
   new `cfg/config.yaml`. kube-bench v0.16.0 maps up to Kubernetes 1.34 only.
   A newer cluster fails with kube-bench's own message unless `benchmark` is
   given.
