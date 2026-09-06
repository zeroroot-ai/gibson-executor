# Security model — gibson-executor

This document describes the security boundaries of `gibson-executor`
and the per-tool args allowlist that protects long-running CLI tools
(nmap, nuclei, masscan, …) from caller-controlled flag injection.

## Threat model

The tool runner runs inside a Kubernetes pod with elevated capabilities:

- `nmap`, `masscan`, `naabu` need raw-socket access (`CAP_NET_RAW`).
- `httpx`, `nuclei` make outbound HTTP requests to caller-specified
  targets.
- All tools can in principle write to the pod filesystem.

The `req.Args []string` field in every parser's `ExecuteRequest` arrives
from the daemon's mission planner, which builds it from the **mission
spec** the operator (or a delegated user) submitted. In a multi-tenant
deployment, the mission spec is a hostile input boundary: callers can
include any string they want in `req.Args`, and without filtering those
strings flow directly into the tool's argv. Tools then interpret those
arguments according to **their** documented behaviour — which often
includes flags that read or write arbitrary paths, such as nmap's
`-oN <file>`, masscan's `-oX <file>`, or nuclei's `-templates <dir>`.

The threat: a malicious or compromised mission spec can use a
plain-looking tool invocation to read or write any file the tool has
access to inside the runner pod, including:

- Kubernetes service account tokens at `/var/run/secrets/.../token`
- Mounted Vault secrets
- Other tenants' working files in shared scratch volumes

`req.Target` and `req.Options` arrive from the same mission spec and are
therefore equally hostile. They are three separate writes into one argv,
so all three go through a policy:

| Field | Control |
|---|---|
| `req.Args` | per-tool args allowlist (`registry.ApplyPolicy`) |
| `req.Options` | the same allowlist, per option (`registry.ApplyOption`) |
| `req.Target` | per-tool target syntax (`registry.ValidateTarget`) |

## Defense: per-tool args allowlist

`internal/policy/policy.go` provides the `ArgsPolicy` type — a map of
**permitted flag name → value validator**. Every parser registers its
allowlist via `registry.RegisterArgsPolicy(toolName, policy)` from the
`policy.go` file in its package.

At dispatch, the parser calls `registry.ApplyPolicy(toolName, req.Args, log)`
which:

1. Looks up the registered policy.
2. Filters `req.Args` against the allowlist:
   - Unknown flags are **dropped** with a structured log event
     `tool.flag.denied`.
   - Allowed flags whose value fails the validator return a hard error
     (the parser surfaces this as `InvalidArgument`).
   - A nil policy = "deny every flag" (the strictest default).
3. Returns the filtered argv to feed the underlying CLI.

Output-file flags (e.g. `-oN`, `-oX`, `-output`, `--output-filename`) are
**denied by default** for every tool. The runner itself pins the
canonical output target (e.g. `-oX -` for nmap, `-oJ -` for masscan) and
consumes the result on stdout. There is no legitimate reason for a caller
to override this, and allowing it opens an arbitrary file write or read.

Input-path flags are the mirror image and are handled the same way. The
one that is allowed — nuclei's `-t` / `-templates`, because template
selection is a documented input of that tool — carries a validator that
admits only a relative reference with no `..` traversal, so it can only
ever resolve inside the runner's pinned template directory.

## Defense: target validation

`req.Target` is not a flag, but it lands on the same argv, and a tool
reads it with the same parser. Two shapes matter:

- A target beginning with `-` is read by the tool as a **flag**. A caller
  who cannot pass `-oN` through `req.Args` can otherwise pass it as the
  target instead, which makes the args allowlist decoration.
- A target carrying a newline is a line-oriented injection for any tool
  that reads its subject list from stdin or a file (dnsx uses
  `-l /dev/stdin`), so one newline becomes N targets.

`policy.ValidateTarget(target, kinds)` closes both by requiring the
target to parse as one of the syntaxes the tool documents — an IP, a CIDR
prefix, a hostname, or an absolute http(s) URL — after rejecting a
leading `-`, control characters and whitespace outright.

Each parser declares its accepted syntaxes with
`registry.RegisterTargetPolicy(toolName, kinds)` in its `policy.go`, and
calls `registry.ValidateTarget(toolName, req.Target)` first thing in
`buildArgs`. A tool that registers nothing **fails closed**: no argv is
built at all. `cmd/gibson-runner` runs the same gate once centrally
before dispatch, so a parser that forgets the call is still unreachable
with a hostile target.

Where the tool supports an end-of-options terminator, the parser emits
`--` before the positional target as a second line of defence (nmap
parses with `getopt_long`, so `--` stops flag interpretation). masscan
has no documented terminator, so its accepted target syntax is
correspondingly narrower — an address or a prefix only.

## Defense: options are not a side door

A parser that writes `args = append(args, "-p", req.Options["ports"])`
hands the caller an argv slot with **no** validator, for a flag the
allowlist may not even grant. Options therefore never build argv
directly; they go through `registry.ApplyOption(toolName, flag, value,
log)`, which enforces three rules:

1. The flag must be in the tool's allowlist.
2. The flag's validator must be non-nil. A nil validator means the flag
   is boolean, so pairing a value with it would put an unvalidated token
   on the argv.
3. The value must not begin with `-`. `ApplyArgs` can never pair a
   dash-leading value, so accepting one here would make `req.Options`
   strictly weaker than `req.Args`.

The same "no value for a boolean flag" rule applies inside `ApplyArgs`:
an allowlisted boolean flag emits alone, and the following token is
dropped as a stray positional rather than riding onto the argv.

## How to add a new tool

1. Create the parser package under `parsers/<tool>/`.
2. In its `policy.go`, list every safe flag from the tool's official
   documentation (one map entry per flag), with the appropriate
   validator. Use `policy.AllowAny` only when the value's shape is
   policed by the tool itself; prefer `policy.AllowEnum(...)` for
   bounded sets and `policy.PathUnder(prefix)` for any path argument.
3. In the same `policy.go`, declare the target syntaxes the tool
   documents:
   ```go
   registry.RegisterTargetPolicy(toolName, policy.TargetNetwork)
   ```
   Omitting this fails closed — the parser will refuse every request.
4. Give the parser a `buildArgs(req) ([]string, error)` that composes the
   whole argv, so the argv is unit-testable without the CLI installed:
   ```go
   func buildArgs(req registry.ExecuteRequest) ([]string, error) {
       if err := registry.ValidateTarget(toolName, req.Target); err != nil {
           return nil, fmt.Errorf("<tool> target: %w", err)
       }
       args := []string{ /* runner-pinned flags */ }
       if v := req.Options["<name>"]; v != "" {
           pair, err := registry.ApplyOption(toolName, "-<flag>", v, nil)
           if err != nil {
               return nil, fmt.Errorf("<tool> <name> option: %w", err)
           }
           args = append(args, pair...)
       }
       filtered, err := registry.ApplyPolicy(toolName, req.Args, nil)
       if err != nil {
           return nil, err
       }
       args = append(args, filtered...)
       return append(args, "--", req.Target), nil // `--` only if the tool supports it
   }
   ```
5. Add a `policy_test.go` under the same package asserting:
   - The canonical output-file injection (e.g. `-oN /etc/passwd`) is
     dropped with `tool.flag.denied`.
   - At least one documented safe flag passes through unchanged.
6. Add a `buildargs_test.go` asserting:
   - A leading-dash target, a newline-bearing target and an empty target
     are all rejected.
   - An option value cannot itself be a flag.
   - A valid target and a valid option still build an argv.

## How to add a new safe flag to an existing tool

Append the entry to the tool's `argsPolicy` map in `policy.go`. Verify
the existing tests still pass and add a new test asserting the new flag
is allowed under happy-path inputs.

## Output-file flag policy

Output-file flags are the most common attack surface. Each tool's
`policy.go` enumerates every output flag and **does not** include them
in the allowlist. If a future feature legitimately needs a tool to write
to a path the caller controls, the validator must be `policy.PathUnder`
constrained to a runner-managed tempdir — never a free-form path.

## Process sandbox (`internal/sandbox`)

Every tool invocation is additionally wrapped by the sandbox package,
which applies four OS-level controls that are orthogonal to the args
allowlist:

### 1. Process-group isolation (`Setpgid`)

Each child process runs in its own process group (`SysProcAttr.Setpgid
= true`).  When the per-call deadline fires, the Go runtime sends
`SIGKILL` to the entire group (`kill(-pgid, SIGKILL)`), reaching any
grandchildren the tool may have forked.  Without this, a process that
forks a grandchild and exits can leave the grandchild running
indefinitely inside the pod.

### 2. Per-tool virtual-memory ceiling (RLIMIT_AS)

The runner re-execs itself in a small pre-exec mode which calls
`setrlimit(RLIMIT_AS)` and then `execve`s the real tool.  Because
`execve` replaces the process image without forking, the limit is in
force the moment the kernel loads the tool, and the tool keeps the PID
the runner is waiting on and the process group `Setpgid` put it in.
Both the soft and the hard limit are pinned, so a tool cannot raise its
own ceiling back up.

No shell is involved.  The tool's argv is carried as an argv from end
to end and is never flattened into a string for anything to re-parse.

Default: **2 GiB**.  Override per-deployment with the environment
variable `TOOL_RUNNER_MEMORY_BYTES` (bytes).  Values below **1 GiB**
are clamped up to it — see "Why the numbers look large" below. See
"Overriding the defaults" below for how this env var actually gets set.

### 3. Runner virtual-memory ceiling (RLIMIT_AS on the runner)

The runner also bounds **itself**, via `setrlimit(RLIMIT_AS)` on its own
process at startup.  The runner is the process that buffers tool output,
so a ceiling on the children alone leaves the largest allocator in the
pipeline unbounded.

Only the soft limit is lowered; the inherited hard limit is left alone,
so an environment that already constrains the runner keeps its own
bound and the pre-exec helper can still set the per-tool ceiling.

Default: **3 GiB**, raised automatically if the configured output cap
implies a higher floor.  Override with `TOOL_RUNNER_SELF_MEMORY_BYTES`.

This is defence in depth, not the primary bound — the output cap below
is unconditional — so a platform whose seccomp profile refuses
`setrlimit(2)` logs a warning and continues rather than refusing to
start.

### Why the memory numbers look large

`RLIMIT_AS` caps *virtual address space*, not resident memory, and a Go
runtime reserves a lot of address space before `main` runs.  Measured on
linux/amd64: a trivial Go binary cannot start at all under a 512 MiB
`RLIMIT_AS` (`failed to reserve page summary memory`), and a Go process
that buffers two 100 MiB streams needs roughly 1.7 GiB of address space.

`httpx` and `nuclei` are Go binaries, and so is the runner.  A ceiling
that reads as generous for a C program is simply an unbootable one here.
That is why the floors are enforced rather than obeyed: a smaller value
does not produce a tighter sandbox, it produces a tool that cannot run.

### 4. Output cap (`CappedBuffer`)

Each child's stdout and stderr are captured through a `CappedBuffer`
writer.  Bytes beyond the configured cap are silently dropped in memory
(the subprocess continues running — it can still write) and
`CappedBuffer.Err()` returns `ErrOutputCapExceeded` after the run.
The parser surfaces this as a hard error rather than silently
truncating the result.

Default: **100 MiB per stream**.  Override with
`TOOL_RUNNER_OUTPUT_CAP_BYTES` (bytes) — see "Overriding the defaults"
below for how this env var actually gets set.

### 5. Per-call deadline

Every tool call runs under a deadline; there is no input that produces an
unbounded run.  The deadline is `CallToolRequest.timeout_ms` when the
caller supplies one, otherwise the parser's declared
`CatalogEntry.DefaultTimeoutSeconds`, otherwise a conservative 300 s
backstop for a parser that declares none.

Sub-second requests round **up** to one second.  Truncating them would
turn the tightest deadline a caller can express into no deadline at all.

The deadline is also what bounds an output flood: `CappedBuffer` stops
buffering at the cap but deliberately keeps accepting writes so the tool
does not die on `EPIPE`, so a tool that never stops talking is stopped
by the clock, not by the cap.

### Overriding the defaults

There is no Helm chart for this image and no `templates/deployment.yaml`
to set env vars on. Per ADR-0052, `gibson-executor` runs as a **setec
microVM guest** launched directly by the gibson daemon — `helm/gibson-workloads/values.yaml`
in `zeroroot-ai/charts` states outright that this workload "has no
Deployment, Service, ServiceAccount, or ClusterSPIFFEID in this chart."
The only override surface today is the sandbox launch environment
itself: `TOOL_RUNNER_OUTPUT_CAP_BYTES`, `TOOL_RUNNER_MEMORY_BYTES`, and
`TOOL_RUNNER_SELF_MEMORY_BYTES`, set on `LaunchRequest.Env` by whatever
calls `harness/sandboxed.Executor`.

An environment that still sets `TOOL_RUNNER_MEMORY_BYTES` to a value as
low as the old `256` MiB default is safe: the runner clamps it up to
the floor rather than failing to start the tool.

Making these operator-tunable via a chart passthrough is a real design
change, not a docs fix, and needs an owner decision on whether tool
resource limits belong to the image or the deployment.

## What is NOT covered

- **Authorisation of the target.** Validation proves the target is a
  well-formed address, prefix, name or URL — not that the caller is
  entitled to scan it. Scope authorisation stays with the daemon.
- **Network rate-limiting.** Enforced by the pod's runtime constraints
  and by per-tool `CatalogEntry.Resources` hints, not by this package.
- **Wall-clock budget across calls.** Each call is individually bounded
  (see below), but the runner does not track a budget spanning calls.

## Reporting issues

If you find a bypass — a flag that escapes a validator, a way to inject
an unknown flag through positional encoding, or any other escape — open
an issue with the reproduction steps. Do **not** open a public issue if
the bypass enables tenant-isolation breakage; use one of the private
channels below instead:

1. **GitHub private vulnerability reporting** (preferred): open this
   repository's `Security` tab and select `Report a vulnerability`
   (https://github.com/zeroroot-ai/gibson-executor/security/advisories/new).
   This creates a draft advisory visible only to maintainers.
2. **Email:** `security@zeroroot.ai`.
