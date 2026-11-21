# auth.md: `zeroroot-ai/gibson-executor`

This page describes the auth model of the tool runner as the code is today.
It is for AI agents and for engineers who change the runner.

## Summary

The tool runner holds no identity and no credential of its own.
It does not authenticate to the Gibson daemon, and it opens no gRPC
connection to the daemon.

The daemon starts the runner as a Setec microVM guest for one tool call
(ADR-0052). The daemon puts the request in the guest environment. The runner
writes the response to stdout. The daemon reads the response from the
captured stdout. The trust boundary is the microVM, not a token.

## Modes and what each one reaches

`cmd/gibson-runner/main.go` has four modes. None of them gets a token or
reads a client secret.

| Mode | What it reads | What it reaches over the network |
|---|---|---|
| default (no flag) | `GIBSON_TOOL_NAME`, `GIBSON_TOOL_INPUT_B64`, declared secrets | Only the tool target. The tool binary makes this traffic. |
| `--list-tools` | Nothing | Nothing. It prints the JSON catalog to stdout. |
| `--verify-tools` | `PATH` | Nothing. It checks that each binary in the catalog is on `PATH`. |
| `--serve` | `GIBSON_DAEMON_ADDRESS`, `RUNNER_HEALTH_ADDR`, `OTEL_*` | A TCP dial to the daemon address for `/readyz`, and the OTel collector. |

## The tool call ABI

The default mode runs one tool call:

1. The daemon sets `GIBSON_TOOL_NAME` to the tool name.
2. The daemon sets `GIBSON_TOOL_INPUT_B64` to the base64 of a protojson
   `gibson.component.v1.CallToolRequest`.
3. The runner looks up the parser, validates the target, and runs the tool
   under a deadline.
4. The runner writes one stdout line that starts with
   `===GIBSON_TOOL_OUTPUT===`, followed by the base64 of a protojson
   `CallToolResponse`.

A tool error goes back inside `CallToolResponse.error`. If the image has no
parser for the tool name, the runner writes `===GIBSON_TOOL_ERROR===` and a
message instead, and exits with code 4. The SDK
package `toolrunner` (sdk v0.212.0) documents the same ABI for SDK tools.
This repository does not import that package. For the ABI, it uses only the
generated proto types from `github.com/zeroroot-ai/sdk/api/gen`.

## Declared secrets

Some tools need a credential, for example a kubeconfig for `kube-bench` or
`trivy-k8s`. The runner never reads a credential value from the tool input,
because the daemon stores the input with the tool call.

1. The mission declares the names of the tenant secrets that a tool can get
   (gibson#485).
2. At dispatch, the daemon resolves each name and puts the value in the
   guest environment.
3. The variable name comes from `secretenv.Key` in the sdk. For example,
   `goat-kubeconfig` becomes `GIBSON_SECRET_GOAT_KUBECONFIG`.
4. The tool input carries only the secret name, in a field such as
   `kubeconfigSecret`.
5. `registry.DeclaredSecret` reads the value with `secretenv.Lookup`.

If the variable is absent or empty, `DeclaredSecret` returns an error that
names the secret. It never falls back to an ambient credential. Read
[`internal/registry/declared_secret.go`](../internal/registry/declared_secret.go)
for the two error cases.

## The `--serve` readiness probe

In `--serve` mode, the runner starts a health server (default `:8081`) with
`/readyz` and `/healthz`. The readiness check is `probes.DaemonProbe` in
[`internal/probes/daemon.go`](../internal/probes/daemon.go).

The probe opens a TCP connection to `GIBSON_DAEMON_ADDRESS` and closes it
at once. The default address is `localhost:50002`. The probe sends no data
and no credential. It shows only that the address accepts a connection.

## Files

| Concern | File |
|---|---|
| Mode selection and the tool call ABI | [`cmd/gibson-runner/main.go`](../cmd/gibson-runner/main.go) |
| Declared secret lookup | [`internal/registry/declared_secret.go`](../internal/registry/declared_secret.go) |
| Readiness probe | [`internal/probes/daemon.go`](../internal/probes/daemon.go) |
| Build guard against legacy auth | [`scripts/check-no-legacy-auth.sh`](../scripts/check-no-legacy-auth.sh) |

## Legacy credentials

The legacy auth stack that the rest of the org deleted is not in this repository:

| Removed | Why |
|---|---|
| `gsk_` API keys | The runner holds no credential. |
| BetterAuth tokens | Audit C13. |
| HMAC identity header construction (`x-gibson-identity-mac`) | The runner sends no identity. |
| `TrustLocalhost` interceptor option | The runner has no interceptor. |

`scripts/check-no-legacy-auth.sh` searches for each legacy pattern and
fails CI on a match.

## When the runner must call the daemon

The runner has no code path that calls a daemon RPC. If a change needs one,
it is a new design. It needs an identity for the runner, which a microVM
guest does not have today. Write an ADR in `docs/adr/` first. Do not add a
client in this repository without one.

## Cross-links

- Security model and the argument policy: [`SECURITY.md`](../SECURITY.md).
- Wrong and right code shapes: [`forbidden-patterns.md`](./forbidden-patterns.md).
- Machine-readable rules: [`rules.yaml`](./rules.yaml).
- Daemon side: [`gibson` `docs/auth.md`](https://github.com/zeroroot-ai/gibson/blob/main/docs/auth.md).
