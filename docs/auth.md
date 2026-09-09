# auth.md — `zeroroot-ai/gibson-executor`

Auth model from the tool runner's perspective. AI-agent-facing.
Spec: `unified-identity-and-authorization` Requirements 12.1–12.3.

## What this is

The tool runner is a stateless service that authenticates to the Gibson
daemon's `gibson.component.v1.ComponentService` to register itself and
poll for work. It is one deployment per cluster (or one container per
host on customer-network installs), with **one Zitadel service account
per deployment**.

The auth model mirrors what an SDK agent does, just for tools instead
of agents. There is no special path for built-in tools.

## Files

| Concern | File |
|---|---|
| Build guard against legacy auth | [`scripts/check-no-legacy-auth.sh`](../scripts/check-no-legacy-auth.sh) |

The auth wiring itself is not a file in this repository. This page records
the model the runner follows. The caller supplies the credentials in the
environment.

## Environment variables

The tool runner takes three required env vars and one optional one:

| Var | Purpose |
|---|---|
| `ZITADEL_TOOL_RUNNER_CLIENT_ID` | Zitadel service-account client_id (Helm Secret `gibson-zitadel-tool-runner`). |
| `ZITADEL_TOOL_RUNNER_CLIENT_SECRET` | Zitadel service-account client_secret. |
| `ZITADEL_ISSUER` | Zitadel base URL, e.g. `https://auth.zeroroot.ai`. Token URL is derived as `<ZITADEL_ISSUER>/oauth/v2/token`. |
| `GIBSON_DAEMON_ADDRESS` | gRPC address of the Envoy front-door. Defaults to `localhost:50002` when running as a sidecar; real deployments set the Envoy public URL. **Note: this env var name is preserved here for historical compatibility with the daemon-client SDK helper; it points to Envoy, not to the daemon directly.** |

`setOIDCEnvVars` translates the
tool-runner-specific env vars into the SDK's generic
`OIDC_CLIENT_CREDENTIALS_*` form so `daemonclient.New` picks them up
via its credential auto-detection. Translation is idempotent — if the
generic vars are already set (e.g. in tests) they are honoured as-is.

## Connection flow

```
ConnectDaemon(ctx)
   |
   | 1. setOIDCEnvVars()
   |     - read ZITADEL_TOOL_RUNNER_CLIENT_ID/SECRET, ZITADEL_ISSUER
   |     - export OIDC_CLIENT_CREDENTIALS_CLIENT_ID/SECRET/TOKEN_URL
   |
   | 2. daemonclient.GetDaemonAddress()
   |     - reads GIBSON_DAEMON_ADDRESS (defaults to localhost:50002)
   |
   | 3. daemonclient.New(ctx, addr)
   |     - exchanges client_credentials for a Zitadel JWT (cached)
   |     - SPIFFE auto-detection via SPIFFE_ENDPOINT_SOCKET:
   |        - present + reachable: mTLS via X509-SVID
   |        - absent: server-side TLS
   |     - returns *daemonclient.Client with refreshing Bearer interceptor
   v
*daemonclient.Client
```

The tool runner's `main` calls `auth.ConnectDaemon(ctx)` once and uses
the returned client for the lifetime of the process. The harness/poll
loop is unaware of any auth concerns.

## SPIFFE auto-detection

When deployed in Kubernetes, the SPIRE Workload API socket is mounted
at `/run/spire/sockets/agent.sock`; the SDK's
[`daemonclient`](https://github.com/zeroroot-ai/sdk/tree/main/daemonclient) detects it
automatically and adds X509-SVID-backed TLS credentials to the dial.
The tool runner code does not reach into SPIFFE APIs directly.

For external (customer-network) deployments without SPIRE, the socket
is absent; the dial falls back to server-side TLS only. The Bearer JWT
auth path is unaffected — TLS is just edge-only instead of mutual.

## What's gone

The same legacy auth stack the rest of the polyrepo deleted is also
gone here:

| Removed | Why |
|---|---|
| `gsk_` API keys | Replaced by Zitadel client_credentials. |
| BetterAuth tokens | Audit C13. |
| HMAC identity header construction (`x-gibson-identity-mac`) | Channel security is SPIFFE mTLS / server-side TLS. |
| `TrustLocalhost` interceptor option | No bypass exists. |

`scripts/check-no-legacy-auth.sh` greps for every legacy pattern and
fails CI on a hit. Keep it green.

## Migration note (SDK >= v0.84.0)

Today the tool runner uses the SDK's `daemonclient.New` directly
because `agent.Connect` (the higher-level ADK entry point) was added
in `v0.84.0` and the tool runner has not yet bumped to consume it.
When the bump lands, the auth wiring shrinks to one call.

For the broader auth architecture (where tokens come from, who validates
them, how SPIFFE is configured cluster-wide), read the SDK's
[`auth.md`](https://github.com/zeroroot-ai/sdk/blob/main/docs/auth.md). The
tool runner is structurally identical. It uses one Zitadel service account per
deployment instead of one per agent.

## Cross-link

- Adding a new auth-touching code path: [`how-to-add-an-auth-call.md`](./how-to-add-an-auth-call.md).
- Wrong vs right code shapes: [`forbidden-patterns.md`](./forbidden-patterns.md).
- Machine-readable rules: [`rules.yaml`](./rules.yaml).
- SDK identity types and the broader auth architecture: [`sdk` `docs/auth.md`](https://github.com/zeroroot-ai/sdk/blob/main/docs/auth.md).
- Daemon-side: [`gibson` `docs/auth.md`](https://github.com/zeroroot-ai/gibson/blob/main/docs/auth.md).
