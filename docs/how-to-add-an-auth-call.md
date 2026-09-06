# how-to-add-an-auth-call.md — `zeroroot-ai/gibson-executor`

The tool runner does not own RPCs — it consumes
`gibson.component.v1.ComponentService` from the daemon. "Adding an
auth-touching code path" from this repo's perspective means **adding a
new place that needs the authenticated `*daemonclient.Client`**.

Worked example: **"add a `--diagnose` flag that calls
`ComponentService.GetCatalog` once at startup before the poll loop
begins."**

Spec: `unified-identity-and-authorization`. Read [`auth.md`](./auth.md)
first if you have not.

## Step 1 — Use the existing client

`auth.ConnectDaemon(ctx)` already returns an authenticated client. Reuse
it; do not stand up a second one.

```go
// cmd/gibson-runner/main.go

func main() {
    ctx := context.Background()
    client, err := auth.ConnectDaemon(ctx)
    if err != nil { log.Fatal(err) }
    defer client.Close()

    if *diagnose {
        if err := runDiagnose(ctx, client); err != nil { log.Fatal(err) }
    }
    poller.Run(ctx, client)
}

func runDiagnose(ctx context.Context, c *daemonclient.Client) error {
    catalog, err := c.ComponentService().GetCatalog(ctx, &componentpb.GetCatalogRequest{})
    if err != nil { return err }
    fmt.Printf("catalog: %d entries\n", len(catalog.Components))
    return nil
}
```

The Bearer token is attached automatically by the client's interceptor;
SPIFFE mTLS is composed automatically when the Workload API socket is
present.

## Step 2 — If you need a different identity

You don't. The tool runner has **one Zitadel service account per
deployment**. New code paths run under the same identity.

If you genuinely need a second identity (e.g. a fan-out tool that acts
on behalf of multiple tenants), that is **mission orchestration** and
belongs in the daemon's mission DAG with capability-grant JWTs minted
per task. The tool runner does not mint or hold per-task identities.

## Step 3 — If you need a fresh JWT

You don't. The OIDC token source caches the JWT and refreshes it
before expiry transparently. Forcing a new token by calling
`http.PostForm("…/oauth/v2/token", …)` directly is the anti-pattern
caught by rule `tool-runner-auth-004`.

If you observe a 401 on a long-running call, raise it as a daemon-side
or Envoy-side issue — token refresh on the client side is automatic
and well-tested.

## Step 4 — If the new code path produces a `DiscoveryResult`

Reserved-field-100 results (`gibson.graphrag.v1.DiscoveryResult`) flow
through the existing `SubmitResult` path — the daemon stamps tenant
from the verified identity headers ext-authz emitted, never from the
result body.

Don't add a `tenant_id` field to your tool's request; the daemon would
ignore it and the audit trail would be misleading.

## Step 5 — Run the build guards

```
make check                              # gofmt + vet + lint + test-race
./scripts/check-no-legacy-auth.sh       # legacy pattern grep
```

If `check-no-legacy-auth.sh` fires on something legitimate (e.g. a doc
that *describes* the deletion), use the documented exempt list — don't
relax the regex.

## Step 6 — Update the chart if env shape changes

If you add a new env var the tool runner reads (rare — the existing
three env vars cover the auth surface), the Helm chart needs a
matching env entry. That edit lives in `enterprise/deploy/` — see the
deploy repo's `how-to-add-an-auth-call.md`.

## Step 7 — End-to-end smoke test

```
make test                  # unit
make integration           # against a Kind cluster
```

For deployments tied to the daemon, verify the `Ping` round-trip from
inside a smoke pod that mimics the tool runner's pod template (mounts
the same Secret, uses the same SPIFFE socket).
