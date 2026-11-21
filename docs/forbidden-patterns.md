# forbidden-patterns.md: `zeroroot-ai/gibson-executor`

Companion to [`rules.yaml`](./rules.yaml). This page shows wrong and right
code shapes for the tool runner. Read [`auth.md`](./auth.md) first: the
runner holds no identity and no credential of its own.

## TOOL-RUNNER-AUTH-001: legacy auth references

Wrong:

```go
// internal/auth/legacy.go (deleted)
const apiKeyEnv = "GSK_API_KEY"   // forbidden: deleted system

func bearerFromEnv() string {
    return "gsk_" + os.Getenv(apiKeyEnv)
}
```

Right: the runner sends no credential to the daemon. The daemon starts the
runner in a Setec microVM and reads the response from stdout, so there is no
token to build.

`scripts/check-no-legacy-auth.sh` searches every Go, Markdown and YAML file
for `gsk_`, `GSK_API_KEY`, `HMAC`, `x-gibson-identity-mac`, `BetterAuth`,
`better-auth`, `BETTER_AUTH` and `TrustLocalhost`. It fails CI on a match.

## TOOL-RUNNER-AUTH-002: a declared secret in the input or a log

Wrong:

```go
// A credential VALUE read from the tool input. The daemon stores the
// input with the tool call, so the value is stored and displayed.
kubeconfig := req.Options["kubeconfig"]                     // forbidden

value, _ := registry.DeclaredSecret(req, "kubeconfigSecret")
slog.Info("got kubeconfig", "value", value)                 // forbidden
```

Right: the input carries only the secret name. The value comes from the
environment, and only the name goes to a log:

```go
kubeconfig, err := registry.DeclaredSecret(req, kubeconfigOption)
if err != nil {
    return nil, err
}
```

`registry.DeclaredSecret` reads the value with the sdk `secretenv.Lookup`.
It never falls back to the input or to an ambient credential.

## TOOL-RUNNER-AUTH-003: importing the daemon module

Wrong:

```go
// internal/poller/loop.go
import "github.com/zeroroot-ai/gibson/internal/component"   // forbidden
```

Right: proto types come from the SDK:

```go
import componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
```

If a type lives only in the daemon, it belongs in the SDK.
Open a PR against `zeroroot-ai/sdk`. The release then reaches this module
through the automatic version bump.

## TOOL-RUNNER-AUTH-005: direct go-spiffe usage

Wrong:

```go
import "github.com/spiffe/go-spiffe/v2/workloadapi"   // forbidden

src, _ := workloadapi.NewX509Source(ctx,
    workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock")))
```

Right: the runner has no SPIFFE identity and dials no daemon RPC. A microVM
guest gets no ClusterSPIFFEID. If a change needs a runner identity, write an
ADR first, as [`auth.md`](./auth.md) says.
