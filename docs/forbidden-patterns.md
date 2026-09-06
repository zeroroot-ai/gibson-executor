# forbidden-patterns.md — `zeroroot-ai/gibson-executor`

Companion to [`rules.yaml`](./rules.yaml). Wrong vs right code shapes
for the tool runner. Spec: `unified-identity-and-authorization`.

## TOOL-RUNNER-AUTH-001: legacy auth references

Wrong:

```go
// internal/auth/legacy.go (deleted)
const apiKeyEnv = "GSK_API_KEY"   // forbidden — deleted system

func bearerFromEnv() string {
    return "gsk_" + os.Getenv(apiKeyEnv)
}
```

Right ([`internal/auth/auth.go`](../internal/auth/auth.go)):

```go
const (
    EnvClientID      = "ZITADEL_TOOL_RUNNER_CLIENT_ID"
    EnvClientSecret  = "ZITADEL_TOOL_RUNNER_CLIENT_SECRET"
    EnvZitadelIssuer = "ZITADEL_ISSUER"
)

func ConnectDaemon(ctx context.Context) (*daemonclient.Client, error) {
    if err := setOIDCEnvVars(); err != nil { return nil, err }
    return daemonclient.New(ctx, daemonclient.GetDaemonAddress())
}
```

`scripts/check-no-legacy-auth.sh` greps every Go / MD / YAML file for
`gsk_`, `GSK_API_KEY`, `HMAC`, `x-gibson-identity-mac`, `BetterAuth`,
`better-auth`, `BETTER_AUTH`, `TrustLocalhost` and fails CI on any hit.

## TOOL-RUNNER-AUTH-002: logging the client_secret

Wrong:

```go
secret := os.Getenv("ZITADEL_TOOL_RUNNER_CLIENT_SECRET")
slog.Info("authenticated", "client_id", clientID, "secret", secret) // forbidden
fmt.Printf("DEBUG: secret=%s\n", secret)                            // forbidden
```

Right — the secret enters via env, lands in the OIDC client config,
and never appears in any log:

```go
slog.Info("tool runner authenticated", "client_id", clientID,
    "issuer", issuer, "daemon_addr", addr)
```

Even `slog.Debug` is unsafe — DEBUG output ships to log pipelines in
many production deployments.

## TOOL-RUNNER-AUTH-003: importing the daemon module

Wrong:

```go
// internal/poller/loop.go
import "github.com/zeroroot-ai/gibson/internal/component"   // forbidden
```

Right — proto types come from the SDK:

```go
import componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
```

If a type genuinely lives only in the daemon, it belongs in the SDK
instead. Open a PR against `zeroroot-ai/sdk`, tag a release, bump this
module's pin.

## TOOL-RUNNER-AUTH-004: bypassing `auth.ConnectDaemon`

Wrong (replicates the wiring inline, splitting credential handling):

```go
// cmd/gibson-runner/main.go
import oauth2cc "golang.org/x/oauth2/clientcredentials"

func main() {
    cfg := oauth2cc.Config{
        ClientID:     os.Getenv("ZITADEL_TOOL_RUNNER_CLIENT_ID"),
        ClientSecret: os.Getenv("ZITADEL_TOOL_RUNNER_CLIENT_SECRET"),
        TokenURL:     os.Getenv("ZITADEL_ISSUER") + "/oauth/v2/token",   // forbidden — duplicate plumbing
    }
    src := cfg.TokenSource(ctx)
    // ... manual gRPC dial ...
}
```

Right ([`internal/auth/auth.go:58`](../internal/auth/auth.go)):

```go
func main() {
    ctx := context.Background()
    client, err := auth.ConnectDaemon(ctx)
    if err != nil { log.Fatal(err) }
    defer client.Close()
    // ... use client ...
}
```

`auth.ConnectDaemon` translates the tool-runner-specific env vars into
the SDK's generic OIDC env vars and delegates to `daemonclient.New`.
One call site, one place to audit.

## TOOL-RUNNER-AUTH-005: direct go-spiffe usage

Wrong (would create a second SPIFFE detection path that can drift from
the SDK's contract):

```go
import "github.com/spiffe/go-spiffe/v2/workloadapi"   // forbidden

src, _ := workloadapi.NewX509Source(ctx,
    workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock")))
tlsCfg := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeAny())
conn, _ := grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
```

Right — the SDK's `daemonclient.New` (and future `agent.Connect`)
auto-detect SPIFFE and compose the right DialOption. Use it:

```go
client, err := daemonclient.New(ctx, daemonclient.GetDaemonAddress())
// SPIFFE detection happens inside; the tool runner never imports
// go-spiffe directly.
```

Subject identity is **always** Zitadel here, regardless of whether the
transport is X509-SVID-mTLS (in-cluster) or server-side TLS (external).
Don't conflate the two.
