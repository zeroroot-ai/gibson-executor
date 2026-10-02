# testdata provenance

## k8s-report.json

The misconfiguration rows are **real trivy output**, not written by hand.

Recorded on 2026-10-02 with the version this image pins, `TRIVY_VERSION=0.75.0`
in `Dockerfile` and `github.com/aquasecurity/trivy v0.75.0` in
`tools/trivy/go.mod`:

```
docker run --rm -v "$PWD:/work:ro" \
  aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa \
  config /work/bad.yaml --format json
```

`bad.yaml` is a Deployment that sets `hostPID`, `hostNetwork`, `hostIPC`,
`privileged`, `runAsUser: 0`, `allowPrivilegeEscalation`, adds `SYS_ADMIN` and
`NET_RAW`, mounts `hostPath: /`, and uses `nginx:latest`. The run produced 26
`FAIL` rows: 9 `HIGH`, 6 `MEDIUM`, 11 `LOW`. Every `ID`, `Severity`, `Title`,
`Message`, `Resolution`, `Description` and `PrimaryURL` in this fixture is
copied from that output unchanged. `CauseMetadata.Code` was dropped, because it
is the manifest source listing and the parser does not read it.

## What was assembled, and why

`trivy config` reports a file. `trivy k8s` reports a cluster, and wraps the
same `Misconfigurations` in a `Resources` list. The wrapper here is assembled,
because no cluster is reachable from this workstation or from a PR runner:
there is no local kind cluster by owner decision, and the staging cluster needs
a credential delivered to a TOOL node, which is gibson#485.

The wrapper is **not guessed**. Its field names are read from the pinned
dependency's own struct, `pkg/k8s/report/report.go` at v0.75.0:

```go
type Report struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Resources     []Resource `json:",omitempty"`
}

type Resource struct {
	Namespace string `json:",omitempty"`
	Kind      string
	Name      string
	Metadata  []types.Metadata `json:",omitempty"`
	Results   types.Results    `json:",omitempty"`
	Error     string           `json:",omitempty"`
}
```

`scripts/check-trivy-k8s-report-shape.sh` reads those field names out of the
pinned module's source and fails when the parser or this fixture names one trivy
no longer declares. So a trivy bump that renames a field fails the build, which
a stale recording would not catch. It reads the source rather than compiling
trivy into the parser's module, because that dependency boundary is deliberate
(`tools/trivy/tools.go`). Run it with `make check-trivy-k8s-shape`, and
`--selftest` proves all three of its rules can fail.

## What the fixture holds

| Resource | Why it is there |
|---|---|
| `goat/Deployment/goat-api` | 12 `FAIL` (8 `HIGH`, 4 `MEDIUM`) and one `PASS` |
| `goat/Deployment/goat-worker` | 4 `FAIL`, all `LOW`, so severity is per check and not per run |
| `kube-system/Role/extension-apiserver-authentication-reader` | a resource-level `Error`: RBAC forbade it. It must count as unread, never as clean |
| `goat/ConfigMap/goat-config` | read, no checks at all: audited and clean |

The `PASS` row is the recorded shape of a `FAIL` row with `Status` flipped,
because the recording above has no passing row: `trivy config` omits them
unless `--include-non-failures` is set, which the tool does pass.
