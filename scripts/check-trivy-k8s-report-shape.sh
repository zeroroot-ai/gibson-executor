#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zero Root AI
#
# Fail when the trivy k8s report shape that parsers/trivyk8s reads no longer
# matches the shape the PINNED trivy declares.
#
# Why this exists. parsers/trivyk8s reads `trivy k8s --format json`, whose
# wrapper is trivy's own pkg/k8s/report.Report. Its golden fixture's
# misconfiguration rows are a real recording, but the cluster wrapper around
# them is assembled, because no cluster is reachable from a PR runner
# (gibson#485). An assembled wrapper can go stale silently: a trivy bump that
# renames a field leaves the fixture passing and the real tool returning an
# empty, clean-looking result.
#
# So the field names are read out of the pinned module's own source and
# compared to what the parser reads and what the fixture carries. This is
# cheaper than compiling trivy into the parser's module, which is a dependency
# boundary this repo keeps on purpose (see tools/trivy/tools.go).
#
# Run: make check-trivy-k8s-shape
#      bash scripts/check-trivy-k8s-report-shape.sh --selftest
set -euo pipefail

cd "$(dirname "$0")/.."

# FIXTURE is overridable so the selftest can point every rule at a throwaway
# copy. It used to mutate the real file and restore it afterwards, and that lost
# a field for good: fail() exits rather than returns, so the first failing run
# died before its restore, and the next run then "passed" against the already
# broken fixture. A guard whose selftest can damage what it guards is worse than
# no selftest.
FIXTURE=${FIXTURE:-parsers/trivyk8s/testdata/k8s-report.json}
PARSER=parsers/trivyk8s/trivyk8s.go

# The fields the parser reads from the wrapper. Each must be a field of the
# matching struct in the pinned trivy.
REPORT_FIELDS=(ClusterName Resources)
RESOURCE_FIELDS=(Namespace Kind Name Error Results)

fail() { printf '%s %s\n' "❌" "$*" >&2; exit 1; }
ok() { printf '%s %s\n' "✅" "$*"; }

# resolve_report_source prints the path to the pinned trivy's k8s report source.
resolve_report_source() {
  local dir
  dir="$(cd tools/trivy && go list -m -f '{{.Dir}}' github.com/aquasecurity/trivy 2>/dev/null)" || return 1
  [ -n "$dir" ] || return 1
  printf '%s\n' "$dir/pkg/k8s/report/report.go"
}

# struct_fields prints the field names of one struct in a Go source file.
struct_fields() {
  local src="$1" name="$2"
  awk -v want="type $name struct {" '
    index($0, want) == 1 { inside = 1; next }
    inside && /^}/ { exit }
    inside {
      # A field line starts with a capitalised identifier. Skip comments,
      # blank lines and unexported fields.
      if ($1 ~ /^[A-Z][A-Za-z0-9_]*$/) print $1
    }
  ' "$src"
}

check_shape() {
  local src
  if ! src="$(resolve_report_source)"; then
    fail "could not resolve the pinned trivy module. Run 'cd tools/trivy && go mod download'."
  fi
  [ -f "$src" ] || fail "the pinned trivy has no $src: the k8s report moved."

  local declared missing=()
  declared="$(struct_fields "$src" Report)"
  [ -n "$declared" ] || fail "read no fields from 'type Report struct' in $src"
  for f in "${REPORT_FIELDS[@]}"; do
    grep -qx "$f" <<<"$declared" || missing+=("Report.$f")
  done

  declared="$(struct_fields "$src" Resource)"
  [ -n "$declared" ] || fail "read no fields from 'type Resource struct' in $src"
  for f in "${RESOURCE_FIELDS[@]}"; do
    grep -qx "$f" <<<"$declared" || missing+=("Resource.$f")
  done

  if [ ${#missing[@]} -gt 0 ]; then
    fail "the pinned trivy no longer declares: ${missing[*]}
parsers/trivyk8s reads these names and its fixture carries them, so a real run
would return an empty, clean-looking result. Re-read pkg/k8s/report/report.go at
the new version, fix the parser and re-record the fixture."
  fi
  ok "the pinned trivy declares every field parsers/trivyk8s reads"
}

check_fixture() {
  [ -f "$FIXTURE" ] || fail "$FIXTURE is missing"
  # Every wrapper field the parser reads must appear in the fixture, so the
  # fixture exercises the path rather than defaulting through it.
  local f
  for f in "${REPORT_FIELDS[@]}" "${RESOURCE_FIELDS[@]}"; do
    grep -q "\"$f\"" "$FIXTURE" || fail "$FIXTURE never sets \"$f\", so that field is untested"
  done
  # And the parser must actually name them, so this list cannot drift from it.
  for f in "${REPORT_FIELDS[@]}" "${RESOURCE_FIELDS[@]}"; do
    grep -q "json:\"$f\"" "$PARSER" || fail "$PARSER does not read \"$f\", so this guard's list is stale"
  done
  ok "the fixture and the parser agree on every wrapper field"
}

selftest() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # 1. A struct that lost a field must fail.
  cat > "$tmp/report.go" <<'EOF'
type Report struct {
	SchemaVersion int
	Resources     []Resource
}

type Resource struct {
	Namespace string
	Kind      string
	Name      string
	Error     string
	Results   types.Results
}
EOF
  local got
  got="$(struct_fields "$tmp/report.go" Report)"
  grep -qx ClusterName <<<"$got" && { echo "SELFTEST FAIL: ClusterName was read from a struct that has none"; return 1; }
  grep -qx Resources <<<"$got" || { echo "SELFTEST FAIL: Resources was not read"; return 1; }
  echo "selftest 1 ok: a missing field is not reported as present"

  # 2. Every field of the real shape must be read.
  cat > "$tmp/full.go" <<'EOF'
type Report struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Resources     []Resource `json:",omitempty"`
	BOM           *core.BOM  `json:"-"`
	name          string
}
EOF
  got="$(struct_fields "$tmp/full.go" Report)"
  for f in ClusterName Resources SchemaVersion BOM; do
    grep -qx "$f" <<<"$got" || { echo "SELFTEST FAIL: $f was not read"; return 1; }
  done
  grep -qx name <<<"$got" && { echo "SELFTEST FAIL: the unexported field 'name' was read"; return 1; }
  echo "selftest 2 ok: exported fields are read and unexported ones are not"

  # 3. A fixture missing a wrapper field must fail. The real fixture is copied
  # and the COPY is damaged. The original is never written to.
  cp "$FIXTURE" "$tmp/fixture.json"
  python3 - "$tmp/fixture.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d.pop("ClusterName", None)
json.dump(d, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
  local rc=0
  # A subshell, because fail() exits rather than returns: calling check_fixture
  # directly would terminate the selftest instead of recording its failure.
  ( FIXTURE="$tmp/fixture.json" check_fixture ) >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 0 ] || { echo "SELFTEST FAIL: a fixture with no ClusterName passed"; return 1; }
  echo "selftest 3 ok: a fixture missing a wrapper field fails"

  # 4. And rule 3 must not have damaged the real fixture.
  ( check_fixture ) >/dev/null 2>&1 || {
    echo "SELFTEST FAIL: the selftest damaged $FIXTURE"; return 1; }
  echo "selftest 4 ok: the real fixture is untouched"

  echo "SELFTEST PASSED"
}

case "${1:-}" in
  --selftest) selftest ;;
  "") check_shape; check_fixture ;;
  *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
