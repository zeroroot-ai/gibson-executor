#!/usr/bin/env bash
# tool-smoke.sh — prove every catalogued tool runs AND parses inside the built
# image (gibson-executor#398).
#
# `--list-tools` proves the binary advertises a parser. `--verify-tools` proves
# the binary the parser execs is on PATH. Neither proves the tool produces
# output the parser can turn into entities: a flag the tool dropped, a JSON
# shape that moved, a missing capability, a template directory that never
# existed — every one of those is invisible until a real mission runs it.
#
# This script runs each tool through the runner (the same ABI the daemon uses:
# GIBSON_TOOL_NAME + GIBSON_TOOL_INPUT_B64 in, ===GIBSON_TOOL_OUTPUT=== out)
# against a target container the script starts itself, decodes the
# DiscoveryResult, and asserts at least one entity of the type that tool is
# expected to emit. A tool that is missing from the image, crashes, or parses
# to nothing fails the run and is named.
#
# Adding a tool = one line in CASES below. The catalog cross-check at the top
# fails the run when a catalogued tool has no case, so a parser cannot land
# without its smoke.
#
# Usage:
#   scripts/tool-smoke.sh <image-ref> [tool ...]
#
# Optional args restrict the run to the named tools (the catalog cross-check
# still runs against the full list). Needs docker with a bridge network. The
# masscan case needs CAP_NET_RAW/CAP_NET_ADMIN: masscan speaks raw packets and
# has no connect-scan fallback, and it does not work over loopback (no ARP on
# lo), which is why the target is a container on a bridge network rather than
# a listener on 127.0.0.1.
#
# Exit 0 = every case passed. Exit 1 = at least one failed (each named).
set -uo pipefail

IMAGE="${1:?usage: tool-smoke.sh <image-ref> [tool ...]}"
shift
ONLY=("$@")

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_ID="$$"
NET="gibson-tool-smoke-${RUN_ID}"
TARGET="gibson-tool-smoke-target-${RUN_ID}"
TARGET_ALIAS="target.smoke.internal"
TARGET_PORT="8080"
# Docker's embedded DNS on a user-defined network. dnsx queries public
# resolvers by default, so the alias above only resolves when the case
# names this resolver explicitly (policy `-r`, added with #398).
DOCKER_DNS="127.0.0.11"
# python:3.12-alpine is digest-pinned like every image in the Dockerfile.
TARGET_IMAGE="python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31"
# subfinder has no local mode: it is a passive enumerator over public
# sources, so its case is the one non-hermetic case here. debian.org is
# stable and answers from several key-less sources.
PUBLIC_DOMAIN="debian.org"
# The host the tlsx case probes. badssl.com exists to serve deliberately
# broken TLS and is the standard fixture for this; expired.badssl.com
# presents a certificate that is expired by construction, so the case
# asserts a finding rather than hoping one exists today. Third and last of
# the non-hermetic cases.
#
# The smoke target container serves plain HTTP, so it cannot stand in here:
# generating a certificate inside it would need a toolchain the pinned
# python image does not carry.
# The image the trivy case scans. Digest-pinned, and deliberately Debian
# oldstable: a scan that finds nothing proves nothing, so the case needs an
# artefact whose packages carry known advisories. It is NOT an end-of-life
# release — alpine:3.14 was tried first and reported zero vulnerabilities,
# because trivy has no advisory data for an EOL distribution and says so
# only in a log line. Debian oldstable is still tracked and reliably
# carries unfixed CVEs. trivy downloads its vulnerability database on first
# run, which makes this the second non-hermetic case after subfinder.
TLS_HOST="expired.badssl.com"
SCAN_IMAGE="debian:11-slim@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd"
TIMEOUT_MS=180000

# One line per tool, four `::`-separated fields:
#   name :: input_json template :: jq count expression :: extra docker-run args
#
# The separator is `::` and not `|` because every count expression is a jq
# pipe: a `|` separator splits `.ports | length` down the middle, and the
# tail lands in the docker-run args, where `length` is read as the image
# name. That is not hypothetical — it is what the first CI run of this
# script did, failing all seven cases with `invalid reference format` and
# `pull access denied for length`. jq has no `::` operator, so the fields
# cannot collide with the expressions again.
#
# Placeholders @IP@ @ALIAS@ @PORT@ @DNS@ @DOMAIN@ @SCANIMAGE@ @TLSHOST@
# @HERE@ are
# substituted before the run.
CASES=(
  'nmap::{"target":"@IP@","ports":"@PORT@","args":["-sT","-Pn","-n"]}::[.ports[]? | select(.state=="open")] | length::'
  'naabu::{"target":"@IP@","ports":"@PORT@","args":["-s","c"]}::.ports | length::'
  'masscan::{"target":"@IP@","ports":"@PORT@","rate":"100"}::.ports | length::--cap-add NET_RAW --cap-add NET_ADMIN --user 0:0'
  'httpx::{"target":"http://@ALIAS@:@PORT@"}::[(.endpoints|length),(.findings|length)] | min::'
  'nuclei::{"target":"http://@ALIAS@:@PORT@","templates":"smoke/http-title.yaml"}::.findings | length::-v @HERE@/tool-smoke/nuclei:/home/runner/smoke:ro'
  'subfinder::{"target":"@DOMAIN@"}::.subdomains | length::'
  'dnsx::{"target":"@ALIAS@","args":["-r","@DNS@"]}::.hosts | length::'
  'tlsx::{"target":"@TLSHOST@"}::.findings | length::'
  'trivy::{"target":"@SCANIMAGE@"}::[.custom_nodes[]? | select(.node_type=="Package")] | length::'
)

# split_case populates the globals CASE_NAME/CASE_INPUT/CASE_EXPR/CASE_EXTRA
# from one CASES entry. Written as prefix/suffix trims rather than
# `IFS=… read` so a multi-character separator works.
split_case() {
  local rest="$1"
  CASE_NAME=${rest%%::*}; rest=${rest#*::}
  CASE_INPUT=${rest%%::*}; rest=${rest#*::}
  CASE_EXPR=${rest%%::*}
  CASE_EXTRA=${rest#*::}
}

log() { printf '%s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; }

cleanup() {
  docker rm -f "$TARGET" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

started=$(date +%s)

rc=0

# --- 1. case table is well-formed ---------------------------------------
# Every case must parse into four fields, and `extra` — which is word-split
# into the docker-run argv — must hold flags or nothing. A case whose
# separator collides with its own jq pipe leaks the tail of the expression
# into that argv, where it is read as the image name. This check names that
# as a malformed case, at once and before docker is touched, instead of as
# seven mystery tool failures.
for c in "${CASES[@]}"; do
  split_case "$c"
  if [ -z "$CASE_NAME" ] || [ -z "$CASE_INPUT" ] || [ -z "$CASE_EXPR" ]; then
    fail "case '${c}': does not parse into name::input::expr::extra"
    rc=1
  elif [ -n "$CASE_EXTRA" ] && [ "${CASE_EXTRA#-}" = "$CASE_EXTRA" ]; then
    fail "case '${CASE_NAME}': extra docker args must start with a flag, got '${CASE_EXTRA}'"
    rc=1
  fi
done
if [ "$rc" -ne 0 ]; then
  exit 1
fi

# --- 2. catalog cross-check: every catalogued tool has a case, every case
#        names a catalogued tool. ---------------------------------------
catalog=$(docker run --rm "$IMAGE" --list-tools 2>/dev/null | jq -r '.[].name' | sort)
if [ -z "$catalog" ]; then
  fail "catalog: \`$IMAGE --list-tools\` produced no tools"
  exit 1
fi
case_names=$(printf '%s\n' "${CASES[@]}" | sed 's/::.*//' | sort)
missing_cases=$(comm -23 <(printf '%s\n' "$catalog") <(printf '%s\n' "$case_names"))
unknown_cases=$(comm -13 <(printf '%s\n' "$catalog") <(printf '%s\n' "$case_names"))
if [ -n "$missing_cases" ]; then
  fail "catalog: tool(s) advertised by --list-tools with no smoke case: $(tr '\n' ' ' <<<"$missing_cases")"
  rc=1
fi
if [ -n "$unknown_cases" ]; then
  fail "catalog: smoke case(s) for tool(s) not in --list-tools: $(tr '\n' ' ' <<<"$unknown_cases")"
  rc=1
fi
if [ "$rc" -ne 0 ]; then
  exit 1
fi
log "catalog: $(tr '\n' ' ' <<<"$catalog")"

# --- 3. the target ------------------------------------------------------
docker network create "$NET" >/dev/null
docker run -d --name "$TARGET" --network "$NET" --network-alias "$TARGET_ALIAS" \
  "$TARGET_IMAGE" sh -c '
    mkdir -p /srv &&
    printf "<html><head><title>Gibson smoke target</title></head><body>ok</body></html>" > /srv/index.html &&
    cd /srv && exec python3 -m http.server '"$TARGET_PORT" >/dev/null
TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")
for _ in $(seq 1 30); do
  if docker exec "$TARGET" python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${TARGET_PORT}/').read()" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
log "target: ${TARGET_ALIAS} (${TARGET_IP}:${TARGET_PORT})"

# --- 4. one run per case --------------------------------------------------
run_case() {
  local name="$1" input="$2" expr="$3" extra="$4"
  input=${input//@IP@/$TARGET_IP}
  input=${input//@ALIAS@/$TARGET_ALIAS}
  input=${input//@PORT@/$TARGET_PORT}
  input=${input//@DNS@/$DOCKER_DNS}
  input=${input//@DOMAIN@/$PUBLIC_DOMAIN}
  input=${input//@SCANIMAGE@/$SCAN_IMAGE}
  input=${input//@TLSHOST@/$TLS_HOST}
  extra=${extra//@HERE@/$HERE}

  local req b64 out code line resp err disc count
  req=$(jq -cn --arg t "$name" --arg i "$input" --argjson ms "$TIMEOUT_MS" \
    '{tool_name:$t,input_json:$i,timeout_ms:$ms}')
  b64=$(printf '%s' "$req" | base64 -w0)

  local t0 t1
  t0=$(date +%s)
  # shellcheck disable=SC2086 # extra is a deliberate word-split list of flags
  out=$(docker run --rm --network "$NET" $extra \
    -e GIBSON_TOOL_NAME="$name" -e GIBSON_TOOL_INPUT_B64="$b64" \
    "$IMAGE" 2>"/tmp/tool-smoke-${name}.stderr")
  code=$?
  t1=$(date +%s)

  line=$(grep '^===GIBSON_TOOL_OUTPUT===' <<<"$out" | tail -1)
  if [ -z "$line" ]; then
    fail "$name: exit $code, no ABI output marker. stdout: $(head -c 300 <<<"$out" | tr '\n' ' ') stderr: $(tail -c 400 "/tmp/tool-smoke-${name}.stderr" | tr '\n' ' ')"
    return 1
  fi
  resp=$(base64 -d <<<"${line#===GIBSON_TOOL_OUTPUT===}")
  err=$(jq -r '.error.message // empty' <<<"$resp")
  if [ -n "$err" ]; then
    # The runner's message says the tool failed; the tool's own stderr says
    # why. Reporting only the former turns every tool failure into "exit
    # status 1" and leaves the reason in a discarded buffer.
    fail "$name: exit $code, runner error: $err. stderr: $(tail -c 600 "/tmp/tool-smoke-${name}.stderr" | tr '\n' ' ')"
    return 1
  fi
  disc=$(jq -r '.outputJson // "{}"' <<<"$resp")
  count=$(jq "$expr" <<<"$disc" 2>/dev/null)
  if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 1 ]; then
    fail "$name: exit $code, parsed to no entity for \`$expr\` (got '${count:-none}'). DiscoveryResult keys: $(jq -c 'to_entries | map({(.key): (.value|length)}) | add' <<<"$disc") stderr: $(tail -c 300 "/tmp/tool-smoke-${name}.stderr" | tr '\n' ' ')"
    return 1
  fi
  log "ok   $name: $count entit$( [ "$count" -eq 1 ] && echo y || echo ies) for \`$expr\` in $((t1 - t0))s"
  return 0
}

failed=()
for c in "${CASES[@]}"; do
  split_case "$c"
  if [ ${#ONLY[@]} -gt 0 ]; then
    keep=0
    for o in "${ONLY[@]}"; do [ "$o" = "$CASE_NAME" ] && keep=1; done
    [ "$keep" -eq 1 ] || continue
  fi
  run_case "$CASE_NAME" "$CASE_INPUT" "$CASE_EXPR" "$CASE_EXTRA" || failed+=("$CASE_NAME")
done

elapsed=$(( $(date +%s) - started ))
if [ ${#failed[@]} -gt 0 ]; then
  fail "tool-smoke: ${#failed[@]} tool(s) failed: ${failed[*]} (${elapsed}s)"
  exit 1
fi
log "tool-smoke: every case passed (${elapsed}s)"
