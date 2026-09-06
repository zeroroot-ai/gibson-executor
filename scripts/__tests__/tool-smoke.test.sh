#!/usr/bin/env bash
# Failing fixtures for scripts/tool-smoke.sh (gibson-executor#398). A smoke
# that cannot fail is worse than no smoke, so this proves the two ways it
# must fail, against derived images built from the image under test:
#
#   1. A tool binary is missing from the image -> the run fails and names
#      that tool. This is the image-drift class the smoke exists to catch.
#   2. The catalog advertises a tool that has no smoke case -> the run
#      fails before any tool executes. This is what makes "adding a tool =
#      one case" enforceable.
#
# Usage: scripts/__tests__/tool-smoke.test.sh <image-ref>
set -uo pipefail

IMAGE="${1:?usage: tool-smoke.test.sh <image-ref>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMOKE="$HERE/../tool-smoke.sh"
rc=0

# --- fixture 1: httpx removed from the image ------------------------------
BROKEN="gibson-executor-smoke-fixture-nohttpx:$$"
docker build -q -t "$BROKEN" - <<EOF >/dev/null
FROM $IMAGE
USER root
RUN rm -f /usr/local/bin/httpx
USER runner:runner
EOF
out=$(bash "$SMOKE" "$BROKEN" httpx 2>&1)
code=$?
if [ "$code" -eq 0 ]; then
  echo "FAIL fixture 1: smoke passed against an image with httpx removed"
  rc=1
elif ! grep -q '^FAIL httpx:' <<<"$out"; then
  echo "FAIL fixture 1: smoke failed but did not name httpx. Output:"
  echo "$out"
  rc=1
else
  echo "ok   fixture 1: missing tool binary fails the run and names httpx"
fi
docker rmi -f "$BROKEN" >/dev/null 2>&1 || true

# --- fixture 2: a catalogued tool with no smoke case ----------------------
# Wrap the runner so --list-tools advertises one extra parser. Every other
# invocation passes through unchanged.
EXTRA="gibson-executor-smoke-fixture-extratool:$$"
docker build -q -t "$EXTRA" --build-arg BASE="$IMAGE" - <<'EOF' >/dev/null
ARG BASE
FROM ${BASE}
USER root
RUN mv /usr/local/bin/gibson-runner /usr/local/bin/gibson-runner.real && \
    printf '%s\n' '#!/bin/sh' \
      'if [ "$1" = "--list-tools" ]; then' \
      '  /usr/local/bin/gibson-runner.real --list-tools | sed "s/^\\[/[{\"name\":\"phantomtool\"},/"' \
      'else' \
      '  exec /usr/local/bin/gibson-runner.real "$@"' \
      'fi' > /usr/local/bin/gibson-runner && chmod 0755 /usr/local/bin/gibson-runner
USER runner:runner
EOF
out=$(bash "$SMOKE" "$EXTRA" nmap 2>&1)
code=$?
if [ "$code" -eq 0 ]; then
  echo "FAIL fixture 2: smoke passed with a catalogued tool that has no case"
  rc=1
elif ! grep -q 'no smoke case: phantomtool' <<<"$out"; then
  echo "FAIL fixture 2: smoke failed but not on the missing case. Output:"
  echo "$out"
  rc=1
else
  echo "ok   fixture 2: a catalogued tool without a case fails the run before any tool runs"
fi
docker rmi -f "$EXTRA" >/dev/null 2>&1 || true

# --- fixture 3: a malformed case ------------------------------------------
# The first CI run of this smoke failed all seven cases at once because the
# field separator was `|`, which is also jq's pipe: `.ports | length` split
# down the middle and `length` reached the docker-run argv as the image
# name. The separator is `::` now, and section 1 of the smoke rejects a case
# whose `extra` field does not look like flags. This fixture proves that
# check fires, by feeding the smoke a copy of itself carrying one case with
# the old collision. It needs no image and no daemon: the check runs before
# docker is touched.
BADSMOKE="$(mktemp -t tool-smoke-badcase-XXXXXX.sh)"
python3 - "$SMOKE" "$BADSMOKE" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()
# One case whose `extra` field is the tail of a jq pipe — the exact shape
# the `|` separator used to produce.
bad = """CASES=(
  'nmap::{"target":"@IP@"}::.ports ::length'
"""
text = text.replace("CASES=(\n", bad, 1)
open(dst, "w").write(text)
PY
out=$(bash "$BADSMOKE" "$IMAGE" nmap 2>&1)
code=$?
if [ "$code" -eq 0 ]; then
  echo "FAIL fixture 3: smoke passed with a malformed case"
  rc=1
elif ! grep -q "extra docker args must start with a flag" <<<"$out"; then
  echo "FAIL fixture 3: smoke failed but not on the malformed case. Output:"
  echo "$out"
  rc=1
else
  echo "ok   fixture 3: a case whose separator collides with its jq pipe is rejected before any tool runs"
fi
rm -f "$BADSMOKE"

exit "$rc"
