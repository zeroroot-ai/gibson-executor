#!/usr/bin/env bash
# check-no-legacy-auth.test.sh — unit tests for scripts/check-no-legacy-auth.sh.
#
# Tests:
#   1. Positive case: an injected `os.Getenv("GSK_API_KEY")` in
#      `internal/foo/legacy.go` trips the guard (exit 1).
#   2. Negative case: the same literal in `docs/forbidden-patterns.md`
#      (one of the IGNORE_PATHS entries) does NOT trip the guard (exit 0).
#
# The tests build isolated fixture trees in $TMPDIR, point the guard at
# them via the REPO_ROOT override, and assert exit codes. They never mutate
# the real repository.
#
# Usage:
#   scripts/__tests__/check-no-legacy-auth.test.sh
#   (Run from anywhere; resolves paths via this file's location.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD="$(cd "${SCRIPT_DIR}/.." && pwd)/check-no-legacy-auth.sh"

if [[ ! -x "${GUARD}" ]]; then
    echo "FAIL: guard not found or not executable at ${GUARD}" >&2
    exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
    echo "FAIL: ripgrep (rg) is required to run these tests" >&2
    exit 1
fi

PASS=0
FAIL=0

# make_fixture_tree <dest>
#   Initialises <dest> as a minimal git repo so the guard's
#   `git rev-parse --show-toplevel` fallback would succeed (the guard
#   honours REPO_ROOT first, but keeping the fixture a real repo guards
#   against future refactors of the script).
make_fixture_tree() {
    local dest="$1"
    git init -q "${dest}"
    (cd "${dest}" && git config user.email test@example.com && git config user.name test)
}

run_guard() {
    # $1 = REPO_ROOT override
    REPO_ROOT="$1" bash "${GUARD}"
}

assert_exit() {
    # $1 = description, $2 = expected exit, $3 = actual exit
    if [[ "$2" == "$3" ]]; then
        echo "PASS: $1 (exit=$3)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $1 — expected exit $2, got $3"
        FAIL=$((FAIL + 1))
    fi
}

# -----------------------------------------------------------------------------
# Test 1 (positive): a forbidden literal in internal/ trips the guard.
# -----------------------------------------------------------------------------
POS_DIR="$(mktemp -d)"
trap 'rm -rf "${POS_DIR}" "${NEG_DIR:-}"' EXIT
make_fixture_tree "${POS_DIR}"
mkdir -p "${POS_DIR}/internal/foo"
cat > "${POS_DIR}/internal/foo/legacy.go" <<'GO'
package foo

import "os"

var _ = os.Getenv("GSK_API_KEY")
GO

set +e
run_guard "${POS_DIR}" >/dev/null 2>&1
POS_EXIT=$?
set -e
assert_exit "positive: guard trips on internal/foo/legacy.go containing GSK_API_KEY" 1 "${POS_EXIT}"

# -----------------------------------------------------------------------------
# Test 2 (negative): same literal in docs/forbidden-patterns.md is ignored.
# -----------------------------------------------------------------------------
NEG_DIR="$(mktemp -d)"
make_fixture_tree "${NEG_DIR}"
mkdir -p "${NEG_DIR}/docs"
cat > "${NEG_DIR}/docs/forbidden-patterns.md" <<'MD'
# Forbidden patterns

Do not introduce code that reads `os.Getenv("GSK_API_KEY")` — this catalogues
the deleted credential surface and must not itself trip the guard.
MD

set +e
run_guard "${NEG_DIR}" >/dev/null 2>&1
NEG_EXIT=$?
set -e
assert_exit "negative: guard ignores docs/forbidden-patterns.md containing GSK_API_KEY" 0 "${NEG_EXIT}"

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "check-no-legacy-auth.test.sh: ${PASS} passed, ${FAIL} failed"

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
