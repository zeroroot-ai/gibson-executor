#!/usr/bin/env bash
# check-no-legacy-auth.sh — build guard that rejects legacy credential patterns.
#
# Searches all Go, Markdown, and YAML files for strings belonging to
# authentication systems that were deleted by spec unified-identity-and-authorization:
#   • gsk_* API keys
#   • GSK_API_KEY env var
#   • HMAC-signed identity headers (x-gibson-identity-mac)
#   • BetterAuth / better-auth / BETTER_AUTH tokens
#   • TrustLocalhost interceptor option
#
# Exit 0 — no hits; the tree is clean.
# Exit 1 — at least one match found; print the offending files.
#
# Usage:
#   scripts/check-no-legacy-auth.sh
#   (Run from the repo root or any subdirectory; uses git top-level.)

set -euo pipefail

PATTERNS=(
    'gsk_'
    'GSK_API_KEY'
    'HMAC'
    'x-gibson-identity-mac'
    'BetterAuth'
    'better-auth'
    'BETTER_AUTH'
    'TrustLocalhost'
)

# Repo-relative paths that document the forbidden patterns themselves and so
# must be excluded from the scan. Without this allowlist the guard trips on
# its own documentation catalog.
IGNORE_PATHS=(
    'docs/forbidden-patterns.md'
    'docs/rules.yaml'
    'docs/auth.md'
)

# Build a single alternation pattern for ripgrep.
PATTERN=$(printf '%s|' "${PATTERNS[@]}")
PATTERN="${PATTERN%|}"  # strip trailing pipe

# Resolve repo root so the script works from any working directory. Callers
# can override REPO_ROOT (e.g. for testing against a fixture directory) by
# exporting it before invocation.
REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"

# Build ripgrep --glob exclusions from IGNORE_PATHS.
RG_EXCLUDES=()
for p in "${IGNORE_PATHS[@]}"; do
    RG_EXCLUDES+=(--glob "!${p}")
done

echo "check-no-legacy-auth: scanning ${REPO_ROOT} for forbidden patterns..."

# Run ripgrep from inside REPO_ROOT so the IGNORE_PATHS globs (which are
# specified repo-relative) anchor correctly.
cd "${REPO_ROOT}"

# Collect matches (rg exits 0 = found, 1 = not found, 2 = error).
if HITS=$(rg -nl --type go --type md --type yaml "${RG_EXCLUDES[@]}" -e "$PATTERN" . 2>&1); then
    echo ""
    echo "ERROR: legacy auth patterns found in the following files:"
    echo "$HITS" | while IFS= read -r f; do
        echo "  $f"
        rg -n -e "$PATTERN" "$f" | sed 's/^/    /'
    done
    echo ""
    echo "Legacy authentication systems (gsk_ keys, HMAC headers, BetterAuth,"
    echo "TrustLocalhost) are deleted by spec unified-identity-and-authorization."
    echo "Remove the matching code before merging."
    exit 1
fi

echo "check-no-legacy-auth: OK — no legacy auth patterns found."
