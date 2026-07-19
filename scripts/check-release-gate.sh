#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORKFLOW="$ROOT/.github/workflows/release.yml"
TEST_WORKFLOW="$ROOT/.github/workflows/test-go.yaml"
MAKEFILE="$ROOT/Makefile"
PROCESS="$ROOT/RELEASE-PROCESS.md"

fail() {
    echo "error: $*" >&2
    exit 1
}

[ -f "$WORKFLOW" ] || fail "release workflow missing"
[ -f "$TEST_WORKFLOW" ] || fail "test workflow missing"
[ -f "$PROCESS" ] || fail "release process documentation missing"

grep -q 'Validate release notes' "$WORKFLOW" || fail "tag releases must validate authored release notes"
grep -Fq 'check-release-notes.sh "release-notes/$GITHUB_REF_NAME.md"' "$WORKFLOW" || fail "tag releases must validate notes matching the tag"
grep -Fq -- '--release-notes release-notes/${{ github.ref_name }}.md' "$WORKFLOW" || fail "GoReleaser must use authored release notes"
grep -q 'check-release-notes-test.sh' "$MAKEFILE" || fail "make check must test the release notes validator"
grep -q 'check-release-gate.sh' "$MAKEFILE" || fail "make check must test the release gate"
grep -q 'scripts/\*\*' "$TEST_WORKFLOW" || fail "script changes must trigger CI"
grep -q 'release-notes/<tag>.md' "$PROCESS" || fail "release process must document authored notes"

validate_line=$(grep -n 'Validate release notes' "$WORKFLOW" | head -n 1 | cut -d: -f1)
publish_line=$(grep -n 'Run GoReleaser' "$WORKFLOW" | head -n 1 | cut -d: -f1)
[ -n "$publish_line" ] || fail "GoReleaser publication step missing"
[ "$validate_line" -lt "$publish_line" ] || fail "release notes must be validated before publication"

echo "release gate checks passed"
