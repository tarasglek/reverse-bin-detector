#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CHECK="$ROOT/scripts/check-release-notes.sh"
TMPDIR=${TMPDIR:-/tmp}
WORK=$(mktemp -d "$TMPDIR/reverse-bin-detector-release-notes.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

fail() {
    echo "error: $*" >&2
    exit 1
}

expect_pass() {
    name=$1
    file=$2
    if ! "$CHECK" "$file" >"$WORK/out" 2>"$WORK/err"; then
        cat "$WORK/err" >&2
        fail "$name: expected validation to pass"
    fi
}

expect_fail() {
    name=$1
    file=$2
    if "$CHECK" "$file" >"$WORK/out" 2>"$WORK/err"; then
        fail "$name: expected validation to fail"
    fi
}

VALID="$WORK/valid.md"
cat >"$VALID" <<'EOF'
# Reverse Bin Detector v1.2.3

## Highlights

- A useful change.

## Breaking changes

None.

## Full list of changes

- A useful change.
EOF
expect_pass "valid notes" "$VALID"
expect_fail "missing notes" "$WORK/missing.md"

BAD="$WORK/bad.md"
sed '1s/Reverse Bin Detector/Reverse Bin/' "$VALID" >"$BAD"
expect_fail "wrong title" "$BAD"

awk '$0 != "## Breaking changes"' "$VALID" >"$BAD"
expect_fail "missing section" "$BAD"

awk '$0 != "None."' "$VALID" >"$BAD"
expect_fail "empty section" "$BAD"

sed 's/^- A useful change\./A useful change./' "$VALID" >"$BAD"
expect_fail "sections without bullets" "$BAD"

echo "release notes validator tests passed"
