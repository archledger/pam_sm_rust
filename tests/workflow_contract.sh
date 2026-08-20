#!/usr/bin/env bash
# Static contract for the fork's GitHub Actions.
# Fails unless every workflow satisfies the approved design:
#   - every `uses:` is pinned by full 40-hex commit SHA
#   - every checkout disables persisted credentials
#   - every workflow declares least-privilege permissions (contents: read)
#   - MSRV is exactly Rust 1.88 alongside current stable
#   - the eight required checks exist by name
#   - ASan uses an explicit target and an explicit symbolizer
#   - no workflow publishes to crates.io, creates releases, or grants write-all
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
workflows="$here/.github/workflows"
fail=0

err() { printf 'workflow contract: %s\n' "$1" >&2; fail=1; }

[ -d "$workflows" ] || { err "no .github/workflows directory"; exit 1; }

# 1. Full-SHA action pins.
bad_pins=$(grep -rhoE 'uses: [^ ]+@[^ ]+' "$workflows" | grep -vE '@[0-9a-f]{40}( |$)' || true)
[ -z "$bad_pins" ] || err "actions not pinned by full SHA:
$bad_pins"

# 2. Persisted credentials disabled on every checkout.
checkouts=$(grep -rc 'actions/checkout@' "$workflows"/*.yml | awk -F: '{s+=$2} END{print s+0}')
disabled=$(grep -rc 'persist-credentials: false' "$workflows"/*.yml | awk -F: '{s+=$2} END{print s+0}')
[ "$disabled" -ge "$checkouts" ] || err "checkouts without persist-credentials: false ($disabled/$checkouts)"

# 3. Least-privilege default permissions in every workflow.
for f in "$workflows"/*.yml; do
    grep -q '^permissions:' "$f" || err "$(basename "$f"): missing top-level permissions"
    grep -q 'contents: read' "$f" || err "$(basename "$f"): default permissions are not contents: read"
done

# 4. MSRV is exactly 1.88, tested alongside stable.
grep -q '"1.88.0"' "$workflows/ci.yml" || err "ci.yml: MSRV 1.88.0 missing"
grep -q 'toolchain: stable' "$workflows/ci.yml" || err "ci.yml: stable leg missing"

# 5. The eight required check names exist.
for name in \
    'fmt · clippy · build · test' \
    'pam_wrapper integration' \
    'AddressSanitizer (test suite)' \
    'Analyze (rust)' \
    'cargo-deny (advisories · licenses · sources)' \
    'actionlint (workflow correctness)' \
    'zizmor (workflow security)' \
    'DCO (exactly one trailer)'
do
    grep -rqF "$name" "$workflows" || err "required check name missing: $name"
done

# 6. ASan uses an explicit target and symbolizer.
grep -q -- '-Zsanitizer=address' "$workflows/asan.yml" || err "asan.yml: -Zsanitizer=address missing"
grep -q -- '--target x86_64-unknown-linux-gnu' "$workflows/asan.yml" || err "asan.yml: explicit --target missing"
grep -Eq 'ASAN_OPTIONS=.*external_symbolizer_path|external_symbolizer_path' "$workflows/asan.yml" \
    || err "asan.yml: explicit symbolizer missing"

# 7. No publication, release, or blanket write permission.
forbidden=$(grep -rniE 'cargo publish|publish.*crates\.io|gh release create|write-all' "$workflows" || true)
[ -z "$forbidden" ] || err "forbidden publication/release/permission content:
$forbidden"

[ "$fail" -eq 0 ] || exit 1
printf 'workflow contract: OK\n'
