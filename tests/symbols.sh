#!/usr/bin/env bash
set -euo pipefail
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cargo build --example test_module --features libpam

MODULE_DIR="${REPO_ROOT}/target/debug/deps"
if [[ ! -f "${MODULE_DIR}/libtest_module.so" ]]; then
  MODULE_DIR="${REPO_ROOT}/target/debug/examples"
fi

MODULE_PATH="${MODULE_DIR}/libtest_module.so"
if [[ ! -f "${MODULE_PATH}" ]]; then
  MODULE_DIR="${REPO_ROOT}/target/release/examples"
  MODULE_PATH="${MODULE_DIR}/libtest_module.so"
fi
if [[ ! -f "${MODULE_PATH}" ]]; then
  MODULE_DIR="${REPO_ROOT}/target/release/deps"
fi
if [[ -z "${MODULE_PATH:-}" || ! -f "${MODULE_PATH}" ]]; then
  MODULE_PATH="$(rg --files "${MODULE_DIR}" -g 'libtest_module*.so' | head -n 1)"
fi

if [[ ! -f "${MODULE_PATH}" ]]; then
  echo "symbol check failed: could not locate libtest_module.so" >&2
  exit 1
fi

mapfile -t actual < <(nm -D --defined-only "${MODULE_PATH}" | awk '$1 ~ /^[0-9a-f]+$/ {print $3}' | rg '^pam_sm_' | sort -u)
mapfile -t expected < <(cat <<'EOF' | sort -u
pam_sm_acct_mgmt
pam_sm_authenticate
pam_sm_chauthtok
pam_sm_close_session
pam_sm_open_session
pam_sm_setcred
EOF
)

if [[ "${#actual[@]}" -eq 0 ]]; then
  echo "symbol check failed: no pam_sm_* symbols found in ${MODULE_PATH}" >&2
  exit 1
fi

if ! diff -u <(printf '%s\n' "${expected[@]}") <(printf '%s\n' "${actual[@]}") ; then
  echo "symbol check failed: exported symbols mismatch" >&2
  echo "module: ${MODULE_PATH}" >&2
  exit 1
fi

echo "symbol check passed: ${MODULE_PATH}"
