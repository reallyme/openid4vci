#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  printf '%s\n' 'error: ripgrep (rg) is required for Rust source policy checks' >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

readonly production_maximum_lines=500
readonly test_maximum_lines=800
status=0
policy_tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "${policy_tmp_dir}"' EXIT

run_rg_allow_no_matches() {
  local output_path="$1"
  shift
  local rg_status=0
  rg "$@" >"${output_path}" || rg_status=$?
  if ((rg_status > 1)); then
    printf '%s\n' 'error: ripgrep failed during Rust source policy checks' >&2
    return "${rg_status}"
  fi
}

run_rg_allow_no_matches "${policy_tmp_dir}/rust-files" --files crates conformance fuzz -g '*.rs'

while IFS= read -r rust_path; do
  case "${rust_path}" in
    */generated/*) continue ;;
    */tests/* | */tests.rs | *_tests.rs) maximum_lines="${test_maximum_lines}" ;;
    *) maximum_lines="${production_maximum_lines}" ;;
  esac

  actual_lines="$(awk 'END { print NR }' "${rust_path}")"
  if ((actual_lines > maximum_lines)); then
    printf 'authored Rust source exceeds audit limit: %s (%s > %s)\n' \
      "${rust_path}" "${actual_lines}" "${maximum_lines}" >&2
    status=1
  fi

  case "${rust_path}" in
    */lib.rs | */mod.rs)
      if rg -n \
        '^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?(fn|struct|enum|trait|impl|type|const|static|macro_rules!)[[:space:]!]' \
        "${rust_path}"; then
        printf 'lib.rs and mod.rs may contain declarations and explicit re-exports only: %s\n' \
          "${rust_path}" >&2
        status=1
      fi
      ;;
  esac
done <"${policy_tmp_dir}/rust-files"

run_rg_allow_no_matches "${policy_tmp_dir}/wildcard-imports" -n \
  '^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?use[[:space:]][^;]*::[*][[:space:]]*;' \
  crates conformance fuzz --glob '*.rs' --glob '!**/generated/**'

while IFS= read -r wildcard_import; do
  printf 'wildcard Rust import or export is forbidden: %s\n' "${wildcard_import}" >&2
  status=1
done <"${policy_tmp_dir}/wildcard-imports"

run_rg_allow_no_matches "${policy_tmp_dir}/inline-tests" -n \
  '^[[:space:]]*mod[[:space:]]+(tests|[A-Za-z0-9_]+_tests)[[:space:]]*\{' \
  crates conformance fuzz --glob '*.rs' --glob '!**/tests/**' \
  --glob '!**/generated/**'

while IFS= read -r inline_test_module; do
  printf 'test bodies must live in dedicated test files: %s\n' "${inline_test_module}" >&2
  status=1
done <"${policy_tmp_dir}/inline-tests"

exit "${status}"
