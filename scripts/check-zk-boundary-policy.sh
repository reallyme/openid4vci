#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  printf '%s\n' 'error: ripgrep (rg) is required for ZK boundary policy checks' >&2
  exit 1
fi

status=0
policy_tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "${policy_tmp_dir}"' EXIT

run_rg_allow_no_matches() {
  local output_path="$1"
  shift
  local rg_status=0
  rg "$@" >"${output_path}" || rg_status=$?
  if ((rg_status > 1)); then
    printf '%s\n' 'error: ripgrep failed during ZK boundary policy checks' >&2
    return "${rg_status}"
  fi
}

run_rg_allow_no_matches "${policy_tmp_dir}/cargo-matches" -n \
  'reallyme-zk-[A-Za-z0-9_-]+|backend-bb|barretenberg|bb-prover|bb_prover' \
  . --glob 'Cargo.toml' --glob '!target/**' --glob '!.git/**'

while IFS= read -r match; do
  case "${match}" in
    *reallyme-zk-api*) ;;
    *)
      printf '%s\n' "error: forbidden ZK crate/backend dependency: ${match}" >&2
      status=1
      ;;
  esac
done <"${policy_tmp_dir}/cargo-matches"

run_rg_allow_no_matches "${policy_tmp_dir}/source-matches" -n \
  'reallyme_zk_[A-Za-z0-9_]+|backend_bb|barretenberg|BbProver|BbVerifier' \
  crates conformance \
  --glob '!crates/proto/src/generated/**' \
  --glob '!**/tests/**'

while IFS= read -r match; do
  case "${match}" in
    *reallyme_zk_api*) ;;
    *)
      printf '%s\n' "error: forbidden concrete ZK backend in Rust source: ${match}" >&2
      status=1
      ;;
  esac
done <"${policy_tmp_dir}/source-matches"

exit "${status}"
