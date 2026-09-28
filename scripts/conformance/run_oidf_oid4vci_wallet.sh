#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

suite_dir="${CONFORMANCE_SUITE_DIR:-${1:-}}"
plan_id="${OIDF_PLAN_ID:-oid4vci-1_0-wallet-haip-test-plan}"
suite_contract="${OIDF_SUITE_CONTRACT:-conformance/oidf/suite-contract.json}"
profile_matrix="${OIDF_PROFILE_MATRIX:-conformance/oidf/profile-matrix.json}"
module_inventory="${OIDF_MODULE_INVENTORY:-conformance/oidf/certification-module-inventory.json}"
suite_commit="${OIDF_SUITE_COMMIT:-}"
runner_mode="${OIDF_WALLET_RUNNER_MODE:-${OIDF_RUNNER_MODE:-execute}}"
results_dir="${CONFORMANCE_RESULTS_DIR:-target/conformance-results}"
result_file="${results_dir}/${plan_id}.json"
result_assertion="${OIDF_RESULT_ASSERTION:-scripts/conformance/assert_oidf_results.sh}"
wallet_harness_endpoint="${OPENID4VCI_WALLET_HARNESS_ENDPOINT:-${OIDF_WALLET_HARNESS_ENDPOINT:-}}"
wallet_harness_health_endpoint="${OPENID4VCI_WALLET_HARNESS_HEALTH_ENDPOINT:-${OIDF_WALLET_HARNESS_HEALTH_ENDPOINT:-}}"
wallet_harness_token="${OPENID4VCI_WALLET_HARNESS_TOKEN:-${OIDF_WALLET_HARNESS_TOKEN:-}}"
wallet_harness_binary="${OPENID4VCI_WALLET_HARNESS_BINARY:-}"
wallet_source_repository="${OPENID4VCI_WALLET_SOURCE_REPOSITORY:-}"
wallet_source_repository_dir="${OPENID4VCI_WALLET_SOURCE_REPOSITORY_DIR:-}"
source_repository_dir="${OPENID4VCI_SOURCE_REPOSITORY_DIR:-.}"
config_file="${OIDF_WALLET_CONFIG_FILE:-}"
plan_expression="${OIDF_WALLET_PLAN_EXPRESSION:-${plan_id}[vci_authorization_code_flow_variant=wallet_initiated][credential_format=sd_jwt_vc]}"
python_bin="${PYTHON:-python3}"
evidence_dir=""
export_dir=""
implementation_evidence_dir=""
wallet_driver_pid=""

cleanup_wallet_driver() {
  if [ -n "$wallet_driver_pid" ]; then
    kill "$wallet_driver_pid" 2>/dev/null || true
    wait "$wallet_driver_pid" 2>/dev/null || true
    wallet_driver_pid=""
  fi
}

trap cleanup_wallet_driver EXIT
trap 'exit 130' HUP INT TERM

write_result() {
  status="$1"
  reason="$2"
  mkdir -p "$results_dir"
  printf '{"plan_id":"%s","status":"%s","reason":"%s"}\n' \
    "$plan_id" "$status" "$reason" > "$result_file"
}

fail_with_result() {
  reason="$1"
  write_result "failed" "$reason"
  echo "$reason" >&2
  exit 2
}

require_lower_hex() {
  value="$1"
  expected_length="$2"
  reason="$3"
  if [ "${#value}" -ne "$expected_length" ]; then
    fail_with_result "$reason"
  fi
  case "$value" in
    *[!0-9a-f]*)
      fail_with_result "$reason"
      ;;
  esac
}

derive_health_endpoint() {
  endpoint="$1"
  case "$endpoint" in
    */oidf/wallet/credential-offer)
      printf '%s/healthz\n' "${endpoint%/oidf/wallet/credential-offer}"
      ;;
    *)
      printf '\n'
      ;;
  esac
}

require_composed_wallet_harness() {
  endpoint="$1"
  if [ -z "$endpoint" ]; then
    fail_with_result "missing_wallet_harness_health_endpoint"
  fi
  if ! command -v curl >/dev/null 2>&1; then
    fail_with_result "missing_curl"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    fail_with_result "missing_jq"
  fi
  if ! curl -fsS "$endpoint" | jq -e '.composed_flow_driver_enabled == true' >/dev/null; then
    fail_with_result "wallet_harness_missing_composed_flow_driver"
  fi
}

require_safe_evidence_dir() {
  dir="$1"
  case "$dir" in
    "" | "/" | "." | "..")
      fail_with_result "unsafe_wallet_evidence_dir"
      ;;
    /*)
      ;;
    *)
      case "$dir" in
        target/conformance-results/*)
          ;;
        *)
          fail_with_result "unsafe_wallet_evidence_dir"
          ;;
      esac
      ;;
  esac
}

if [ -z "$suite_dir" ] || [ ! -d "$suite_dir" ]; then
  fail_with_result "missing_conformance_suite"
fi

if [ ! -f "$suite_contract" ]; then
  fail_with_result "missing_oidf_suite_contract"
fi

if [ ! -f "$profile_matrix" ]; then
  fail_with_result "missing_oidf_profile_matrix"
fi

if [ ! -f "$module_inventory" ]; then
  fail_with_result "missing_oidf_module_inventory"
fi

for command_name in git jq openssl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail_with_result "missing_required_command"
  fi
done

if [ -z "$suite_commit" ]; then
  suite_commit="$(jq -er '.commit | select(type == "string" and length == 40)' "$suite_contract")" ||
    fail_with_result "invalid_oidf_suite_contract"
fi

actual_commit="$(git -C "$suite_dir" rev-parse HEAD 2>/dev/null || true)"
if [ "$actual_commit" != "$suite_commit" ]; then
  fail_with_result "conformance_suite_commit_mismatch"
fi

if [ ! -f "conformance/oidf-wallet-plan.toml" ]; then
  fail_with_result "missing_oidf_wallet_plan"
fi

runner="${suite_dir}/scripts/run-test-plan.py"

echo "OIDF suite: ${suite_dir}"
echo "OIDF suite commit: ${suite_commit}"
echo "Plan: ${plan_id}"
echo "OpenID4VCI wallet harness: ${wallet_harness_endpoint:-not_configured}"

if [ "$runner_mode" != "execute" ]; then
  fail_with_result "wallet_runner_disabled"
fi

profile_id="$(jq -er \
  --arg role "wallet" \
  --arg plan_id "$plan_id" \
  --arg expression "$plan_expression" \
  '.profiles[] | select(
    .entity_under_test == $role and
    .plan_id == $plan_id and
    .plan_expression == $expression
  ) | .profile_id' \
  "$profile_matrix")" || fail_with_result "wallet_plan_expression_not_allowlisted"
expected_module_count="$(jq -er \
  --arg profile_id "$profile_id" \
  '.profiles[]
   | select(.profile_id == $profile_id)
   | .expected_module_count
   | select(type == "number" and . > 0)' \
  "$profile_matrix")" || fail_with_result "wallet_profile_module_count_missing"

if [ -z "$wallet_source_repository" ]; then
  fail_with_result "wallet_source_repository_identity_missing"
fi

source_repository="$(jq -er '.source_repository | select(type == "string" and length > 0)' \
  "$profile_matrix")" || fail_with_result "source_repository_missing"
source_commit="$(git -C "$source_repository_dir" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" ||
  fail_with_result "source_commit_unavailable"
require_lower_hex "$source_commit" 40 "source_commit_invalid"
if [ -n "$(git -C "$source_repository_dir" status --porcelain --untracked-files=normal)" ]; then
  fail_with_result "source_worktree_not_clean"
fi

if [ -z "$wallet_source_repository_dir" ] || [ ! -d "$wallet_source_repository_dir" ]; then
  fail_with_result "wallet_source_repository_missing"
fi
wallet_source_commit="$(git -C "$wallet_source_repository_dir" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" ||
  fail_with_result "wallet_source_commit_unavailable"
require_lower_hex "$wallet_source_commit" 40 "wallet_source_commit_invalid"
if [ -n "$(git -C "$wallet_source_repository_dir" status --porcelain --untracked-files=normal)" ]; then
  fail_with_result "wallet_source_worktree_not_clean"
fi
if [ -z "$wallet_harness_binary" ] || [ ! -f "$wallet_harness_binary" ]; then
  fail_with_result "wallet_harness_binary_missing"
fi
wallet_harness_binary_sha256="$(openssl dgst -sha256 "$wallet_harness_binary" | awk '{print $NF}')" ||
  fail_with_result "wallet_harness_binary_digest_failed"
require_lower_hex "$wallet_harness_binary_sha256" 64 "wallet_harness_binary_digest_invalid"

evidence_dir="${OIDF_WALLET_EVIDENCE_DIR:-${results_dir}/${profile_id}}"
export_dir="${evidence_dir}/suite-export"
implementation_evidence_dir="${evidence_dir}/wallet-implementation-evidence"

case "$plan_expression" in
  *'[vci_authorization_code_flow_variant=wallet_initiated]'*)
    launch_mode="wallet_initiated"
    ;;
  *'[vci_authorization_code_flow_variant=issuer_initiated]'*)
    launch_mode="issuer_initiated"
    ;;
  *)
    fail_with_result "wallet_plan_launch_mode_missing"
    ;;
esac

if [ -z "${CONFORMANCE_SERVER:-}" ]; then
  fail_with_result "missing_conformance_server"
fi

if [ -z "$wallet_harness_endpoint" ]; then
  fail_with_result "missing_wallet_harness_endpoint"
fi

if [ -z "$wallet_harness_token" ]; then
  fail_with_result "missing_wallet_harness_token"
fi

if [ -z "$wallet_harness_health_endpoint" ]; then
  wallet_harness_health_endpoint="$(derive_health_endpoint "$wallet_harness_endpoint")"
fi

require_composed_wallet_harness "$wallet_harness_health_endpoint"

if [ ! -f "$runner" ]; then
  fail_with_result "missing_oidf_runner"
fi

if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
  fail_with_result "missing_oidf_wallet_config"
fi

if [ ! -f "$result_assertion" ]; then
  fail_with_result "missing_oidf_result_assertion"
fi

wallet_driver="scripts/conformance/drive_oidf_wallet_modules.py"
implementation_assertion="scripts/conformance/assert_oidf_wallet_implementation_evidence.py"
if [ ! -f "$wallet_driver" ]; then
  fail_with_result "missing_oidf_wallet_module_driver"
fi
if [ ! -f "$implementation_assertion" ]; then
  fail_with_result "missing_oidf_wallet_implementation_assertion"
fi

oidf_alias="$(jq -er '.alias | select(type == "string" and length > 0)' "$config_file")" ||
  fail_with_result "missing_oidf_wallet_alias"

require_safe_evidence_dir "$evidence_dir"
rm -rf "$evidence_dir"
mkdir -p "$export_dir" "$implementation_evidence_dir"
printf '%s\n' "$actual_commit" > "$evidence_dir/oidf-suite-revision.txt"
scripts/conformance/redact_oidf_config.sh \
  "$config_file" \
  "$evidence_dir/oid4vci-wallet-config.redacted.json"
"$python_bin" scripts/conformance/discover_oidf_openid4vci.py \
  "$suite_dir" \
  "$evidence_dir/oidf-discovery" \
  --contract "$suite_contract" || fail_with_result "oidf_suite_contract_mismatch"

CONFORMANCE_SERVER="$CONFORMANCE_SERVER" \
  OIDF_PLAN_ID="$plan_id" \
  OIDF_ALIAS="$oidf_alias" \
  OIDF_WALLET_PLAN_EXPRESSION="$plan_expression" \
  OPENID4VCI_WALLET_HARNESS_ENDPOINT="$wallet_harness_endpoint" \
  OPENID4VCI_WALLET_HARNESS_TOKEN="$wallet_harness_token" \
  OPENID4VCI_WALLET_IMPLEMENTATION_EVIDENCE_DIR="$implementation_evidence_dir" \
  "$python_bin" "$wallet_driver" &
wallet_driver_pid=$!

runner_status=0
if OPENID4VCI_WALLET_HARNESS_ENDPOINT="$wallet_harness_endpoint" \
  OIDF_WALLET_HARNESS_ENDPOINT="$wallet_harness_endpoint" \
  scripts/conformance/execute_oidf_test_plan.sh \
    "$runner" "$export_dir" "$plan_expression" "$config_file"; then
  runner_status=0
else
  runner_status=$?
fi

if ! kill -0 "$wallet_driver_pid" 2>/dev/null; then
  wait "$wallet_driver_pid" 2>/dev/null || true
  wallet_driver_pid=""
  fail_with_result "oidf_wallet_module_driver_exited"
fi
kill "$wallet_driver_pid" 2>/dev/null || true
if ! wait "$wallet_driver_pid"; then
  wallet_driver_pid=""
  fail_with_result "oidf_wallet_module_driver_failed"
fi
wallet_driver_pid=""

if [ "$runner_status" -eq 0 ]; then
  if ! "$result_assertion" \
    "$export_dir" \
    "$expected_module_count" \
    "$module_inventory" \
    "$plan_expression" \
    "$oidf_alias"; then
    fail_with_result "oidf_suite_export_missing"
  fi
  if ! "$python_bin" "$implementation_assertion" \
    "$export_dir" "$implementation_evidence_dir" "$launch_mode"; then
    fail_with_result "oidf_wallet_implementation_evidence_failed"
  fi
  implementation_evidence_count="$(find "$implementation_evidence_dir" -type f -name '*.json' | wc -l | tr -d ' ')"
  suite_export_count="$(find "$export_dir" -maxdepth 1 -type f -name '*.zip' | wc -l | tr -d ' ')"
  if [ "$suite_export_count" != "1" ]; then
    fail_with_result "oidf_suite_export_count_invalid"
  fi
  suite_export_file="$(find "$export_dir" -maxdepth 1 -type f -name '*.zip' -print)"
  suite_export_sha256="$(openssl dgst -sha256 "$suite_export_file" | awk '{print $NF}')" ||
    fail_with_result "oidf_suite_export_digest_failed"
  require_lower_hex "$suite_export_sha256" 64 "oidf_suite_export_digest_invalid"
  current_source_commit="$(git -C "$source_repository_dir" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" ||
    fail_with_result "source_commit_unavailable_after_execution"
  if [ "$current_source_commit" != "$source_commit" ] ||
    [ -n "$(git -C "$source_repository_dir" status --porcelain --untracked-files=normal)" ]; then
    fail_with_result "source_changed_during_execution"
  fi
  current_wallet_source_commit="$(git -C "$wallet_source_repository_dir" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" ||
    fail_with_result "wallet_source_commit_unavailable_after_execution"
  if [ "$current_wallet_source_commit" != "$wallet_source_commit" ] ||
    [ -n "$(git -C "$wallet_source_repository_dir" status --porcelain --untracked-files=normal)" ]; then
    fail_with_result "wallet_source_changed_during_execution"
  fi
  current_wallet_binary_sha256="$(openssl dgst -sha256 "$wallet_harness_binary" | awk '{print $NF}')" ||
    fail_with_result "wallet_harness_binary_digest_failed_after_execution"
  if [ "$current_wallet_binary_sha256" != "$wallet_harness_binary_sha256" ]; then
    fail_with_result "wallet_harness_binary_changed_during_execution"
  fi
  jq -n \
    --arg source_repository "$source_repository" \
    --arg source_commit "$source_commit" \
    --arg profile_id "$profile_id" \
    --arg plan_id "$plan_id" \
    --arg plan_expression "$plan_expression" \
    --arg oidf_alias "$oidf_alias" \
    --arg result "passed" \
    --arg suite_commit "$actual_commit" \
    --arg wallet_harness_endpoint "$wallet_harness_endpoint" \
    --arg wallet_harness_health_endpoint "$wallet_harness_health_endpoint" \
    --arg wallet_config "oid4vci-wallet-config.redacted.json" \
    --arg implementation_evidence_dir "wallet-implementation-evidence" \
    --arg implementation_source_repository "$wallet_source_repository" \
    --arg implementation_source_commit "$wallet_source_commit" \
    --arg implementation_binary_sha256 "$wallet_harness_binary_sha256" \
    --arg suite_export_sha256 "$suite_export_sha256" \
    --argjson implementation_evidence_count "$implementation_evidence_count" \
    '{
      schema_version: 3,
      source_repository: $source_repository,
      source_commit: $source_commit,
      source_worktree_clean: true,
      profile_id: $profile_id,
      plan_id: $plan_id,
      plan_expression: $plan_expression,
      oidf_alias: $oidf_alias,
      result: $result,
      suite_commit: $suite_commit,
      wallet_harness_endpoint: $wallet_harness_endpoint,
      wallet_harness_health_endpoint: $wallet_harness_health_endpoint,
      wallet_config: $wallet_config,
      implementation_evidence_dir: $implementation_evidence_dir,
      implementation_evidence_count: $implementation_evidence_count,
      implementation_source_repository: $implementation_source_repository,
      implementation_source_commit: $implementation_source_commit,
      implementation_source_worktree_clean: true,
      implementation_binary_sha256: $implementation_binary_sha256,
      suite_export_sha256: $suite_export_sha256
    }' > "$evidence_dir/summary.json"
  write_result "passed" "oidf_wallet_suite_runner_completed"
else
  fail_with_result "oidf_wallet_suite_runner_failed"
fi
