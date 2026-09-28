#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

runner="${1:-}"
export_dir="${2:-}"
plan_expression="${3:-}"
config_file="${4:-}"
mode="${OIDF_CONFORMANCE_MODE:-}"
python_bin="${PYTHON:-python3}"

fail() {
  echo "OIDF test-plan execution failed: $1" >&2
  exit 64
}

if [ -z "$runner" ] || [ -z "$export_dir" ] || [ -z "$plan_expression" ] || [ -z "$config_file" ]; then
  fail "missing_arguments"
fi
if [ ! -f "$runner" ] || [ ! -f "$config_file" ]; then
  fail "missing_input_file"
fi

case "$mode" in
  local)
    if [ "${CONFORMANCE_TOKEN+x}" = "x" ]; then
      fail "local_mode_forbids_conformance_token"
    fi
    CONFORMANCE_DEV_MODE=1 \
      "$python_bin" "$runner" \
      --export-dir "$export_dir" \
      "$plan_expression" \
      "$config_file"
    ;;
  hosted)
    if [ "${CONFORMANCE_DEV_MODE+x}" = "x" ]; then
      fail "hosted_mode_forbids_developer_mode"
    fi
    if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
      fail "hosted_mode_requires_conformance_token"
    fi
    for server_url in "${CONFORMANCE_SERVER:-}" "${CONFORMANCE_SERVER_MTLS:-}"; do
      case "$server_url" in
        https://localhost* | https://127.* | https://host.docker.internal* | https://\[::1\]*)
          fail "hosted_mode_requires_public_server"
          ;;
        https://*)
          ;;
        *)
          fail "hosted_mode_requires_https_server"
          ;;
      esac
    done
    "$python_bin" "$runner" \
      --export-dir "$export_dir" \
      "$plan_expression" \
      "$config_file"
    ;;
  *)
    fail "mode_must_be_local_or_hosted"
    ;;
esac
