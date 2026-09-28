#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly FUZZ_MANIFEST="fuzz/Cargo.toml"
readonly FUZZ_RUNS="${OPENID4VCI_FUZZ_RUNS:-16}"
readonly FUZZ_MAX_LEN="${OPENID4VCI_FUZZ_MAX_LEN:-4096}"
readonly FUZZ_MAX_TOTAL_TIME="${OPENID4VCI_FUZZ_MAX_TOTAL_TIME:-}"
readonly FUZZ_RSS_LIMIT_MB="${OPENID4VCI_FUZZ_RSS_LIMIT_MB:-4096}"
readonly FUZZ_TOOLCHAIN="${OPENID4VCI_FUZZ_TOOLCHAIN:-nightly-2026-09-15}"
readonly FUZZ_BINARY_DIRECTORY_OVERRIDE="${OPENID4VCI_FUZZ_BINARY_DIRECTORY:-}"
readonly FUZZ_TARGET="${OPENID4VCI_FUZZ_TARGET:-}"

readonly -a FUZZ_TARGETS=(
  "credential_request_json"
  "issuer_metadata_json"
  "credential_offer_json"
  "credential_offer_uri"
  "nonce_response_json"
  "credential_response_json"
  "deferred_credential_request_json"
  "notification_request_json"
  "problem_details_json"
  "proof_jwt"
  "key_attestation_jwt"
  "issuer_metadata_proto"
  "operation_wire"
  "protojson_messages"
  "oauth_form"
  "signed_metadata_jwt"
  "credential_request_jwe"
  "credential_response_jwe"
)

require_positive_integer() {
  local name="$1"
  local value="$2"

  case "$value" in
    "" | *[!0-9]*)
      printf '%s must be a positive integer\n' "$name" >&2
      exit 2
      ;;
  esac

  if [ "$value" -eq 0 ]; then
    printf '%s must be greater than zero\n' "$name" >&2
    exit 2
  fi
}

require_positive_integer "OPENID4VCI_FUZZ_MAX_LEN" "$FUZZ_MAX_LEN"
if [ -n "$FUZZ_MAX_TOTAL_TIME" ]; then
  require_positive_integer "OPENID4VCI_FUZZ_MAX_TOTAL_TIME" "$FUZZ_MAX_TOTAL_TIME"
  require_positive_integer "OPENID4VCI_FUZZ_RSS_LIMIT_MB" "$FUZZ_RSS_LIMIT_MB"
else
  require_positive_integer "OPENID4VCI_FUZZ_RUNS" "$FUZZ_RUNS"
fi

case "$FUZZ_TOOLCHAIN" in
  "" | *[!A-Za-z0-9._-]*)
    printf 'OPENID4VCI_FUZZ_TOOLCHAIN must be a rustup toolchain name\n' >&2
    exit 2
    ;;
esac

selected_targets=("${FUZZ_TARGETS[@]}")
if [ -n "$FUZZ_TARGET" ]; then
  target_is_known=0
  for configured_target in "${FUZZ_TARGETS[@]}"; do
    if [ "$configured_target" = "$FUZZ_TARGET" ]; then
      target_is_known=1
      break
    fi
  done
  if [ "$target_is_known" -ne 1 ]; then
    printf 'OPENID4VCI_FUZZ_TARGET is not a configured fuzz target\n' >&2
    exit 2
  fi
  selected_targets=("$FUZZ_TARGET")
fi
readonly -a selected_targets

if [ -n "$FUZZ_BINARY_DIRECTORY_OVERRIDE" ]; then
  fuzz_binary_directory="$FUZZ_BINARY_DIRECTORY_OVERRIDE"
else
  # cargo-fuzz does not expose Cargo's --locked flag. Validate the dedicated
  # lockfile before building so local execution cannot silently drift.
  cargo "+${FUZZ_TOOLCHAIN}" metadata \
    --locked \
    --manifest-path "$FUZZ_MANIFEST" \
    --format-version 1 \
    --no-deps \
    >/dev/null

  # Build and link the complete target set once. Per-target Cargo invocations
  # repeat graph checks and may relink targets between executions.
  cargo "+${FUZZ_TOOLCHAIN}" fuzz build

  host_target="$(rustc "+${FUZZ_TOOLCHAIN}" -vV | sed -n 's/^host: //p')"
  if [ -z "$host_target" ]; then
    printf 'unable to determine the pinned nightly host target\n' >&2
    exit 1
  fi
  fuzz_binary_directory="fuzz/target/${host_target}/release"
fi
readonly fuzz_binary_directory

if [ ! -d "$fuzz_binary_directory" ]; then
  printf 'fuzz binary directory does not exist\n' >&2
  exit 1
fi

for target in "${selected_targets[@]}"; do
  artifact_dir="fuzz/artifacts/${target}"
  corpus_dir="fuzz/corpus/${target}"
  if [ -n "$FUZZ_MAX_TOTAL_TIME" ]; then
    fuzz_args=(
      "-max_total_time=${FUZZ_MAX_TOTAL_TIME}"
      "-rss_limit_mb=${FUZZ_RSS_LIMIT_MB}"
      "-max_len=${FUZZ_MAX_LEN}"
      "-artifact_prefix=${artifact_dir}/"
    )
  else
    fuzz_args=(
      "-runs=${FUZZ_RUNS}"
      "-max_len=${FUZZ_MAX_LEN}"
      "-artifact_prefix=${artifact_dir}/"
    )
  fi
  # Curated corpora are intentionally checked in for boundary-heavy targets.
  # Passing them explicitly prevents a green smoke run from exercising only
  # libFuzzer's synthetic empty input when contract fixtures are available.
  if [ -d "$corpus_dir" ]; then
    fuzz_args+=("$corpus_dir")
  fi
  mkdir -p "$artifact_dir"
  fuzz_binary="${fuzz_binary_directory}/${target}"
  if [ ! -x "$fuzz_binary" ]; then
    printf 'fuzz target executable is missing or not executable: %s\n' "$target" >&2
    exit 1
  fi
  printf 'Running fuzz smoke target: %s\n' "$target"
  "$fuzz_binary" "${fuzz_args[@]}"
done
