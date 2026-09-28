#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

source_repository_dir="${1:-}"
issuer_binary="${2:-}"
expected_source_commit="${3:-}"
expected_binary_sha256="${4:-}"

fail() {
  echo "OIDF issuer provenance check failed: $1" >&2
  exit 70
}

for command_name in awk git openssl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 69
  fi
done

if [ -z "$source_repository_dir" ] || [ ! -d "$source_repository_dir" ]; then
  fail "source repository directory is unavailable"
fi
if [ -z "$issuer_binary" ] || [ ! -x "$issuer_binary" ]; then
  fail "issuer binary is unavailable or not executable"
fi
if [ "${#expected_source_commit}" -ne 40 ]; then
  fail "expected source commit is malformed"
fi
case "$expected_source_commit" in
  *[!0-9a-f]*)
    fail "expected source commit is malformed"
    ;;
esac
if [ "${#expected_binary_sha256}" -ne 64 ]; then
  fail "expected issuer binary digest is malformed"
fi
case "$expected_binary_sha256" in
  *[!0-9a-f]*)
    fail "expected issuer binary digest is malformed"
    ;;
esac

actual_source_commit="$(git -C "$source_repository_dir" rev-parse --verify 'HEAD^{commit}')" ||
  fail "source commit is unavailable"
if [ "$actual_source_commit" != "$expected_source_commit" ]; then
  fail "source commit changed during execution"
fi
if [ -n "$(git -C "$source_repository_dir" status --porcelain --untracked-files=normal)" ]; then
  fail "source worktree is not clean"
fi
actual_binary_sha256="$(openssl dgst -sha256 "$issuer_binary" | awk '{print $NF}')" ||
  fail "issuer binary digest could not be computed"
if [ "$actual_binary_sha256" != "$expected_binary_sha256" ]; then
  fail "issuer binary changed during execution"
fi
