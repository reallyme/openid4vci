#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/openid4vci-issuer-provenance-test.XXXXXX")"
cleanup() {
  rm -rf "$temp_dir"
}
trap cleanup EXIT

source_repository_dir="$temp_dir/source"
issuer_binary="$temp_dir/issuer"
marker_file="$temp_dir/injection-marker"
assertion="scripts/conformance/assert_oidf_issuer_provenance.sh"

mkdir -p "$source_repository_dir"
git -C "$source_repository_dir" init -q
git -C "$source_repository_dir" config user.name "ReallyMe Test"
git -C "$source_repository_dir" config user.email "test@really.me"
printf '%s\n' "fixture" > "$source_repository_dir/tracked.txt"
git -C "$source_repository_dir" add tracked.txt
git -C "$source_repository_dir" commit -q -m "Create provenance fixture"
source_commit="$(git -C "$source_repository_dir" rev-parse HEAD)"
printf '%s\n' "issuer fixture" > "$issuer_binary"
chmod +x "$issuer_binary"
binary_sha256="$(openssl dgst -sha256 "$issuer_binary" | awk '{print $NF}')"

expect_failure() {
  case_name="$1"
  shift
  if "$assertion" "$@" >/dev/null 2>&1; then
    echo "issuer provenance test unexpectedly passed: $case_name" >&2
    exit 1
  fi
}

"$assertion" "$source_repository_dir" "$issuer_binary" "$source_commit" "$binary_sha256"

printf '%s\n' "dirty" >> "$source_repository_dir/tracked.txt"
expect_failure "dirty source worktree" \
  "$source_repository_dir" "$issuer_binary" "$source_commit" "$binary_sha256"
printf '%s\n' "fixture" > "$source_repository_dir/tracked.txt"

printf '%s\n' "untracked" > "$source_repository_dir/untracked.txt"
expect_failure "untracked source file" \
  "$source_repository_dir" "$issuer_binary" "$source_commit" "$binary_sha256"
rm "$source_repository_dir/untracked.txt"

printf '%s\n' "next" > "$source_repository_dir/next.txt"
git -C "$source_repository_dir" add next.txt
git -C "$source_repository_dir" commit -q -m "Advance provenance fixture"
expect_failure "source commit changed" \
  "$source_repository_dir" "$issuer_binary" "$source_commit" "$binary_sha256"
source_commit="$(git -C "$source_repository_dir" rev-parse HEAD)"

printf '%s\n' "mutated issuer fixture" > "$issuer_binary"
expect_failure "issuer binary changed" \
  "$source_repository_dir" "$issuer_binary" "$source_commit" "$binary_sha256"

expect_failure "malicious expected commit" \
  "$source_repository_dir" "$issuer_binary" "\$(touch $marker_file)" "$binary_sha256"
if [ -e "$marker_file" ]; then
  echo "issuer provenance test executed untrusted expected commit data" >&2
  exit 1
fi

echo "OIDF issuer provenance tests passed"
