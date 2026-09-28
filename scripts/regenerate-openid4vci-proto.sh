#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly repository_root
cd "${repository_root}"
generation_root="$(mktemp -d /tmp/reallyme-openid4vci-proto.XXXXXX)"

cleanup_generation_root() {
  case "${generation_root}" in
    /tmp/reallyme-openid4vci-proto.*)
      rm -rf -- "${generation_root}"
      ;;
    *)
      return 1
      ;;
  esac
}
trap cleanup_generation_root EXIT

# Buffa packaging discovers adjacent ReallyMe crates when generation runs in a
# multi-repository checkout. Isolating the module prevents a schema update in
# OpenID4VCI from rewriting or requiring write access to sibling repositories.
mkdir -p "${generation_root}/crates/proto"
cp -R \
  "${repository_root}/crates/proto/proto" \
  "${generation_root}/crates/proto/proto"
cp "${repository_root}/buf.yaml" "${generation_root}/buf.yaml"
cp "${repository_root}/buf.gen.yaml" "${generation_root}/buf.gen.yaml"

(
  cd "${generation_root}"
  buf generate
)

readonly generated_relative_root="crates/proto/src/generated/buffa"
for generated_file in \
  mod.rs \
  reallyme.openid4vci.v1.mod.rs \
  reallyme.openid4vci.v1.openid4vci.rs \
  reallyme.openid4vci.v1.openid4vci.__oneof.rs \
  reallyme.openid4vci.v1.openid4vci.__view.rs \
  reallyme.openid4vci.v1.openid4vci.__view_oneof.rs; do
  cp \
    "${generation_root}/${generated_relative_root}/${generated_file}" \
    "${repository_root}/${generated_relative_root}/${generated_file}"
done

node scripts/harden-generated-openid4vci-proto.mjs
rustfmt --edition 2021 \
  "${repository_root}/${generated_relative_root}/mod.rs" \
  "${repository_root}/${generated_relative_root}/reallyme.openid4vci.v1.mod.rs" \
  "${repository_root}/${generated_relative_root}/reallyme.openid4vci.v1.openid4vci.rs" \
  "${repository_root}/${generated_relative_root}/reallyme.openid4vci.v1.openid4vci.__oneof.rs" \
  "${repository_root}/${generated_relative_root}/reallyme.openid4vci.v1.openid4vci.__view.rs" \
  "${repository_root}/${generated_relative_root}/reallyme.openid4vci.v1.openid4vci.__view_oneof.rs"
node scripts/harden-generated-openid4vci-proto.mjs --check-idempotent
node scripts/check-proto-first-boundaries.mjs
