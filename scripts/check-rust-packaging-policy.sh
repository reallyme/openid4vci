#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

status=0

require_manifest_text() {
  local manifest="$1"
  local required="$2"

  if ! awk -v required="${required}" 'index($0, required) { found = 1 } END { exit !found }' "${manifest}"; then
    printf '%s\n' "error: ${manifest} is missing approved package policy: ${required}" >&2
    status=1
  fi
}

require_manifest_text "crates/proto/Cargo.toml" 'name = "reallyme-openid4vci-proto"'
require_manifest_text "crates/proto/Cargo.toml" 'publish = true'
require_manifest_text "crates/types/Cargo.toml" 'name = "reallyme-openid4vci-types"'
require_manifest_text "crates/types/Cargo.toml" 'publish = true'
require_manifest_text "crates/attestation/Cargo.toml" 'name = "openid4vci-attestation"'
require_manifest_text "crates/attestation/Cargo.toml" 'publish = true'
require_manifest_text "crates/wallet/Cargo.toml" 'name = "reallyme-openid4vci-wallet"'
require_manifest_text "crates/wallet/Cargo.toml" 'publish = true'
require_manifest_text "crates/profiles/Cargo.toml" 'name = "openid4vci-profiles"'
require_manifest_text "crates/profiles/Cargo.toml" 'publish = true'
require_manifest_text "crates/issuer/Cargo.toml" 'name = "openid4vci-issuer"'
require_manifest_text "crates/issuer/Cargo.toml" 'publish = true'
require_manifest_text "crates/proto-codec/Cargo.toml" 'name = "openid4vci-proto-codec"'
require_manifest_text "crates/proto-codec/Cargo.toml" 'publish = true'
require_manifest_text "crates/http/Cargo.toml" 'name = "openid4vci-http"'
require_manifest_text "crates/http/Cargo.toml" 'publish = true'
require_manifest_text "crates/openid4vci/Cargo.toml" 'name = "reallyme-openid4vci"'
require_manifest_text "crates/openid4vci/Cargo.toml" 'publish = true'
require_manifest_text "Cargo.toml" 'license = "MIT OR Apache-2.0"'
require_manifest_text "Cargo.toml" 'package = "reallyme-openid4vci-types"'
require_manifest_text "Cargo.toml" 'package = "reallyme-openid4vci-proto"'
require_manifest_text "Cargo.toml" 'reallyme-jose = { version = "=0.4.2", default-features = false }'
require_manifest_text "Cargo.toml" 'reallyme-ssi-proto = { version = "=0.3.4", default-features = false }'
require_manifest_text "Cargo.toml" 'reallyme-openid-oauth = { version = "=0.3.4", default-features = false }'
require_manifest_text "Cargo.toml" 'reallyme-openid4vc-profiles = { version = "=0.3.4", default-features = false }'
require_manifest_text "Cargo.toml" 'reallyme-trust-core = { version = "=0.3.4", default-features = false }'
require_manifest_text "Cargo.toml" 'envelopes-x509 = { package = "reallyme-trust-x509", version = "=0.3.4", default-features = false }'
require_manifest_text "Cargo.toml" 'reallyme-mdoc = { version = "=0.3.4", default-features = false }'
require_manifest_text "Cargo.toml" 'reallyme-revocation = { version = "=0.3.4", default-features = false }'

if awk '
  index($0, "path = \"../ssi/") { invalid = 1 }
  index($0, "git =") && index($0, "reallyme/ssi") { invalid = 1 }
  END { exit invalid ? 0 : 1 }
' Cargo.toml; then
  printf '%s\n' "error: SSI dependencies must resolve from crates.io" >&2
  status=1
fi

for private_manifest in conformance/Cargo.toml; do
  require_manifest_text "${private_manifest}" 'publish = false'
done

is_allowed_registry_reallyme_package() {
  local package_name="$1"
  local package_version="$2"

  case "${package_name}" in
    reallyme-crypto | reallyme-crypto-*)
      [[ "${package_version}" == 0.3.* ]]
      ;;
    reallyme-codec | reallyme-codec-*)
      [[ "${package_version}" == 0.2.* ]]
      ;;
    reallyme-jose | reallyme-jose-*)
      [[ "${package_version}" == "0.4.2" ]]
      ;;
    reallyme-cose | reallyme-cose-*)
      [[ "${package_version}" == 0.2.* ]]
      ;;
    reallyme-credential-status | reallyme-mdoc | reallyme-openid-oauth | \
      reallyme-openid4vc-profiles | reallyme-revocation | reallyme-ssi-proto | \
      reallyme-trust-core | reallyme-trust-x509)
      [[ "${package_version}" == "0.3.4" ]]
      ;;
    *)
      return 1
      ;;
  esac
}

if [[ -f Cargo.lock ]]; then
  if awk '
    function flush_package() {
      if (reallyme && registry_source) {
        print package_name "\t" package_version
      }
    }
    /^\[\[package\]\]/ {
      flush_package()
      reallyme = 0
      registry_source = 0
      package_name = ""
      package_version = ""
      next
    }
    /^name = "reallyme-/ {
      reallyme = 1
      package_name = $0
      sub(/^name = "/, "", package_name)
      sub(/"$/, "", package_name)
      next
    }
    /^version = "/ {
      package_version = $0
      sub(/^version = "/, "", package_version)
      sub(/"$/, "", package_version)
      next
    }
    /^source = "registry\+https:\/\/github.com\/rust-lang\/crates.io-index"/ {
      registry_source = 1
      next
    }
    END {
      flush_package()
    }
  ' Cargo.lock | while IFS=$'\t' read -r package_name package_version; do
    if is_allowed_registry_reallyme_package "${package_name}" "${package_version}"; then
      continue
    fi
    printf '%s\n' "error: ${package_name} ${package_version} is not an approved independently released ReallyMe foundation package" >&2
    exit 1
  done; then
    :
  else
    status=1
  fi
fi

while IFS= read -r manifest; do
  crate_type_block="$(
    awk '
      /^[[:space:]]*crate-type[[:space:]]*=/ {
        in_block = 1
      }
      in_block {
        print
        if ($0 ~ /\]/) {
          in_block = 0
        }
      }
    ' "${manifest}"
  )"
  if [[ -z "${crate_type_block}" ]]; then
    continue
  fi

  if [[ "${crate_type_block}" != *"rlib"* ]]; then
    printf '%s\n' "error: ${manifest} declares crate-type without mandatory rlib" >&2
    status=1
  fi
done < <(
  find . \
    -name Cargo.toml \
    -not -path './target/*' \
    -not -path './.git/*' \
    -print
)

require_packaged_file() {
  local package_listing="$1"
  local package_name="$2"
  local required_path="$3"

  if ! awk -v required="${required_path}" '$0 == required { found = 1 } END { exit !found }' <<<"${package_listing}"; then
    printf '%s\n' "error: ${package_name} package is missing ${required_path}" >&2
    status=1
  fi
}

proto_package_listing="$(
  cargo package \
    --list \
    --allow-dirty \
    --manifest-path crates/proto/Cargo.toml
)"

for required_path in \
  proto/reallyme/openid4vci/v1/openid4vci.proto \
  proto/reallyme/openid4vci/v1/openid4vci_service.proto \
  tests/fixtures/protojson/manifest.json \
  tests/fixtures/protobuf/credential-offer.pb.hex \
  tests/fixtures/protobuf/credential-request.pb.hex \
  tests/fixtures/protobuf/credential-response.pb.hex \
  tests/fixtures/protobuf/deferred-credential-request.pb.hex \
  tests/fixtures/protobuf/issuer-metadata.pb.hex \
  tests/fixtures/protobuf/notification-request.pb.hex \
  tests/fixtures/protobuf/problem-details.pb.hex \
  tests/generated_security_tests.rs; do
  require_packaged_file "${proto_package_listing}" "reallyme-openid4vci-proto" "${required_path}"
done

if awk '/^(packages|bindings)\// { found = 1 } END { exit !found }' <<<"${proto_package_listing}"; then
  printf '%s\n' "error: reallyme-openid4vci-proto package contains platform binding artifacts" >&2
  status=1
fi

types_package_listing="$(
  cargo package \
    --list \
    --allow-dirty \
    --manifest-path crates/types/Cargo.toml
)"

for required_path in \
  LICENSE-MIT \
  LICENSE-APACHE \
  README.md \
  examples/generate_iso_transport_evidence.rs \
  src/lib.rs \
  src/validation.rs \
  tests/final_spec_tests.rs; do
  require_packaged_file "${types_package_listing}" "reallyme-openid4vci-types" "${required_path}"
done

for package_directory in \
  crates/proto \
  crates/types \
  crates/attestation \
  crates/wallet \
  crates/profiles \
  crates/issuer \
  crates/proto-codec \
  crates/http \
  crates/openid4vci; do
  for legal_file in LICENSE-MIT LICENSE-APACHE; do
    if ! cmp -s "${legal_file}" "${package_directory}/${legal_file}"; then
      printf '%s\n' "error: ${package_directory}/${legal_file} differs from repository ${legal_file}" >&2
      status=1
    fi
  done
done

exit "${status}"
