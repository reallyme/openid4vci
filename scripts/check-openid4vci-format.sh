#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# rustfmt follows path dependencies when `--all` is used. Restricting the
# package set keeps this repository responsible for its own sources without
# rewriting generated code in sibling ReallyMe checkouts.
cargo fmt --check \
  -p reallyme-openid4vci \
  -p reallyme-openid4vci-types \
  -p openid4vci-attestation \
  -p reallyme-openid4vci-wallet \
  -p openid4vci-http \
  -p openid4vci-issuer \
  -p openid4vci-profiles \
  -p reallyme-openid4vci-proto \
  -p openid4vci-proto-codec \
  -p openid4vci-conformance

cargo fmt --manifest-path fuzz/Cargo.toml -- --check
