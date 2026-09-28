#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly GITLEAKS_VERSION="8.30.1"

case "$(uname -s):$(uname -m)" in
  Darwin:arm64)
    readonly archive_platform="darwin_arm64"
    readonly archive_sha256="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
    ;;
  Darwin:x86_64)
    readonly archive_platform="darwin_x64"
    readonly archive_sha256="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"
    ;;
  Linux:aarch64 | Linux:arm64)
    readonly archive_platform="linux_arm64"
    readonly archive_sha256="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
    ;;
  Linux:x86_64 | Linux:amd64)
    readonly archive_platform="linux_x64"
    readonly archive_sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    ;;
  *)
    echo "unsupported platform for the pinned gitleaks release" >&2
    exit 69
    ;;
esac

scan_directory="$(mktemp -d)"
readonly scan_directory
cleanup() {
  rm -rf -- "${scan_directory}"
}
trap cleanup EXIT

readonly archive_name="gitleaks_${GITLEAKS_VERSION}_${archive_platform}.tar.gz"
readonly archive_path="${scan_directory}/${archive_name}"
readonly binary_path="${scan_directory}/gitleaks"
readonly download_url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${archive_name}"

curl --fail --show-error --silent --location \
  --output "${archive_path}" \
  "${download_url}"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "${archive_path}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_sha256="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
else
  echo "a SHA-256 implementation is required" >&2
  exit 69
fi
readonly actual_sha256

if [[ "${actual_sha256}" != "${archive_sha256}" ]]; then
  echo "gitleaks archive digest mismatch" >&2
  exit 65
fi

tar --extract --gzip --file "${archive_path}" --directory "${scan_directory}" gitleaks
chmod 0755 "${binary_path}"

"${binary_path}" git --redact --no-banner --verbose .
