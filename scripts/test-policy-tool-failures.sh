#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_tmp_dir}"' EXIT

for policy_script in check-rust-source-policy.sh check-zk-boundary-policy.sh; do
  if PATH=/usr/bin:/bin "${repo_root}/scripts/${policy_script}" >/dev/null 2>&1; then
    printf 'policy script accepted a missing rg executable: %s\n' "${policy_script}" >&2
    exit 1
  fi
done

printf '%s\n' '#!/usr/bin/env bash' 'exit 2' >"${test_tmp_dir}/rg"
chmod +x "${test_tmp_dir}/rg"

for policy_script in check-rust-source-policy.sh check-zk-boundary-policy.sh; do
  if PATH="${test_tmp_dir}:/usr/bin:/bin" \
    "${repo_root}/scripts/${policy_script}" >/dev/null 2>&1; then
    printf 'policy script accepted a failing rg executable: %s\n' "${policy_script}" >&2
    exit 1
  fi
done
