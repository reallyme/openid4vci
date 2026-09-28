#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

audited_lockfiles=0

# Audit the repository's tracked lockfiles rather than only the workspace root.
# Fuzzers and standalone audit tools have independent dependency resolutions and
# can otherwise retain yanked or vulnerable packages after the root is clean.
while IFS= read -r -d '' lockfile; do
    audit_args=(--deny warnings --file "${lockfile}")
    if [[ "${audited_lockfiles}" -gt 0 ]]; then
        audit_args+=(--no-fetch)
    fi

    cargo audit "${audit_args[@]}"
    audited_lockfiles=$((audited_lockfiles + 1))
done < <(git ls-files -z -- '*Cargo.lock')

if [[ "${audited_lockfiles}" -eq 0 ]]; then
    echo "security audit failed: repository has no tracked Cargo.lock files" >&2
    exit 1
fi
