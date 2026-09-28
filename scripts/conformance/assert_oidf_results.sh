#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

python_bin="${PYTHON:-python3}"
exec "$python_bin" scripts/conformance/assert_oidf_results.py "$@"
