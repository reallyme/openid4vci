#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

require_command() {
  command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 69
  fi
}

require_command curl
require_command docker
require_command git
require_command jq
require_command openssl
require_command python3
require_command shasum

if ! docker ps >/dev/null 2>&1; then
  echo "docker daemon is not reachable" >&2
  exit 69
fi
