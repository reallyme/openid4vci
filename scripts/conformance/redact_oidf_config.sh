#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

input_file="${1:-}"
output_file="${2:-}"

if [ -z "$input_file" ] || [ -z "$output_file" ]; then
  echo "usage: redact_oidf_config.sh <input-json> <output-json>" >&2
  exit 64
fi

if [ "$input_file" = "$output_file" ]; then
  echo "input and output paths must differ" >&2
  exit 64
fi

if [ ! -f "$input_file" ]; then
  echo "OIDF configuration input not found" >&2
  exit 66
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "missing required command: jq" >&2
  exit 69
fi

umask 077
jq '
  def sensitive_name:
    test("(?i)^(client_?secret|password|private_?key|private_?key_?pem|api_?key|access_?token|refresh_?token|tx_?code|pin)$");
  walk(
    if type == "object" then
      del(.d, .p, .q, .dp, .dq, .qi, .oth, .k)
      | with_entries(
          if (.key | sensitive_name) then
            .value = "<redacted>"
          else
            .
          end
        )
    else
      .
    end
  )
' "$input_file" > "$output_file"
