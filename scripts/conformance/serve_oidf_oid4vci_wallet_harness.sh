#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

bind="${OPENID4VCI_WALLET_HARNESS_BIND:-127.0.0.1:8788}"
endpoint="http://${bind}/oidf/wallet/credential-offer"

echo "OIDF OpenID4VCI wallet harness endpoint: ${endpoint}"
echo "Set OPENID4VCI_WALLET_HARNESS_ENDPOINT=${endpoint} for wallet-role OIDF plans."
echo "This OpenID4VCI example is recorder-only; execute-mode wallet OIDF runs must use a composed identity/wallet harness whose /healthz reports composed_flow_driver_enabled=true."
echo "For a remote OIDF server, expose this listener through public HTTPS."

exec cargo run -p openid4vci-http --features axum-holder-harness --example holder_harness -- "${bind}"
