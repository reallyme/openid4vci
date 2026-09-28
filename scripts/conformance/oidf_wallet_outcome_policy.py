#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Source-bound terminal outcomes for the OIDF OpenID4VCI wallet plan."""

from __future__ import annotations

from dataclasses import dataclass


CREDENTIAL_STORED = "credential_stored"
PROTOCOL_REJECTED = "protocol_rejected"

ISSUER_MISMATCH = (
    "fapi2-security-profile-final-client-test-discovery-issuer-mismatch"
)
MISSING_STATE = (
    "fapi2-security-profile-final-client-test-ensure-authorization-response-"
    "with-invalid-missing-state-fails"
)
INVALID_STATE = (
    "fapi2-security-profile-final-client-test-ensure-authorization-response-"
    "with-invalid-state-fails"
)
INVALID_AUTHORIZATION_ISSUER = (
    "fapi2-security-profile-final-client-test-invalid-authorization-response-iss"
)
MISSING_AUTHORIZATION_ISSUER = (
    "fapi2-security-profile-final-client-test-remove-authorization-response-iss"
)

CERTIFICATION_POSITIVE_MODULES = frozenset(
    {
        "fapi2-security-profile-final-client-test-happy-path",
        "fapi2-security-profile-final-client-test-happy-path-no-dpop-nonce",
        "fapi2-security-profile-final-client-test-rs-dpop-auth-scheme-case-insensitivity",
        "fapi2-security-profile-final-client-test-token-endpoint-response-without-expires_in",
        "fapi2-security-profile-final-client-test-token-type-case-insensitivity",
        "oid4vci-1_0-wallet-test-batch-credential-issuance",
        "oid4vci-1_0-wallet-test-client-attestation-challenge",
        "oid4vci-1_0-wallet-test-credential-issuance",
        "oid4vci-1_0-wallet-test-credential-issuance-notification",
    }
)

# The engineering plan contains positive-path coverage that is not part of the
# locked HAIP certification inventory. Keep those modules explicit and closed:
# an unknown suite module must never be treated as successful merely because
# the wallet returned a credential.
ENGINEERING_POSITIVE_MODULES = frozenset(
    {
        "oid4vci-1_0-wallet-happy-path-with-scopes-without-authorization-details-in-token-response",
    }
)

POSITIVE_MODULES = CERTIFICATION_POSITIVE_MODULES | ENGINEERING_POSITIVE_MODULES

REJECTION_REASONS = {
    ISSUER_MISMATCH: "authorization_server_issuer_mismatch",
    MISSING_STATE: "authorization_state_missing",
    INVALID_STATE: "authorization_state_mismatch",
    INVALID_AUTHORIZATION_ISSUER: "authorization_issuer_mismatch",
    MISSING_AUTHORIZATION_ISSUER: "authorization_issuer_missing",
}

CERTIFICATION_WALLET_MODULES = CERTIFICATION_POSITIVE_MODULES | frozenset(
    REJECTION_REASONS
)
WALLET_MODULES = POSITIVE_MODULES | frozenset(REJECTION_REASONS)


class OutcomePolicyError(Exception):
    """Stable failure raised when evidence does not match the locked plan policy."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ExpectedOutcome:
    """Expected non-secret terminal outcome for one suite module."""

    flow_status: str
    flow_reason: str | None


def expected_outcome(module_id: str) -> ExpectedOutcome:
    """Return the exact terminal outcome required by the pinned suite module."""
    if module_id in POSITIVE_MODULES:
        return ExpectedOutcome(CREDENTIAL_STORED, None)
    reason = REJECTION_REASONS.get(module_id)
    if reason is not None:
        return ExpectedOutcome(PROTOCOL_REJECTED, reason)
    raise OutcomePolicyError("unknown_wallet_module_policy")


def validate_observed_outcome(
    module_id: str, flow_status: object, flow_reason: object
) -> ExpectedOutcome:
    """Validate a host outcome without treating arbitrary failures as rejections."""
    expected = expected_outcome(module_id)
    if flow_status != expected.flow_status or flow_reason != expected.flow_reason:
        raise OutcomePolicyError("wallet_flow_outcome_mismatch")
    return expected
