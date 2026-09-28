// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Profile policy builders.

use openid4vci_types::CredentialFormat;

use crate::define::{IssuanceProfile, ProfilePolicy};

/// Returns the baseline HAIP policy surface.
///
/// HAIP is the OpenID4VC High Assurance Interoperability Profile and is the
/// eIDAS-relevant high-assurance profile implemented by `crates/profiles`.
#[must_use]
pub fn haip_policy() -> ProfilePolicy {
    ProfilePolicy {
        profile: IssuanceProfile::Haip,
        credential_formats: vec![CredentialFormat::SdJwtVc, CredentialFormat::MsoMdoc],
        credential_configuration_scope_required: true,
        proof_required_for_every_configuration: false,
        wallet_attestation_format_required: false,
        key_attestation_required_for_every_proof: false,
        dpop_required: true,
        par_required: true,
        authorization_code_grant_required: true,
        pkce_s256_required: true,
        authorization_response_issuer_required: true,
        oauth_client_authentication_required: true,
        request_encryption_support_required: false,
        request_encryption_required: false,
        response_encryption_support_required: false,
        response_encryption_required: false,
        nonce_endpoint_required_for_key_binding: true,
        eidas_relevant: true,
    }
}

/// Returns the baseline EUDI PID issuance policy surface.
#[must_use]
pub fn eudi_pid_policy() -> ProfilePolicy {
    ProfilePolicy {
        profile: IssuanceProfile::EudiPid,
        credential_formats: vec![CredentialFormat::SdJwtVc, CredentialFormat::MsoMdoc],
        credential_configuration_scope_required: true,
        proof_required_for_every_configuration: false,
        wallet_attestation_format_required: false,
        key_attestation_required_for_every_proof: false,
        dpop_required: true,
        par_required: true,
        authorization_code_grant_required: true,
        pkce_s256_required: true,
        authorization_response_issuer_required: true,
        oauth_client_authentication_required: true,
        request_encryption_support_required: false,
        request_encryption_required: false,
        response_encryption_support_required: false,
        response_encryption_required: false,
        nonce_endpoint_required_for_key_binding: true,
        eidas_relevant: true,
    }
}
