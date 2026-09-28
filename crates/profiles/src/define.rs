// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Profile identifiers and issuance policy types.

use openid4vci_types::CredentialFormat;
pub use reallyme_openid4vc_profiles::{
    Profile as IssuanceProfile, HAIP_PROFILE_NAME, HAIP_SHORT_NAME,
};

/// Immutable issuance requirements for a named interoperability profile.
///
/// Fields are private so a value identified as HAIP or EUDI PID cannot be
/// weakened while retaining its standards-derived label. Stricter deployment
/// requirements belong in a separately named application policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePolicy {
    pub(crate) profile: IssuanceProfile,
    pub(crate) credential_formats: Vec<CredentialFormat>,
    pub(crate) credential_configuration_scope_required: bool,
    pub(crate) proof_required_for_every_configuration: bool,
    pub(crate) wallet_attestation_format_required: bool,
    pub(crate) key_attestation_required_for_every_proof: bool,
    pub(crate) dpop_required: bool,
    pub(crate) par_required: bool,
    pub(crate) authorization_code_grant_required: bool,
    pub(crate) pkce_s256_required: bool,
    pub(crate) authorization_response_issuer_required: bool,
    pub(crate) oauth_client_authentication_required: bool,
    pub(crate) request_encryption_support_required: bool,
    pub(crate) request_encryption_required: bool,
    pub(crate) response_encryption_support_required: bool,
    pub(crate) response_encryption_required: bool,
    pub(crate) nonce_endpoint_required_for_key_binding: bool,
    pub(crate) eidas_relevant: bool,
}

impl ProfilePolicy {
    /// Returns the immutable profile identity.
    #[must_use]
    pub const fn profile(&self) -> IssuanceProfile {
        self.profile
    }

    /// Returns credential formats permitted by this profile.
    #[must_use]
    pub fn credential_formats(&self) -> &[CredentialFormat] {
        &self.credential_formats
    }

    /// Whether every configuration must advertise an OAuth scope.
    #[must_use]
    pub const fn credential_configuration_scope_required(&self) -> bool {
        self.credential_configuration_scope_required
    }

    /// Whether every configuration must require proof.
    #[must_use]
    pub const fn proof_required_for_every_configuration(&self) -> bool {
        self.proof_required_for_every_configuration
    }

    /// Whether the Appendix E wallet-attestation format is universally required.
    #[must_use]
    pub const fn wallet_attestation_format_required(&self) -> bool {
        self.wallet_attestation_format_required
    }

    /// Whether every proof type must require key attestation.
    #[must_use]
    pub const fn key_attestation_required_for_every_proof(&self) -> bool {
        self.key_attestation_required_for_every_proof
    }

    /// Whether DPoP is required.
    #[must_use]
    pub const fn dpop_required(&self) -> bool {
        self.dpop_required
    }

    /// Whether PAR is required for the authorization-code flow.
    #[must_use]
    pub const fn par_required(&self) -> bool {
        self.par_required
    }

    /// Whether the Authorization Code grant must be supported.
    #[must_use]
    pub const fn authorization_code_grant_required(&self) -> bool {
        self.authorization_code_grant_required
    }

    /// Whether authorization-code requests must use PKCE with `S256`.
    #[must_use]
    pub const fn pkce_s256_required(&self) -> bool {
        self.pkce_s256_required
    }

    /// Whether authorization responses must carry the issuer identifier.
    #[must_use]
    pub const fn authorization_response_issuer_required(&self) -> bool {
        self.authorization_response_issuer_required
    }

    /// Whether the OAuth client must authenticate at protected AS endpoints.
    #[must_use]
    pub const fn oauth_client_authentication_required(&self) -> bool {
        self.oauth_client_authentication_required
    }

    /// Whether request-encryption support is mandatory.
    #[must_use]
    pub const fn request_encryption_support_required(&self) -> bool {
        self.request_encryption_support_required
    }

    /// Whether every request must be encrypted.
    #[must_use]
    pub const fn request_encryption_required(&self) -> bool {
        self.request_encryption_required
    }

    /// Whether response-encryption support is mandatory.
    #[must_use]
    pub const fn response_encryption_support_required(&self) -> bool {
        self.response_encryption_support_required
    }

    /// Whether every response must be encrypted.
    #[must_use]
    pub const fn response_encryption_required(&self) -> bool {
        self.response_encryption_required
    }

    /// Whether key-binding configurations conditionally require a nonce endpoint.
    #[must_use]
    pub const fn nonce_endpoint_required_for_key_binding(&self) -> bool {
        self.nonce_endpoint_required_for_key_binding
    }

    /// Whether the profile is relevant to eIDAS deployments.
    #[must_use]
    pub const fn is_eidas_relevant(&self) -> bool {
        self.eidas_relevant
    }
}
