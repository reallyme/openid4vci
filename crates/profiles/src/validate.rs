// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer profile policy validation.

use core::fmt;

use openid4vci_types::{CredentialFormat, IssuerMetadata};

use crate::define::ProfilePolicy;

/// Result type for issuer-profile policy validation.
pub type ProfilePolicyResult<T> = Result<T, ProfilePolicyError>;

/// Deterministic profile-policy failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{status}")]
pub struct ProfilePolicyError {
    status: ProfilePolicyStatus,
}

impl ProfilePolicyError {
    /// Creates a policy error from a stable status code.
    #[must_use]
    pub const fn new(status: ProfilePolicyStatus) -> Self {
        Self { status }
    }

    /// Returns the stable profile-policy status code.
    #[must_use]
    pub const fn status(self) -> ProfilePolicyStatus {
        self.status
    }
}

/// Stable issuer-profile policy status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilePolicyStatus {
    /// At least one credential configuration must be advertised.
    CredentialConfigurationRequired,
    /// A credential format is outside the profile allow-list.
    UnsupportedCredentialFormat,
    /// The profile requires a scope on every credential configuration.
    CredentialConfigurationScopeRequired,
    /// The profile requires holder proof metadata or enforcement.
    ProofRequired,
    /// The profile requires the final-spec Nonce Endpoint.
    NonceEndpointRequired,
    /// The profile requires key-attestation policy for binding keys.
    KeyAttestationRequired,
    /// The profile requires wallet attestation.
    WalletAttestationRequired,
    /// The profile requires DPoP-bound authorization.
    DpopRequired,
    /// The profile requires PAR for authorization-code issuance.
    ParRequired,
    /// The profile requires the OAuth Authorization Code grant.
    AuthorizationCodeGrantRequired,
    /// The profile requires PKCE using `S256`.
    PkceS256Required,
    /// The profile requires issuer identification in authorization responses.
    AuthorizationResponseIssuerRequired,
    /// The profile requires OAuth client authentication.
    OauthClientAuthenticationRequired,
    /// The profile requires advertised credential request encryption support.
    RequestEncryptionSupportRequired,
    /// The profile requires mandatory credential request encryption.
    RequestEncryptionRequired,
    /// The profile requires advertised credential response encryption support.
    ResponseEncryptionSupportRequired,
    /// The profile requires mandatory credential response encryption.
    ResponseEncryptionRequired,
}

impl fmt::Display for ProfilePolicyStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::CredentialConfigurationRequired => "credential_configuration_required",
            Self::UnsupportedCredentialFormat => "unsupported_credential_format",
            Self::CredentialConfigurationScopeRequired => "credential_configuration_scope_required",
            Self::ProofRequired => "proof_required",
            Self::NonceEndpointRequired => "nonce_endpoint_required",
            Self::KeyAttestationRequired => "key_attestation_required",
            Self::WalletAttestationRequired => "wallet_attestation_required",
            Self::DpopRequired => "dpop_required",
            Self::ParRequired => "par_required",
            Self::AuthorizationCodeGrantRequired => "authorization_code_grant_required",
            Self::PkceS256Required => "pkce_s256_required",
            Self::AuthorizationResponseIssuerRequired => "authorization_response_issuer_required",
            Self::OauthClientAuthenticationRequired => "oauth_client_authentication_required",
            Self::RequestEncryptionSupportRequired => "request_encryption_support_required",
            Self::RequestEncryptionRequired => "request_encryption_required",
            Self::ResponseEncryptionSupportRequired => "response_encryption_support_required",
            Self::ResponseEncryptionRequired => "response_encryption_required",
        };
        formatter.write_str(value)
    }
}

/// Observed issuer capabilities for evaluating a profile policy.
///
/// Metadata can prove advertised formats, nonce support, proof metadata, and
/// encryption support. HTTP/OAuth controls such as wallet attestation, DPoP,
/// and PAR are intentionally supplied by adapters or tests because they are
/// enforcement behavior, not static Credential Issuer Metadata fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerProfileRequirements {
    /// Credential formats advertised or enforced for this issuer surface.
    pub credential_formats: Vec<CredentialFormat>,
    /// Whether every credential configuration carries an OAuth scope.
    pub credential_configuration_scopes_present: bool,
    /// Whether holder proof metadata or enforcement is present.
    pub proof_required: bool,
    /// Whether the final-spec Nonce Endpoint is present.
    pub nonce_endpoint_present: bool,
    /// Whether any configuration advertises cryptographic holder binding.
    pub key_binding_supported: bool,
    /// Whether key attestation is required for binding keys.
    pub key_attestation_required: bool,
    /// Whether wallet attestation enforcement is present.
    pub wallet_attestation_required: bool,
    /// Whether DPoP enforcement is present.
    pub dpop_required: bool,
    /// Whether PAR enforcement is present for authorization-code flows.
    pub par_required: bool,
    /// Whether the Authorization Code grant is supported.
    pub authorization_code_grant_supported: bool,
    /// Whether PKCE with `S256` is required for authorization-code requests.
    pub pkce_s256_required: bool,
    /// Whether authorization responses carry the AS issuer identifier.
    pub authorization_response_issuer_required: bool,
    /// Whether OAuth client authentication is enforced at AS endpoints.
    pub oauth_client_authentication_required: bool,
    /// Whether credential request encryption is supported.
    pub request_encryption_supported: bool,
    /// Whether credential request encryption is mandatory.
    pub request_encryption_required: bool,
    /// Whether credential response encryption is supported.
    pub response_encryption_supported: bool,
    /// Whether credential response encryption is mandatory.
    pub response_encryption_required: bool,
}

impl IssuerProfileRequirements {
    /// Derives profile-observable requirements from Credential Issuer Metadata.
    #[must_use]
    pub fn from_metadata(metadata: &IssuerMetadata) -> Self {
        let credential_formats = metadata
            .credential_configurations_supported
            .values()
            .map(|configuration| configuration.format.clone())
            .collect();
        let proof_required = metadata
            .credential_configurations_supported
            .values()
            .all(|configuration| configuration.supports_proofs());
        let credential_configuration_scopes_present = metadata
            .credential_configurations_supported
            .values()
            .all(|configuration| configuration.scope.is_some());
        let key_attestation_required =
            metadata
                .credential_configurations_supported
                .values()
                .all(|configuration| {
                    configuration
                        .proof_types_supported
                        .as_ref()
                        .is_some_and(|proof_types| {
                            proof_types
                                .values()
                                .all(|proof| proof.key_attestations_required.is_some())
                        })
                });
        let key_binding_supported =
            metadata
                .credential_configurations_supported
                .values()
                .any(|configuration| {
                    configuration
                        .cryptographic_binding_methods_supported
                        .as_ref()
                        .is_some_and(|methods| !methods.is_empty())
                });
        let request_encryption_required = metadata
            .credential_request_encryption
            .as_ref()
            .is_some_and(|encryption| encryption.encryption_required);
        let response_encryption_required = metadata
            .credential_response_encryption
            .as_ref()
            .is_some_and(|encryption| encryption.encryption_required);

        Self {
            credential_formats,
            credential_configuration_scopes_present,
            proof_required,
            nonce_endpoint_present: metadata.nonce_endpoint.is_some(),
            key_binding_supported,
            key_attestation_required,
            wallet_attestation_required: false,
            dpop_required: false,
            par_required: false,
            authorization_code_grant_supported: false,
            pkce_s256_required: false,
            authorization_response_issuer_required: false,
            oauth_client_authentication_required: false,
            request_encryption_supported: metadata.credential_request_encryption.is_some(),
            request_encryption_required,
            response_encryption_supported: metadata.credential_response_encryption.is_some(),
            response_encryption_required,
        }
    }

    /// Validates observed requirements against a static profile policy.
    pub fn validate_with_policy(&self, policy: &ProfilePolicy) -> ProfilePolicyResult<()> {
        if self.credential_formats.is_empty() {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::CredentialConfigurationRequired,
            ));
        }
        if self
            .credential_formats
            .iter()
            .any(|format| !policy.credential_formats.contains(format))
        {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::UnsupportedCredentialFormat,
            ));
        }
        if policy.credential_configuration_scope_required
            && !self.credential_configuration_scopes_present
        {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::CredentialConfigurationScopeRequired,
            ));
        }
        if policy.proof_required_for_every_configuration && !self.proof_required {
            return Err(ProfilePolicyError::new(ProfilePolicyStatus::ProofRequired));
        }
        if policy.nonce_endpoint_required_for_key_binding
            && self.key_binding_supported
            && !self.nonce_endpoint_present
        {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::NonceEndpointRequired,
            ));
        }
        if policy.key_attestation_required_for_every_proof && !self.key_attestation_required {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::KeyAttestationRequired,
            ));
        }
        if policy.wallet_attestation_format_required && !self.wallet_attestation_required {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::WalletAttestationRequired,
            ));
        }
        if policy.dpop_required && !self.dpop_required {
            return Err(ProfilePolicyError::new(ProfilePolicyStatus::DpopRequired));
        }
        if policy.par_required && !self.par_required {
            return Err(ProfilePolicyError::new(ProfilePolicyStatus::ParRequired));
        }
        if policy.authorization_code_grant_required && !self.authorization_code_grant_supported {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::AuthorizationCodeGrantRequired,
            ));
        }
        if policy.pkce_s256_required && !self.pkce_s256_required {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::PkceS256Required,
            ));
        }
        if policy.authorization_response_issuer_required
            && !self.authorization_response_issuer_required
        {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::AuthorizationResponseIssuerRequired,
            ));
        }
        if policy.oauth_client_authentication_required && !self.oauth_client_authentication_required
        {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::OauthClientAuthenticationRequired,
            ));
        }
        if policy.request_encryption_support_required && !self.request_encryption_supported {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::RequestEncryptionSupportRequired,
            ));
        }
        if policy.request_encryption_required && !self.request_encryption_required {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::RequestEncryptionRequired,
            ));
        }
        if policy.response_encryption_support_required && !self.response_encryption_supported {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::ResponseEncryptionSupportRequired,
            ));
        }
        if policy.response_encryption_required && !self.response_encryption_required {
            return Err(ProfilePolicyError::new(
                ProfilePolicyStatus::ResponseEncryptionRequired,
            ));
        }
        Ok(())
    }
}

impl ProfilePolicy {
    /// Validates issuer requirements against this profile.
    pub fn validate_issuer_requirements(
        &self,
        requirements: &IssuerProfileRequirements,
    ) -> ProfilePolicyResult<()> {
        requirements.validate_with_policy(self)
    }

    /// Validates metadata-observable issuer requirements against this profile.
    pub fn validate_metadata(&self, metadata: &IssuerMetadata) -> ProfilePolicyResult<()> {
        IssuerProfileRequirements::from_metadata(metadata).validate_with_policy(self)
    }
}
