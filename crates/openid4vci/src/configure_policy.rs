// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDK-facing OpenID4VCI protocol policy.
//!
//! This is a declarative profile template, not evidence that a runtime has
//! enforced the controls. A composed issuer must validate its observed
//! [`openid4vci_profiles::IssuerProfileRequirements`] before serving traffic.

use openid4vci_types::CredentialFormat;

/// Unified OpenID4VCI protocol policy for SDK and platform facades.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenId4VciProtocolPolicy {
    /// Accepted credential formats for the issuance profile.
    pub credential_formats: Vec<CredentialFormat>,
    /// Require wallet attestation client authentication at protected issuer
    /// boundaries.
    pub wallet_attestation_required: bool,
    /// Require key attestation for holder binding keys before issuing.
    pub key_attestation_required: bool,
    /// Require DPoP sender-constrained access tokens.
    pub dpop_required: bool,
    /// Require PAR for authorization-code issuance flows.
    pub par_required: bool,
    /// Require support for the OAuth Authorization Code grant.
    pub authorization_code_grant_required: bool,
    /// Require PKCE with `S256` for authorization-code requests.
    pub pkce_s256_required: bool,
    /// Require issuer identification in authorization responses.
    pub authorization_response_issuer_required: bool,
    /// Require OAuth client authentication at authorization-server endpoints.
    pub oauth_client_authentication_required: bool,
    /// Whether this policy is intended for eIDAS-relevant high-assurance use.
    pub eidas_relevant: bool,
}

impl OpenId4VciProtocolPolicy {
    /// Return the strict policy template used by production composition.
    #[must_use]
    pub fn production() -> Self {
        Self::reallyme_high_assurance()
    }

    /// Returns ReallyMe's high-assurance deployment overlay.
    ///
    /// This overlay deliberately requires wallet and key attestation for the
    /// local deployment. Those are stricter ecosystem choices and are not
    /// mislabeled as universal HAIP requirements.
    #[must_use]
    pub fn reallyme_high_assurance() -> Self {
        Self {
            credential_formats: high_assurance_credential_formats(),
            wallet_attestation_required: true,
            key_attestation_required: true,
            dpop_required: true,
            par_required: true,
            authorization_code_grant_required: true,
            pkce_s256_required: true,
            authorization_response_issuer_required: true,
            oauth_client_authentication_required: true,
            eidas_relevant: true,
        }
    }

    /// Returns ReallyMe's EUDI PID deployment overlay.
    #[must_use]
    pub fn reallyme_eudi_pid_deployment() -> Self {
        Self {
            credential_formats: high_assurance_credential_formats(),
            wallet_attestation_required: true,
            key_attestation_required: true,
            dpop_required: true,
            par_required: true,
            authorization_code_grant_required: true,
            pkce_s256_required: true,
            authorization_response_issuer_required: true,
            oauth_client_authentication_required: true,
            eidas_relevant: true,
        }
    }

    /// Converts this profile into the mandatory Axum construction policy.
    ///
    /// Passing this value into `AxumIssuerParts` makes the adapter verify that
    /// the declared DPoP, wallet-attestation, key-attestation, and PAR controls
    /// are present before any route can be served.
    #[cfg(feature = "http")]
    #[must_use]
    pub const fn axum_issuer_security_policy(&self) -> openid4vci_http::AxumIssuerSecurityPolicy {
        openid4vci_http::AxumIssuerSecurityPolicy::new(
            self.dpop_required,
            self.wallet_attestation_required,
            self.key_attestation_required,
            self.par_required,
        )
        .with_haip_authorization_server_controls()
    }

    /// Convert to the profile policy type when the profile crate is enabled.
    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn haip_profile_policy(self) -> openid4vci_profiles::ProfilePolicy {
        openid4vci_profiles::haip_policy()
    }

    /// Convert to the EUDI PID profile policy type when profiles are enabled.
    #[cfg(feature = "profiles")]
    #[must_use]
    pub fn eudi_pid_profile_policy(self) -> openid4vci_profiles::ProfilePolicy {
        openid4vci_profiles::eudi_pid_policy()
    }

    /// Validates metadata and adapter-observed controls against this policy.
    ///
    /// The caller must derive `requirements` from the actual issuer metadata
    /// and runtime adapters. This keeps high-assurance defaults connected to
    /// deployed DPoP, PAR, wallet-attestation, proof, and encryption controls
    /// instead of treating construction of a policy value as enforcement.
    #[cfg(feature = "profiles")]
    pub fn validate_issuer_requirements(
        self,
        requirements: &openid4vci_profiles::IssuerProfileRequirements,
    ) -> openid4vci_profiles::ProfilePolicyResult<()> {
        openid4vci_profiles::haip_policy().validate_issuer_requirements(requirements)?;
        let status =
            if self.wallet_attestation_required && !requirements.wallet_attestation_required {
                Some(openid4vci_profiles::ProfilePolicyStatus::WalletAttestationRequired)
            } else if self.key_attestation_required && !requirements.key_attestation_required {
                Some(openid4vci_profiles::ProfilePolicyStatus::KeyAttestationRequired)
            } else if self.dpop_required && !requirements.dpop_required {
                Some(openid4vci_profiles::ProfilePolicyStatus::DpopRequired)
            } else if self.par_required && !requirements.par_required {
                Some(openid4vci_profiles::ProfilePolicyStatus::ParRequired)
            } else if self.authorization_code_grant_required
                && !requirements.authorization_code_grant_supported
            {
                Some(openid4vci_profiles::ProfilePolicyStatus::AuthorizationCodeGrantRequired)
            } else if self.pkce_s256_required && !requirements.pkce_s256_required {
                Some(openid4vci_profiles::ProfilePolicyStatus::PkceS256Required)
            } else if self.authorization_response_issuer_required
                && !requirements.authorization_response_issuer_required
            {
                Some(openid4vci_profiles::ProfilePolicyStatus::AuthorizationResponseIssuerRequired)
            } else if self.oauth_client_authentication_required
                && !requirements.oauth_client_authentication_required
            {
                Some(openid4vci_profiles::ProfilePolicyStatus::OauthClientAuthenticationRequired)
            } else {
                None
            };
        match status {
            Some(status) => Err(openid4vci_profiles::ProfilePolicyError::new(status)),
            None => Ok(()),
        }
    }
}

impl Default for OpenId4VciProtocolPolicy {
    fn default() -> Self {
        Self::production()
    }
}

fn high_assurance_credential_formats() -> Vec<CredentialFormat> {
    vec![CredentialFormat::SdJwtVc, CredentialFormat::MsoMdoc]
}

#[path = "tests/configure_policy_tests.rs"]
#[cfg(test)]
mod configure_policy_tests;
