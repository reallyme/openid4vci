// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use openid4vci_types::CredentialFormat;

use crate::policy::OpenId4VciProtocolPolicy;

#[test]
fn production_policy_uses_high_assurance_defaults() {
    let policy = OpenId4VciProtocolPolicy::production();

    assert_eq!(
        policy.credential_formats,
        vec![CredentialFormat::SdJwtVc, CredentialFormat::MsoMdoc]
    );
    assert!(policy.wallet_attestation_required);
    assert!(policy.key_attestation_required);
    assert!(policy.dpop_required);
    assert!(policy.par_required);
    assert!(policy.authorization_code_grant_required);
    assert!(policy.pkce_s256_required);
    assert!(policy.authorization_response_issuer_required);
    assert!(policy.oauth_client_authentication_required);
    assert!(policy.eidas_relevant);
}

#[cfg(feature = "http")]
#[test]
fn production_policy_maps_to_required_router_security_policy() {
    let policy = OpenId4VciProtocolPolicy::production();
    let router_policy = policy.axum_issuer_security_policy();

    assert_eq!(
        router_policy,
        openid4vci_http::AxumIssuerSecurityPolicy::new(true, true, true, true)
            .with_haip_authorization_server_controls()
    );
}

#[cfg(feature = "profiles")]
#[test]
fn production_policy_maps_to_profile_policy() {
    let policy = OpenId4VciProtocolPolicy::production().haip_profile_policy();

    assert_eq!(policy.profile(), openid4vci_profiles::IssuanceProfile::Haip);
    assert!(!policy.wallet_attestation_format_required());
    assert!(policy.is_eidas_relevant());
}

#[cfg(feature = "profiles")]
#[test]
fn production_policy_rejects_runtime_requirements_without_enforced_controls() {
    let requirements = openid4vci_profiles::IssuerProfileRequirements {
        credential_formats: vec![CredentialFormat::SdJwtVc],
        credential_configuration_scopes_present: true,
        proof_required: true,
        nonce_endpoint_present: true,
        key_binding_supported: true,
        key_attestation_required: true,
        wallet_attestation_required: false,
        dpop_required: true,
        par_required: true,
        authorization_code_grant_supported: true,
        pkce_s256_required: true,
        authorization_response_issuer_required: true,
        oauth_client_authentication_required: true,
        request_encryption_supported: true,
        request_encryption_required: false,
        response_encryption_supported: true,
        response_encryption_required: false,
    };

    assert_eq!(
        OpenId4VciProtocolPolicy::production()
            .validate_issuer_requirements(&requirements)
            .err()
            .map(openid4vci_profiles::ProfilePolicyError::status),
        Some(openid4vci_profiles::ProfilePolicyStatus::WalletAttestationRequired)
    );
}
