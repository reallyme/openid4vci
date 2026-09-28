// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HAIP and EUDI PID issuer profile policy tests.

use std::collections::BTreeMap;

use openid4vci_profiles::{
    eudi_pid_policy, haip_policy, IssuanceProfile, IssuerProfileRequirements, ProfilePolicyStatus,
    HAIP_PROFILE_NAME,
};
use openid4vci_types::{
    CredentialConfiguration, CredentialFormat, CredentialRequestEncryptionMetadata,
    CredentialResponseEncryptionMetadata, KeyAttestationsRequired, OpenId4VciResult,
    ProofTypeMetadata, PublicJwk, PublicJwkSet,
};
use serde_json::json;

fn request_encryption_jwks() -> OpenId4VciResult<PublicJwkSet> {
    PublicJwkSet::new(vec![PublicJwk::new(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF4",
        "y": "x_FEzRu9",
        "kid": "request-encryption-1",
        "alg": "ECDH-ES"
    }))?])
}

#[test]
fn haip_is_eidas_relevant_high_assurance_profile() {
    let policy = haip_policy();

    assert_eq!(policy.profile(), IssuanceProfile::Haip);
    assert_eq!(
        policy.profile().display_name(),
        "OpenID4VC High Assurance Interoperability Profile"
    );
    assert_eq!(policy.profile().display_name(), HAIP_PROFILE_NAME);
    assert!(policy.profile().is_eidas_relevant());
    assert!(policy.is_eidas_relevant());
    assert!(policy.credential_configuration_scope_required());
    assert!(!policy.proof_required_for_every_configuration());
    assert!(!policy.wallet_attestation_format_required());
    assert!(!policy.key_attestation_required_for_every_proof());
    assert!(policy.dpop_required());
    assert!(policy.par_required());
    assert!(policy.authorization_code_grant_required());
    assert!(policy.pkce_s256_required());
    assert!(policy.authorization_response_issuer_required());
    assert!(policy.oauth_client_authentication_required());
    assert!(policy.nonce_endpoint_required_for_key_binding());
    assert!(!policy.request_encryption_support_required());
    assert!(!policy.request_encryption_required());
    assert!(!policy.response_encryption_support_required());
    assert!(!policy.response_encryption_required());
    assert_eq!(
        policy.credential_formats(),
        [CredentialFormat::SdJwtVc, CredentialFormat::MsoMdoc]
    );
}

#[test]
fn eudi_pid_policy_is_eidas_relevant_high_assurance_issuance_profile() {
    let policy = eudi_pid_policy();

    assert_eq!(policy.profile(), IssuanceProfile::EudiPid);
    assert_eq!(policy.profile().display_name(), "EUDI PID Profile");
    assert_eq!(policy.profile().short_name(), "EUDI-PID");
    assert!(policy.profile().is_eidas_relevant());
    assert!(policy.is_eidas_relevant());
    assert!(policy.credential_configuration_scope_required());
    assert!(!policy.proof_required_for_every_configuration());
    assert!(!policy.wallet_attestation_format_required());
    assert!(!policy.key_attestation_required_for_every_proof());
    assert!(policy.dpop_required());
    assert!(policy.par_required());
    assert!(policy.authorization_code_grant_required());
    assert!(policy.pkce_s256_required());
    assert!(policy.authorization_response_issuer_required());
    assert!(policy.oauth_client_authentication_required());
    assert!(policy.nonce_endpoint_required_for_key_binding());
    assert!(!policy.request_encryption_support_required());
    assert!(!policy.request_encryption_required());
    assert!(!policy.response_encryption_support_required());
    assert!(!policy.response_encryption_required());
    assert_eq!(
        policy.credential_formats(),
        [CredentialFormat::SdJwtVc, CredentialFormat::MsoMdoc]
    );
}

#[test]
fn haip_policy_accepts_complete_issuer_requirements() {
    let policy = haip_policy();
    let requirements = complete_requirements();

    assert!(policy.validate_issuer_requirements(&requirements).is_ok());
}

#[test]
fn haip_policy_rejects_unsupported_issuer_format() {
    let policy = haip_policy();
    let mut requirements = complete_requirements();
    requirements.credential_formats = vec![CredentialFormat::JwtVcJson];

    let result = policy.validate_issuer_requirements(&requirements);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(ProfilePolicyStatus::UnsupportedCredentialFormat)
    );
}

#[test]
fn haip_policy_requires_scope_conditional_nonce_and_oauth_security() {
    assert_profile_status(
        ProfilePolicyStatus::CredentialConfigurationScopeRequired,
        |requirements| {
            requirements.credential_configuration_scopes_present = false;
        },
    );
    assert_profile_status(ProfilePolicyStatus::NonceEndpointRequired, |requirements| {
        requirements.nonce_endpoint_present = false;
    });
    assert_profile_status(ProfilePolicyStatus::DpopRequired, |requirements| {
        requirements.dpop_required = false;
    });
    assert_profile_status(ProfilePolicyStatus::ParRequired, |requirements| {
        requirements.par_required = false;
    });
    assert_profile_status(
        ProfilePolicyStatus::AuthorizationCodeGrantRequired,
        |requirements| {
            requirements.authorization_code_grant_supported = false;
        },
    );
    assert_profile_status(ProfilePolicyStatus::PkceS256Required, |requirements| {
        requirements.pkce_s256_required = false;
    });
    assert_profile_status(
        ProfilePolicyStatus::AuthorizationResponseIssuerRequired,
        |requirements| {
            requirements.authorization_response_issuer_required = false;
        },
    );
    assert_profile_status(
        ProfilePolicyStatus::OauthClientAuthenticationRequired,
        |requirements| {
            requirements.oauth_client_authentication_required = false;
        },
    );
}

#[test]
fn haip_does_not_turn_optional_attestation_formats_into_universal_requirements() {
    let policy = eudi_pid_policy();
    let mut requirements = complete_requirements();
    requirements.proof_required = false;
    requirements.key_attestation_required = false;
    requirements.wallet_attestation_required = false;

    assert!(policy.validate_issuer_requirements(&requirements).is_ok());
}

#[test]
fn eudi_pid_policy_does_not_require_optional_encryption_extensions() {
    let policy = eudi_pid_policy();
    let mut requirements = complete_requirements();
    requirements.request_encryption_supported = false;
    requirements.response_encryption_supported = false;

    assert!(policy.validate_issuer_requirements(&requirements).is_ok());
}

#[test]
fn nonce_endpoint_is_not_required_without_key_binding() {
    let policy = haip_policy();
    let mut requirements = complete_requirements();
    requirements.key_binding_supported = false;
    requirements.nonce_endpoint_present = false;

    assert!(policy.validate_issuer_requirements(&requirements).is_ok());
}

#[test]
fn eudi_pid_policy_extracts_metadata_observable_requirements() -> OpenId4VciResult<()> {
    let metadata = openid4vci_types::IssuerMetadata::builder(
        "https://issuer.example.test".to_owned(),
        "https://issuer.example.test/credential".to_owned(),
    )
    .authorization_servers(vec!["https://as.example.test".to_owned()])
    .nonce_endpoint("https://issuer.example.test/nonce".to_owned())
    .credential_request_encryption(CredentialRequestEncryptionMetadata {
        alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
        enc_values_supported: vec!["A128GCM".to_owned()],
        zip_values_supported: None,
        jwks: request_encryption_jwks()?,
        encryption_required: false,
    })
    .credential_response_encryption(CredentialResponseEncryptionMetadata {
        alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
        enc_values_supported: Some(vec!["A128GCM".to_owned()]),
        zip_values_supported: None,
        encryption_required: false,
    })
    .credential_configuration(
        "pid".to_owned(),
        credential_configuration_with_key_attestation(CredentialFormat::SdJwtVc),
    )
    .build()?;

    let mut requirements = IssuerProfileRequirements::from_metadata(&metadata);
    requirements.wallet_attestation_required = true;
    requirements.dpop_required = true;
    requirements.par_required = true;
    requirements.authorization_code_grant_supported = true;
    requirements.pkce_s256_required = true;
    requirements.authorization_response_issuer_required = true;
    requirements.oauth_client_authentication_required = true;

    assert!(eudi_pid_policy()
        .validate_issuer_requirements(&requirements)
        .is_ok());
    Ok(())
}

#[test]
fn eudi_pid_policy_rejects_metadata_without_configuration_scope() -> OpenId4VciResult<()> {
    let metadata = openid4vci_types::IssuerMetadata::builder(
        "https://issuer.example.test".to_owned(),
        "https://issuer.example.test/credential".to_owned(),
    )
    .nonce_endpoint("https://issuer.example.test/nonce".to_owned())
    .credential_request_encryption(CredentialRequestEncryptionMetadata {
        alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
        enc_values_supported: vec!["A128GCM".to_owned()],
        zip_values_supported: None,
        jwks: request_encryption_jwks()?,
        encryption_required: false,
    })
    .credential_response_encryption(CredentialResponseEncryptionMetadata {
        alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
        enc_values_supported: Some(vec!["A128GCM".to_owned()]),
        zip_values_supported: None,
        encryption_required: false,
    })
    .credential_configuration(
        "pid".to_owned(),
        credential_configuration_without_scope(CredentialFormat::SdJwtVc),
    )
    .build()?;

    let mut requirements = IssuerProfileRequirements::from_metadata(&metadata);
    requirements.wallet_attestation_required = true;
    requirements.dpop_required = true;
    requirements.par_required = true;
    requirements.authorization_code_grant_supported = true;
    requirements.pkce_s256_required = true;
    requirements.authorization_response_issuer_required = true;
    requirements.oauth_client_authentication_required = true;

    let result = eudi_pid_policy().validate_issuer_requirements(&requirements);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(ProfilePolicyStatus::CredentialConfigurationScopeRequired)
    );
    Ok(())
}

fn complete_requirements() -> IssuerProfileRequirements {
    IssuerProfileRequirements {
        credential_formats: vec![CredentialFormat::SdJwtVc],
        credential_configuration_scopes_present: true,
        proof_required: true,
        nonce_endpoint_present: true,
        key_binding_supported: true,
        key_attestation_required: true,
        wallet_attestation_required: true,
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
    }
}

fn assert_profile_status(
    expected: ProfilePolicyStatus,
    mutate: impl FnOnce(&mut IssuerProfileRequirements),
) {
    let policy = eudi_pid_policy();
    let mut requirements = complete_requirements();
    mutate(&mut requirements);

    let result = policy.validate_issuer_requirements(&requirements);

    assert_eq!(result.err().map(|error| error.status()), Some(expected));
}

fn credential_configuration_with_key_attestation(
    format: CredentialFormat,
) -> CredentialConfiguration {
    let mut proof_types = BTreeMap::new();
    proof_types.insert(
        "jwt".to_owned(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_owned()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: Some(vec!["iso_18045_high".to_owned()]),
                user_authentication: Some(vec!["iso_18045_high".to_owned()]),
                preferred_key_storage_status_period: Some(86_400),
            }),
        },
    );

    let mut configuration = CredentialConfiguration::new(format);
    configuration.scope = Some("pid".to_owned());
    configuration.vct = Some("urn:eudi:pid:1".to_owned());
    configuration.proof_types_supported = Some(proof_types);
    configuration
}

fn credential_configuration_without_scope(format: CredentialFormat) -> CredentialConfiguration {
    let mut configuration = credential_configuration_with_key_attestation(format);
    configuration.scope = None;
    configuration
}
