// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure issuer endpoint behavior tests.

use std::collections::BTreeMap;

use openid4vci_issuer::{
    handle_credential_request, handle_credential_request_body, ConfirmationJwk,
    CredentialEndpointConfig, CredentialIssuer, CredentialRequestInput, CredentialRequestJson,
    CredentialResponseEncryptor, EncryptedCredentialResponse, IssuanceAuthorization,
    IssuanceOutcome, IssuerError, IssuerResult, IssuerStatus, ProofAlgorithm, ProofKind,
    ProofVerificationContext, ProofVerifier, VerifiedProof, VerifiedProofSet,
};
use openid4vci_types::{
    CredentialConfiguration, CredentialEnvelope, CredentialFormat, CredentialRequest,
    CredentialResponse, CredentialResponseEncryption, CredentialSelector, IssuerMetadata,
    KeyAttestationsRequired, ProofTypeMetadata, Proofs,
};
use serde_json::json;

mod support;
use support::{authenticated_request_json, TestNonceManager};

const TEST_NONCE: &str = "c-nonce-1";

/// A fresh manager seeded with the nonce returned by the accepting verifier.
fn nonce_manager() -> TestNonceManager {
    TestNonceManager::seeded(TEST_NONCE, 100)
}

#[allow(clippy::panic)]
fn authorization() -> IssuanceAuthorization {
    IssuanceAuthorization::new("pid".to_owned(), "subject-1".to_owned(), [7_u8; 32])
        .unwrap_or_else(|error| panic!("test authorization must be valid: {error}"))
}

fn default_config() -> CredentialEndpointConfig {
    let algorithms = vec![
        openid4vci_issuer::ProofAlgorithm::EdDsa,
        openid4vci_issuer::ProofAlgorithm::Es256,
        openid4vci_issuer::ProofAlgorithm::Es256k,
    ];
    CredentialEndpointConfig {
        credential_issuer: "https://issuer.example".to_owned(),
        proof_required: true,
        accepted_attestation_proof_algorithms: algorithms.clone(),
        accepted_proof_algorithms: algorithms,
        key_attestation_required: false,
        key_attestation_policy: None,
        key_attestation_local_policy: None,
        proof_type_policies: BTreeMap::new(),
        nonce_required: true,
        request_encryption_required: false,
        max_batch_size: None,
        response_encryption_required: false,
        response_encryption_metadata: None,
    }
}

/// Proof verifier that reports a fixed `c_nonce` on every verified proof, used
/// to exercise the endpoint's single-use nonce consumption.
struct FixedNonceProofVerifier {
    nonce: &'static str,
}

impl ProofVerifier for FixedNonceProofVerifier {
    fn verify(
        &self,
        proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        let proof_count = if proofs.jwt.is_empty() {
            proofs.attestation.len()
        } else {
            proofs.jwt.len()
        };
        let mut verified = Vec::with_capacity(proof_count);
        for index in 0..proof_count {
            let key_byte =
                u8::try_from(index).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
            verified.push(VerifiedProof::new(
                ProofKind::Jwt,
                Some(self.nonce.to_owned()),
                None,
                None,
                None,
                Some(json!({"kty": "EC", "x": key_byte})),
                Some(ConfirmationJwk {
                    algorithm: ProofAlgorithm::Es256,
                    public_key: vec![key_byte; 65],
                    key_id: None,
                }),
            )?);
        }
        VerifiedProofSet::new(verified, Vec::new())
    }
}

fn request_input(
    request: &CredentialRequest,
    authenticated_encryption: bool,
) -> IssuerResult<CredentialRequestInput> {
    let json = serde_json::to_string(request)
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
    let body = if authenticated_encryption {
        authenticated_request_json(json)?
    } else {
        CredentialRequestJson::new(json)?
    };
    body.parse_credential_request()
}

fn mixed_proof_config(reverse_insertion: bool) -> IssuerResult<CredentialEndpointConfig> {
    let jwt = (
        "jwt".to_owned(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["EdDSA".to_owned()],
            key_attestations_required: None,
        },
    );
    let attestation = (
        "attestation".to_owned(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_owned()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: Some(vec!["high".to_owned()]),
                user_authentication: None,
                preferred_key_storage_status_period: None,
            }),
        },
    );
    let mut proof_types = BTreeMap::new();
    if reverse_insertion {
        proof_types.insert(attestation.0, attestation.1);
        proof_types.insert(jwt.0, jwt.1);
    } else {
        proof_types.insert(jwt.0, jwt.1);
        proof_types.insert(attestation.0, attestation.1);
    }
    let metadata = IssuerMetadata::builder(
        "https://issuer.example".to_owned(),
        "https://issuer.example/credential".to_owned(),
    )
    .credential_configuration(
        "pid".to_owned(),
        CredentialConfiguration {
            proof_types_supported: Some(proof_types),
            ..CredentialConfiguration::new(CredentialFormat::SdJwtVc)
        },
    )
    .build()
    .map_err(|_| IssuerError::new(IssuerStatus::InvalidProofPolicy))?;
    let local = openid4vci_issuer::KeyAttestationLocalPolicy::new(300, 5)?;
    CredentialEndpointConfig::from_metadata(&metadata, "pid", Some(local))
}

#[test]
fn mixed_proof_policy_is_selected_by_submitted_type_independent_of_map_order() -> IssuerResult<()> {
    for reverse_insertion in [false, true] {
        let config = mixed_proof_config(reverse_insertion)?;
        assert!(config
            .proof_type_policies
            .get(&ProofKind::Jwt)
            .is_some_and(|policy| {
                policy.key_attestation_policy.is_none()
                    && policy.accepted_algorithms == [ProofAlgorithm::EdDsa]
            }));
        assert!(config
            .proof_type_policies
            .get(&ProofKind::Attestation)
            .is_some_and(|policy| {
                policy.key_attestation_policy.is_some()
                    && policy.accepted_algorithms == [ProofAlgorithm::Es256]
            }));

        let jwt_request = CredentialRequest {
            credential_configuration_id: Some("pid".to_owned()),
            credential_identifier: None,
            proofs: Some(Proofs {
                jwt: vec!["a.b.c".to_owned()],
                di_vp: Vec::new(),
                attestation: Vec::new(),
            }),
            credential_response_encryption: None,
        };
        assert!(handle_credential_request(
            &authorization(),
            &jwt_request,
            &config,
            &AcceptingProofVerifier,
            &ImmediateIssuer,
            &nonce_manager(),
            10,
        )
        .is_ok());

        let attestation_request = CredentialRequest {
            credential_configuration_id: Some("pid".to_owned()),
            credential_identifier: None,
            proofs: Some(Proofs {
                jwt: Vec::new(),
                di_vp: Vec::new(),
                attestation: vec!["a.b.c".to_owned()],
            }),
            credential_response_encryption: None,
        };
        assert_eq!(
            handle_credential_request(
                &authorization(),
                &attestation_request,
                &config,
                &AcceptingProofVerifier,
                &ImmediateIssuer,
                &nonce_manager(),
                10,
            )
            .err()
            .map(|error| error.status()),
            Some(IssuerStatus::InvalidProof)
        );
    }
    Ok(())
}

/// A trusted-provider contract violation must still fail before issuance. This
/// does not make the provider untrusted; it prevents an accidental proof-family
/// substitution from bypassing the metadata policy selected for the request.
struct SubstitutingProofVerifier;

impl ProofVerifier for SubstitutingProofVerifier {
    fn verify(
        &self,
        _proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        VerifiedProofSet::new(
            vec![VerifiedProof::new(
                ProofKind::Attestation,
                Some(TEST_NONCE.to_owned()),
                None,
                None,
                None,
                Some(json!({"kty": "EC", "x": 1})),
                Some(ConfirmationJwk {
                    algorithm: ProofAlgorithm::Es256,
                    public_key: vec![1_u8; 65],
                    key_id: None,
                }),
            )?],
            Vec::new(),
        )
    }
}

struct RejectIfCalledIssuer;

impl CredentialIssuer for RejectIfCalledIssuer {
    fn issue(
        &self,
        _authorization: &IssuanceAuthorization,
        _request: &CredentialRequest,
        _selector: &CredentialSelector,
        _verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome> {
        Err(IssuerError::new(IssuerStatus::EncodingFailed))
    }
}

#[test]
fn endpoint_rejects_verified_proof_type_substitution_before_issuance() -> IssuerResult<()> {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };

    let result = handle_credential_request(
        &authorization(),
        &request,
        &mixed_proof_config(false)?,
        &SubstitutingProofVerifier,
        &RejectIfCalledIssuer,
        &nonce_manager(),
        10,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn endpoint_consumes_c_nonce_single_use() -> IssuerResult<()> {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = default_config();
    let verifier = FixedNonceProofVerifier { nonce: "c-nonce-1" };
    let store = TestNonceManager::seeded("c-nonce-1", 100);

    // First issuance consumes the server-issued nonce.
    handle_credential_request(
        &authorization(),
        &request,
        &config,
        &verifier,
        &ImmediateIssuer,
        &store,
        10,
    )?;

    // Replaying the same request fails because the nonce is already consumed.
    let replay = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &verifier,
        &ImmediateIssuer,
        &store,
        10,
    );
    assert_eq!(
        replay.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn endpoint_rejects_missing_key_attestation_when_required() {
    // HAIP high-assurance: a plain JWT proof (no key attestation) is rejected
    // when the profile requires key attestation.
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let mut config = default_config();
    config.key_attestation_required = true;
    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &nonce_manager(),
        0,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
}

#[test]
fn endpoint_rejects_untrusted_attestation_coverage_claim() {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: Vec::new(),
            di_vp: Vec::new(),
            attestation: vec!["a.b.c".to_owned()],
        }),
        credential_response_encryption: None,
    };
    let mut config = default_config();
    config.key_attestation_required = true;
    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &nonce_manager(),
        0,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
}

#[test]
fn endpoint_rejects_unknown_c_nonce() {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = default_config();
    // The proof carries a nonce the issuer never issued (empty store).
    let verifier = FixedNonceProofVerifier {
        nonce: "attacker-chosen",
    };
    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &verifier,
        &ImmediateIssuer,
        &nonce_manager(),
        10,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
}

struct AcceptingProofVerifier;

impl ProofVerifier for AcceptingProofVerifier {
    fn verify(
        &self,
        proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        let proof_count = if proofs.jwt.is_empty() {
            proofs.attestation.len()
        } else {
            proofs.jwt.len()
        };
        let kind = if proofs.attestation.is_empty() {
            ProofKind::Jwt
        } else {
            ProofKind::Attestation
        };
        let mut verified = Vec::with_capacity(proof_count);
        for index in 0..proof_count {
            let key_byte =
                u8::try_from(index).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
            verified.push(VerifiedProof::new(
                kind,
                Some(TEST_NONCE.to_owned()),
                None,
                None,
                None,
                Some(json!({"kty": "EC", "x": key_byte})),
                Some(ConfirmationJwk {
                    algorithm: ProofAlgorithm::Es256,
                    public_key: vec![key_byte; 65],
                    key_id: None,
                }),
            )?);
        }
        VerifiedProofSet::new(verified, Vec::new())
    }
}

struct ImmediateIssuer;

impl CredentialIssuer for ImmediateIssuer {
    fn issue(
        &self,
        _authorization: &IssuanceAuthorization,
        _request: &CredentialRequest,
        _selector: &CredentialSelector,
        _verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome> {
        let response = CredentialResponse::immediate(
            vec![CredentialEnvelope::compact("credential".to_owned())],
            Some("notification-1".to_owned()),
        )
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        Ok(IssuanceOutcome::Immediate(response))
    }
}

#[test]
fn endpoint_rejects_proofs_over_batch_size() {
    // Two key proofs when batch issuance is not offered (max_batch_size None => 1)
    // must be rejected before any signature verification.
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned(), "d.e.f".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = default_config();
    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &nonce_manager(),
        0,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
}

#[test]
fn endpoint_reports_unknown_credential_identifier_for_identifier_selector() {
    // An unknown credential accessed via `credential_identifier` yields the
    // identifier-specific error code, not the configuration one.
    let request = CredentialRequest {
        credential_configuration_id: None,
        credential_identifier: Some("unknown-id".to_owned()),
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = default_config();
    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &AcceptingProofVerifier,
        &UnsupportedIssuer,
        &nonce_manager(),
        0,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::UnknownCredentialIdentifier)
    );
}

/// Issuer double that always reports the requested credential as unknown.
struct UnsupportedIssuer;

impl CredentialIssuer for UnsupportedIssuer {
    fn issue(
        &self,
        _authorization: &IssuanceAuthorization,
        _request: &CredentialRequest,
        _selector: &CredentialSelector,
        _verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome> {
        Err(IssuerError::new(IssuerStatus::UnsupportedCredential))
    }
}

struct PendingDeferredIssuer;

impl CredentialIssuer for PendingDeferredIssuer {
    fn issue(
        &self,
        _authorization: &IssuanceAuthorization,
        _request: &CredentialRequest,
        _selector: &CredentialSelector,
        _verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome> {
        let response = CredentialResponse::deferred("transaction-1".to_owned(), 5)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        Ok(IssuanceOutcome::Deferred(response))
    }
}

#[test]
fn immediate_response_body_is_not_marked_deferred() -> IssuerResult<()> {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = default_config();
    let body = handle_credential_request_body(
        &authorization(),
        &request_input(&request, false)?,
        &config,
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &TestResponseEncryptor,
        &nonce_manager(),
        0,
    )?;
    assert!(!body.is_deferred());
    Ok(())
}

#[test]
fn pending_deferred_response_body_is_marked_deferred() -> IssuerResult<()> {
    // A still-pending deferred response (transaction_id, no credentials) must be
    // marked deferred so the HTTP adapter serializes it with status 202.
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = default_config();
    let body = handle_credential_request_body(
        &authorization(),
        &request_input(&request, false)?,
        &config,
        &AcceptingProofVerifier,
        &PendingDeferredIssuer,
        &TestResponseEncryptor,
        &nonce_manager(),
        0,
    )?;
    assert!(body.is_deferred());
    Ok(())
}

struct TestResponseEncryptor;

impl CredentialResponseEncryptor for TestResponseEncryptor {
    fn validate_parameters(&self, _encryption: &CredentialResponseEncryption) -> IssuerResult<()> {
        Ok(())
    }

    fn encrypt_response(
        &self,
        _response: &CredentialResponse,
        _encryption: &CredentialResponseEncryption,
    ) -> IssuerResult<EncryptedCredentialResponse> {
        EncryptedCredentialResponse::new("a.b.c.d.e".to_owned())
    }
}

#[test]
fn endpoint_requires_proof_when_configured() {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: None,
        credential_response_encryption: None,
    };
    let config = default_config();
    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &nonce_manager(),
        0,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::ProofRequired)
    );
}

#[test]
fn endpoint_issues_immediate_response_with_verified_proof() -> IssuerResult<()> {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = default_config();
    let response = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &nonce_manager(),
        0,
    )?;
    assert_eq!(response.notification_id.as_deref(), Some("notification-1"));
    Ok(())
}

#[test]
fn endpoint_rejects_direct_immediate_response_with_mismatched_proof_count() {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned(), "d.e.f".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = CredentialEndpointConfig {
        // Batch of 2 is within the ceiling, so the request reaches issuance and
        // is rejected for the credential/proof count mismatch, not the batch bound.
        max_batch_size: Some(2),
        ..default_config()
    };

    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &nonce_manager(),
        0,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
}
