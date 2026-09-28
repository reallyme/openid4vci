// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential endpoint request and response encryption policy tests.

use std::collections::BTreeMap;

use openid4vci_issuer::{
    handle_credential_request_body, preflight_credential_request, ConfirmationJwk,
    CredentialEndpointConfig, CredentialIssuer, CredentialRequestInput, CredentialRequestJson,
    CredentialResponseBody, CredentialResponseEncryptor, EncryptedCredentialResponse,
    IssuanceAuthorization, IssuanceOutcome, IssuerError, IssuerResult, IssuerStatus,
    ProofAlgorithm, ProofKind, ProofVerificationContext, ProofVerifier, VerifiedProof,
    VerifiedProofSet,
};
use openid4vci_types::{
    CredentialEnvelope, CredentialRequest, CredentialResponse, CredentialResponseEncryption,
    CredentialResponseEncryptionMetadata, CredentialSelector, Proofs, PublicJwk,
};
use serde_json::json;

mod support;
use support::{authenticated_request_json, TestNonceManager};

const TEST_NONCE: &str = "c-nonce-1";

fn nonce_manager() -> TestNonceManager {
    TestNonceManager::seeded(TEST_NONCE, 100)
}

#[allow(clippy::panic)]
fn authorization() -> IssuanceAuthorization {
    IssuanceAuthorization::new("pid".to_owned(), "subject-1".to_owned(), [7_u8; 32])
        .unwrap_or_else(|error| panic!("test authorization must be valid: {error}"))
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

fn public_jwk(value: serde_json::Value) -> IssuerResult<PublicJwk> {
    PublicJwk::new(value).map_err(|_| IssuerError::new(IssuerStatus::InvalidEncryptionParameters))
}

struct AcceptingProofVerifier;

impl ProofVerifier for AcceptingProofVerifier {
    fn verify(
        &self,
        proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        let mut verified = Vec::with_capacity(proofs.jwt.len());
        for index in 0..proofs.jwt.len() {
            let key_byte =
                u8::try_from(index).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
            verified.push(VerifiedProof::new(
                ProofKind::Jwt,
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

fn encrypted_request() -> IssuerResult<CredentialRequest> {
    Ok(CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: Some(CredentialResponseEncryption {
            jwk: public_jwk(json!({"kty":"EC","alg":"ECDH-ES"}))?,
            enc: "A256GCM".to_owned(),
            zip: None,
        }),
    })
}

fn encryption_config() -> CredentialEndpointConfig {
    CredentialEndpointConfig {
        credential_issuer: "https://issuer.example".to_owned(),
        proof_required: true,
        accepted_proof_algorithms: vec![
            ProofAlgorithm::EdDsa,
            ProofAlgorithm::Es256,
            ProofAlgorithm::Es256k,
        ],
        accepted_attestation_proof_algorithms: vec![
            ProofAlgorithm::EdDsa,
            ProofAlgorithm::Es256,
            ProofAlgorithm::Es256k,
        ],
        key_attestation_required: false,
        key_attestation_policy: None,
        key_attestation_local_policy: None,
        proof_type_policies: BTreeMap::new(),
        nonce_required: true,
        request_encryption_required: false,
        max_batch_size: None,
        response_encryption_required: true,
        response_encryption_metadata: Some(CredentialResponseEncryptionMetadata {
            alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
            enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            zip_values_supported: None,
            encryption_required: true,
        }),
    }
}

#[test]
fn endpoint_encrypts_response_when_wallet_supplies_parameters() -> IssuerResult<()> {
    let request = encrypted_request()?;
    let body = handle_credential_request_body(
        &authorization(),
        &request_input(&request, true)?,
        &encryption_config(),
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &TestResponseEncryptor,
        &nonce_manager(),
        0,
    )?;

    match body {
        CredentialResponseBody::Jwt { encrypted, .. } => {
            assert_eq!(encrypted.as_str(), "a.b.c.d.e")
        }
        CredentialResponseBody::Json(_) => {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
    }
    Ok(())
}

#[test]
fn encrypted_response_wrapper_rejects_non_compact_jwe() {
    let result = EncryptedCredentialResponse::new("a.b.c".to_owned());
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
}

#[test]
fn encrypted_response_debug_redacts_compact_jwe() -> IssuerResult<()> {
    let encrypted =
        EncryptedCredentialResponse::new("secret.header.ciphertext.tag.value".to_owned())?;
    let debug = format!("{encrypted:?}");
    assert!(!debug.contains("secret.header.ciphertext.tag.value"));
    assert!(debug.contains("<redacted>"));
    Ok(())
}

fn assert_encryption_rejected(request: &CredentialRequest) -> IssuerResult<()> {
    let result = handle_credential_request_body(
        &authorization(),
        &request_input(request, true)?,
        &encryption_config(),
        &AcceptingProofVerifier,
        &ImmediateIssuer,
        &TestResponseEncryptor,
        &nonce_manager(),
        0,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    Ok(())
}

#[test]
fn endpoint_rejects_response_encryption_without_jwk_alg() -> IssuerResult<()> {
    let mut request = encrypted_request()?;
    request.credential_response_encryption = Some(CredentialResponseEncryption {
        jwk: public_jwk(json!({"kty":"EC"}))?,
        enc: "A256GCM".to_owned(),
        zip: None,
    });
    assert_encryption_rejected(&request)
}

#[test]
fn endpoint_rejects_unsupported_response_encryption_alg() -> IssuerResult<()> {
    let mut request = encrypted_request()?;
    request.credential_response_encryption = Some(CredentialResponseEncryption {
        jwk: public_jwk(json!({"kty":"EC","alg":"RSA-OAEP"}))?,
        enc: "A256GCM".to_owned(),
        zip: None,
    });
    assert_encryption_rejected(&request)
}

#[test]
fn endpoint_rejects_unsupported_response_encryption_enc() -> IssuerResult<()> {
    let mut request = encrypted_request()?;
    request.credential_response_encryption = Some(CredentialResponseEncryption {
        jwk: public_jwk(json!({"kty":"EC","alg":"ECDH-ES"}))?,
        enc: "A128CBC-HS256".to_owned(),
        zip: None,
    });
    assert_encryption_rejected(&request)
}

#[test]
fn preflight_rejects_response_encryption_without_transport_provenance() -> IssuerResult<()> {
    let mut request = encrypted_request()?;
    request.proofs = Some(Proofs {
        jwt: vec!["a.b.c".to_owned(), "d.e.f".to_owned()],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    });
    let mut config = encryption_config();
    config.max_batch_size = Some(2);

    let result = preflight_credential_request(
        &authorization(),
        &request,
        &config,
        &AcceptingProofVerifier,
        1_700_000_000,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncryptionRequired)
    );
    Ok(())
}
