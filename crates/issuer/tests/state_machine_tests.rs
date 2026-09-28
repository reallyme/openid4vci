// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer state-transition tests over the pure endpoint engine.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use openid4vci_issuer::{
    handle_credential_request, handle_credential_request_body,
    handle_deferred_credential_request_body, handle_nonce_request, preflight_credential_request,
    ConfirmationJwk, CredentialEndpointConfig, CredentialIssuer, CredentialRequestInput,
    CredentialRequestJson, DeferredCredentialRequestInput, DeferredIssuance, DeferredIssuer,
    DeferredResolution, DeferredStore, InMemoryDeferredStore, IssuanceAuthorization,
    IssuanceOutcome, IssuedCredential, IssuerError, IssuerResult, IssuerStatus, ProofAlgorithm,
    ProofKind, ProofVerificationContext, ProofVerifier, VerifiedProof, VerifiedProofSet,
    MAX_NONCE_TTL_SECONDS,
};
use openid4vci_types::{
    CredentialEnvelope, CredentialFormat, CredentialRequest, CredentialResponse,
    CredentialResponseEncryption, CredentialResponseEncryptionMetadata, CredentialSelector,
    DeferredCredentialRequest, Proofs, PublicJwk,
};
use serde_json::{json, Value};

mod support;
use support::{authenticated_request_json, TestNonceManager};

#[path = "support/state_machine_doubles.rs"]
mod state_machine_doubles;
use state_machine_doubles::{
    CountingDeferredIssuer, RejectingZipResponseEncryptor, StoreBackedDeferredIssuer,
    TestResponseEncryptor,
};

const ISSUER: &str = "https://issuer.example";
const TEST_NONCE: &str = "nonce-1";

#[allow(clippy::panic)]
fn authorization() -> IssuanceAuthorization {
    IssuanceAuthorization::new("pid".to_owned(), "subject-1".to_owned(), [7_u8; 32])
        .unwrap_or_else(|error| panic!("test authorization must be valid: {error}"))
}

#[test]
fn preflight_then_issue_has_no_preflight_side_effect() -> IssuerResult<()> {
    let request = credential_request(Some(TEST_NONCE));
    let config = credential_config();
    let issuer = CountingIssuer::default();
    let nonce_manager = TestNonceManager::seeded(TEST_NONCE, 1_700_000_100);

    let preflight = preflight_credential_request(
        &authorization(),
        &request,
        &config,
        &NonceProofVerifier,
        1_700_000_000,
    )?;
    assert_eq!(preflight.binding_key_count, 1);
    assert_eq!(issuer.issue_count(), 0);

    handle_credential_request(
        &authorization(),
        &request,
        &config,
        &NonceProofVerifier,
        &issuer,
        &nonce_manager,
        1_700_000_000,
    )?;
    assert_eq!(issuer.issue_count(), 1);
    Ok(())
}

#[test]
fn authorization_context_must_match_requested_configuration() -> IssuerResult<()> {
    let request = credential_request(Some(TEST_NONCE));
    let issuer = CountingIssuer::default();
    let authorization =
        IssuanceAuthorization::new("different".to_owned(), "subject-1".to_owned(), [7_u8; 32])?;
    let result = handle_credential_request(
        &authorization,
        &request,
        &credential_config(),
        &NonceProofVerifier,
        &issuer,
        &TestNonceManager::seeded(TEST_NONCE, 1_700_000_100),
        1_700_000_000,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::UnsupportedCredential)
    );
    assert_eq!(issuer.issue_count(), 0);
    Ok(())
}

#[test]
fn nonce_then_credential_replay_is_forbidden_transition() -> IssuerResult<()> {
    let store = TestNonceManager::empty();
    let nonce = handle_nonce_request(&store, 10, 60)?;
    assert_eq!(nonce.c_nonce, TEST_NONCE);

    let request = credential_request(Some(TEST_NONCE));
    let config = credential_config();
    handle_credential_request(
        &authorization(),
        &request,
        &config,
        &NonceProofVerifier,
        &CountingIssuer::default(),
        &store,
        11,
    )?;

    let replay = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &NonceProofVerifier,
        &CountingIssuer::default(),
        &store,
        12,
    );
    assert_eq!(
        replay.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn expired_nonce_rejects_credential_transition() -> IssuerResult<()> {
    let store = TestNonceManager::empty();
    let nonce = handle_nonce_request(&store, 10, 1)?;
    assert_eq!(nonce.c_nonce, TEST_NONCE);

    let request = credential_request(Some(TEST_NONCE));
    let result = handle_credential_request(
        &authorization(),
        &request,
        &credential_config(),
        &NonceProofVerifier,
        &CountingIssuer::default(),
        &store,
        12,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn nonce_lifetime_is_bounded_before_store_allocation() {
    let store = TestNonceManager::empty();
    let result = handle_nonce_request(&store, 10, MAX_NONCE_TTL_SECONDS + 1);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidRequest)
    );
}

#[test]
fn mixed_batch_nonces_are_rejected_before_consumption() {
    let mut request = credential_request(Some(TEST_NONCE));
    request.proofs = Some(Proofs {
        jwt: vec![TEST_NONCE.to_owned(), "nonce-2".to_owned()],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    });
    let mut config = credential_config();
    config.max_batch_size = Some(2);
    let nonce_manager = CountingNonceManager::default();

    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &MixedNonceProofVerifier,
        &CountingIssuer::default(),
        &nonce_manager,
        11,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    assert_eq!(nonce_manager.consume_count.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_response_encryption_is_rejected_before_nonce_or_issuance() -> IssuerResult<()> {
    let mut request = credential_request(Some(TEST_NONCE));
    request.credential_response_encryption = Some(encryption_with_zip());
    let config = encryption_credential_config();
    let issuer = CountingIssuer::default();
    let nonce_manager = TestNonceManager::seeded(TEST_NONCE, 1_700_000_100);

    let result = handle_credential_request_body(
        &authorization(),
        &credential_input(&request, true)?,
        &config,
        &NonceProofVerifier,
        &issuer,
        &RejectingZipResponseEncryptor,
        &nonce_manager,
        1_700_000_000,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    assert_eq!(issuer.issue_count(), 0);

    let mut retry = request;
    retry
        .credential_response_encryption
        .as_mut()
        .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidRequest))?
        .zip = None;
    handle_credential_request_body(
        &authorization(),
        &credential_input(&retry, true)?,
        &config,
        &NonceProofVerifier,
        &issuer,
        &TestResponseEncryptor,
        &nonce_manager,
        1_700_000_000,
    )?;
    assert_eq!(issuer.issue_count(), 1);
    Ok(())
}

#[test]
fn unadvertised_response_compression_is_rejected_before_nonce_or_issuance() -> IssuerResult<()> {
    let mut request = credential_request(Some(TEST_NONCE));
    request.credential_response_encryption = Some(encryption_with_zip());
    let mut config = encryption_credential_config();
    if let Some(metadata) = config.response_encryption_metadata.as_mut() {
        metadata.zip_values_supported = None;
    }
    let issuer = CountingIssuer::default();
    let nonce_manager = TestNonceManager::seeded(TEST_NONCE, 1_700_000_100);

    let result = handle_credential_request_body(
        &authorization(),
        &credential_input(&request, true)?,
        &config,
        &NonceProofVerifier,
        &issuer,
        &TestResponseEncryptor,
        &nonce_manager,
        1_700_000_000,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    assert_eq!(issuer.issue_count(), 0);

    let mut retry = request;
    retry
        .credential_response_encryption
        .as_mut()
        .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidRequest))?
        .zip = None;
    handle_credential_request_body(
        &authorization(),
        &credential_input(&retry, true)?,
        &config,
        &NonceProofVerifier,
        &issuer,
        &TestResponseEncryptor,
        &nonce_manager,
        1_700_000_000,
    )?;
    assert_eq!(issuer.issue_count(), 1);
    Ok(())
}

#[test]
fn invalid_deferred_encryption_is_rejected_before_transaction_resolution() -> IssuerResult<()> {
    let issuer = CountingDeferredIssuer::default();
    let mut request = deferred_request("ready-1");
    request.credential_response_encryption = Some(encryption_with_zip());

    let result = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&request, true)?,
        &encryption_credential_config(),
        &issuer,
        &RejectingZipResponseEncryptor,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    assert_eq!(issuer.resolve_count.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn plaintext_credential_request_is_rejected_before_all_side_effects_when_encryption_is_required(
) -> IssuerResult<()> {
    let config = CredentialEndpointConfig {
        request_encryption_required: true,
        ..credential_config()
    };
    let verifier = CountingProofVerifier::default();
    let issuer = CountingIssuer::default();
    let nonces = CountingNonceManager::default();
    let result = handle_credential_request_body(
        &authorization(),
        &credential_input(&credential_request(Some(TEST_NONCE)), false)?,
        &config,
        &verifier,
        &issuer,
        &TestResponseEncryptor,
        &nonces,
        1_700_000_000,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncryptionRequired)
    );
    assert_eq!(verifier.verify_count.load(Ordering::SeqCst), 0);
    assert_eq!(issuer.issue_count(), 0);
    assert_eq!(nonces.consume_count.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn plaintext_deferred_request_is_rejected_before_store_resolution_when_encryption_is_required(
) -> IssuerResult<()> {
    let config = CredentialEndpointConfig {
        request_encryption_required: true,
        ..credential_config()
    };
    let issuer = CountingDeferredIssuer::default();
    let result = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&deferred_request("ready-1"), false)?,
        &config,
        &issuer,
        &TestResponseEncryptor,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncryptionRequired)
    );
    assert_eq!(issuer.resolve_count.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn deferred_polling_preserves_pending_and_completed_states() -> IssuerResult<()> {
    let config = credential_config();
    let issuer = DeterministicDeferredIssuer;
    let encryptor = TestResponseEncryptor;

    let pending = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&deferred_request("pending-1"), false)?,
        &config,
        &issuer,
        &encryptor,
    )?;
    assert!(pending.is_deferred());

    let completed = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&deferred_request("ready-1"), false)?,
        &config,
        &issuer,
        &encryptor,
    )?;
    assert!(!completed.is_deferred());
    Ok(())
}

#[test]
fn deferred_retry_preserves_transaction_and_interval() -> IssuerResult<()> {
    let config = credential_config();
    let issuer = DeterministicDeferredIssuer;
    let encryptor = TestResponseEncryptor;

    let first = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&deferred_request("pending-1"), false)?,
        &config,
        &issuer,
        &encryptor,
    )?;
    let retry = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&deferred_request("pending-1"), false)?,
        &config,
        &issuer,
        &encryptor,
    )?;
    assert!(first.is_deferred());
    assert_eq!(first, retry);
    Ok(())
}

#[test]
fn deferred_response_rejects_unadvertised_compression_before_resolution() -> IssuerResult<()> {
    let config = CredentialEndpointConfig {
        response_encryption_metadata: Some(CredentialResponseEncryptionMetadata {
            alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
            enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            zip_values_supported: None,
            encryption_required: false,
        }),
        ..credential_config()
    };
    let request = DeferredCredentialRequest {
        transaction_id: "ready-1".to_owned(),
        credential_response_encryption: Some(CredentialResponseEncryption {
            jwk: public_jwk(json!({"kty":"EC","alg":"ECDH-ES"}))?,
            enc: "A256GCM".to_owned(),
            zip: Some("DEF".to_owned()),
        }),
    };

    let issuer = CountingDeferredIssuer::default();
    let result = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&request, true)?,
        &config,
        &issuer,
        &RejectingZipResponseEncryptor,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    assert_eq!(issuer.resolve_count.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn deferred_poll_uses_fresh_response_encryption_key() -> IssuerResult<()> {
    let config = CredentialEndpointConfig {
        response_encryption_metadata: Some(CredentialResponseEncryptionMetadata {
            alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
            enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            zip_values_supported: None,
            encryption_required: false,
        }),
        ..credential_config()
    };
    let request = DeferredCredentialRequest {
        transaction_id: "ready-1".to_owned(),
        credential_response_encryption: Some(CredentialResponseEncryption {
            jwk: public_jwk(json!({
                "kty":"EC",
                "alg":"ECDH-ES",
                "crv":"P-256",
                "x":"fresh-x",
                "y":"fresh-y"
            }))?,
            enc: "A256GCM".to_owned(),
            zip: None,
        }),
    };

    let response = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&request, true)?,
        &config,
        &DeterministicDeferredIssuer,
        &TestResponseEncryptor,
    )?;
    assert!(matches!(
        response,
        openid4vci_issuer::CredentialResponseBody::Jwt { .. }
    ));
    Ok(())
}

#[test]
fn restored_deferred_transaction_completes_once_then_replay_fails() -> IssuerResult<()> {
    let store = InMemoryDeferredStore::new();
    let record = DeferredIssuance::new(
        credential_request(None),
        vec![IssuedCredential::new(
            CredentialFormat::SdJwtVc,
            Value::String("credential.jwt".to_owned()),
        )?],
    )?;
    store.put("restored-1", record, 1_000, 2_000)?;

    let issuer = StoreBackedDeferredIssuer { store: &store };
    let first = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&deferred_request("restored-1"), false)?,
        &credential_config(),
        &issuer,
        &TestResponseEncryptor,
    )?;
    assert!(!first.is_deferred());

    let replay = handle_deferred_credential_request_body(
        &authorization(),
        &deferred_input(&deferred_request("restored-1"), false)?,
        &credential_config(),
        &issuer,
        &TestResponseEncryptor,
    );
    assert_eq!(
        replay.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidTransaction)
    );
    Ok(())
}

fn credential_request(nonce: Option<&str>) -> CredentialRequest {
    let proof = nonce.unwrap_or("proof");
    CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec![proof.to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    }
}

fn credential_config() -> CredentialEndpointConfig {
    CredentialEndpointConfig {
        credential_issuer: ISSUER.to_owned(),
        proof_required: true,
        accepted_proof_algorithms: vec![
            openid4vci_issuer::ProofAlgorithm::EdDsa,
            openid4vci_issuer::ProofAlgorithm::Es256,
            openid4vci_issuer::ProofAlgorithm::Es256k,
        ],
        accepted_attestation_proof_algorithms: vec![
            openid4vci_issuer::ProofAlgorithm::EdDsa,
            openid4vci_issuer::ProofAlgorithm::Es256,
            openid4vci_issuer::ProofAlgorithm::Es256k,
        ],
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

fn encryption_credential_config() -> CredentialEndpointConfig {
    CredentialEndpointConfig {
        response_encryption_required: true,
        response_encryption_metadata: Some(CredentialResponseEncryptionMetadata {
            alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
            enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            zip_values_supported: Some(vec!["DEF".to_owned()]),
            encryption_required: true,
        }),
        ..credential_config()
    }
}

fn encryption_with_zip() -> CredentialResponseEncryption {
    let jwk = match public_jwk(json!({
        "kty": "EC",
        "alg": "ECDH-ES",
        "crv": "P-256",
        "x": "f83OJ3D2xF4BFGZAzA-Rir6S3oS0wA-KM3K-E7d96cw",
        "y": "x_FEzRu9m36HLNFx9J5xWuP8Nw81bq9cc2LFeY6-DPM"
    })) {
        Ok(jwk) => jwk,
        Err(_) => std::process::abort(),
    };
    CredentialResponseEncryption {
        jwk,
        enc: "A256GCM".to_owned(),
        zip: Some("DEF".to_owned()),
    }
}

fn public_jwk(value: Value) -> IssuerResult<PublicJwk> {
    PublicJwk::new(value).map_err(|_| IssuerError::new(IssuerStatus::InvalidEncryptionParameters))
}

fn credential_input(
    request: &CredentialRequest,
    authenticated_encryption: bool,
) -> IssuerResult<CredentialRequestInput> {
    let json = serde_json::to_string(request)
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
    request_json(json, authenticated_encryption)?.parse_credential_request()
}

fn deferred_input(
    request: &DeferredCredentialRequest,
    authenticated_encryption: bool,
) -> IssuerResult<DeferredCredentialRequestInput> {
    let json = serde_json::to_string(request)
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
    request_json(json, authenticated_encryption)?.parse_deferred_credential_request()
}

fn request_json(
    json: String,
    authenticated_encryption: bool,
) -> IssuerResult<CredentialRequestJson> {
    if authenticated_encryption {
        authenticated_request_json(json)
    } else {
        CredentialRequestJson::new(json)
    }
}

fn deferred_request(transaction_id: &str) -> DeferredCredentialRequest {
    DeferredCredentialRequest {
        transaction_id: transaction_id.to_owned(),
        credential_response_encryption: None,
    }
}

#[derive(Default)]
struct CountingIssuer {
    issue_count: AtomicUsize,
}

impl CountingIssuer {
    fn issue_count(&self) -> usize {
        self.issue_count.load(Ordering::SeqCst)
    }
}

impl CredentialIssuer for CountingIssuer {
    fn issue(
        &self,
        _authorization: &IssuanceAuthorization,
        _request: &CredentialRequest,
        _selector: &CredentialSelector,
        _verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome> {
        self.issue_count.fetch_add(1, Ordering::SeqCst);
        CredentialResponse::immediate(
            vec![CredentialEnvelope::compact("credential".to_owned())],
            Some("notification-1".to_owned()),
        )
        .map(IssuanceOutcome::Immediate)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
    }
}

struct NonceProofVerifier;

impl ProofVerifier for NonceProofVerifier {
    fn verify(
        &self,
        _proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        VerifiedProofSet::new(vec![verified_proof(TEST_NONCE, 1)?], Vec::new())
    }
}

#[derive(Default)]
struct CountingProofVerifier {
    verify_count: AtomicUsize,
}

impl ProofVerifier for CountingProofVerifier {
    fn verify(
        &self,
        _proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        self.verify_count.fetch_add(1, Ordering::SeqCst);
        VerifiedProofSet::new(vec![verified_proof(TEST_NONCE, 1)?], Vec::new())
    }
}

#[derive(Default)]
struct CountingNonceManager {
    consume_count: AtomicUsize,
}

impl openid4vci_issuer::NonceManager for CountingNonceManager {
    fn issue(&self, _now_unix: u64, _ttl_seconds: u64) -> IssuerResult<String> {
        Ok(TEST_NONCE.to_owned())
    }

    fn consume(
        &self,
        _nonce: &str,
        _replay_partition: &[u8; 32],
        _now_unix: u64,
    ) -> IssuerResult<()> {
        self.consume_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct MixedNonceProofVerifier;

impl ProofVerifier for MixedNonceProofVerifier {
    fn verify(
        &self,
        _proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        VerifiedProofSet::new(
            vec![
                verified_proof(TEST_NONCE, 1)?,
                verified_proof("nonce-2", 2)?,
            ],
            Vec::new(),
        )
    }
}

fn verified_proof(nonce: &str, key_byte: u8) -> IssuerResult<VerifiedProof> {
    VerifiedProof::new(
        ProofKind::Jwt,
        Some(nonce.to_owned()),
        Some(ISSUER.to_owned()),
        None,
        None,
        Some(json!({"kty": "EC", "x": key_byte})),
        Some(ConfirmationJwk {
            algorithm: ProofAlgorithm::Es256,
            public_key: vec![key_byte; 65],
            key_id: None,
        }),
    )
}

struct DeterministicDeferredIssuer;

impl DeferredIssuer for DeterministicDeferredIssuer {
    fn resolve_deferred(
        &self,
        _authorization: &IssuanceAuthorization,
        transaction_id: &str,
    ) -> IssuerResult<DeferredResolution> {
        let outcome = match transaction_id {
            "pending-1" => CredentialResponse::deferred("pending-1".to_owned(), 5)
                .map(IssuanceOutcome::Deferred)
                .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed)),
            "ready-1" => CredentialResponse::immediate(
                vec![CredentialEnvelope::compact("credential".to_owned())],
                None,
            )
            .map(IssuanceOutcome::Immediate)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed)),
            _ => Err(IssuerError::new(IssuerStatus::InvalidTransaction)),
        }?;
        Ok(DeferredResolution::new(outcome))
    }
}
