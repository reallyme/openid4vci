// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key-attestation proof verifier tests.

use std::sync::Arc;

use openid4vci_attestation::{
    AttackPotentialResistance, AttestationError, AttestationResult, AttestationStatus,
    KeyAttestationAlgorithm, KeyAttestationJwt, KeyAttestationStatusEvidence,
    KeyAttestationTrustEvidenceInput, KeyAttestationTrustPurpose, KeyAttestationTrustVerifier,
    ParsedKeyAttestation,
};
use openid4vci_issuer::{
    IssuerStatus, KeyAttestationLocalPolicy, KeyAttestationPolicy, KeyAttestationProofVerifier,
    ProofAlgorithm, ProofKind, ProofVerificationContext, ProofVerifier,
};
use openid4vci_types::{CredentialSelector, KeyAttestationsRequired, ProofTypeMetadata, Proofs};
use reallyme_codec::base64url::bytes_to_base64url;
use serde_json::{json, Value};
use thiserror::Error;

const ISSUER: &str = "https://issuer.example";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
enum AttestationProofTestError {
    #[error("json")]
    Json,
    #[error("attestation")]
    Attestation,
}

struct AcceptingTrustVerifier;

impl KeyAttestationTrustVerifier for AcceptingTrustVerifier {
    fn verify_key_attestation(
        &self,
        _jwt: &KeyAttestationJwt,
        _parsed: &ParsedKeyAttestation,
    ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
        accepted_trust_evidence(_parsed)
    }
}

#[test]
fn key_attestation_proof_verifier_accepts_direct_attestation(
) -> Result<(), AttestationProofTestError> {
    let proofs = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec![key_attestation_jwt(Some("nonce-1"))?],
    };

    let verified = verifier().verify(&proofs, &context(true)?)?;

    assert_eq!(verified.binding_key_count(), 1);
    assert!(verified.includes_key_attestation());
    assert_eq!(verified.proofs().len(), 1);
    assert_eq!(verified.proofs()[0].kind(), ProofKind::Attestation);
    assert_eq!(verified.proofs()[0].nonce(), Some("nonce-1"));
    assert_eq!(
        verified.proofs()[0].public_jwk(),
        Some(&attested_key("key-1"))
    );
    assert_eq!(verified.key_attestations().len(), 1);
    assert_eq!(
        verified.key_attestations()[0].key_storage(),
        Some([AttackPotentialResistance::Iso18045Moderate].as_slice())
    );
    assert_eq!(
        verified.key_attestations()[0]
            .certification()
            .map(|value| value.as_str()),
        Some("https://certification.example/key-storage")
    );
    assert!(verified.key_attestations()[0].status().is_some());
    Ok(())
}

#[test]
fn direct_attestation_exposes_every_attested_key_for_credential_binding(
) -> Result<(), AttestationProofTestError> {
    let proofs = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec![key_attestation_jwt_with_keys(
            Some("nonce-1"),
            vec![attested_key("key-1"), attested_key("key-2")],
        )?],
    };

    let verified = verifier().verify(&proofs, &context(true)?)?;

    assert_eq!(verified.binding_key_count(), 2);
    assert_eq!(verified.proofs().len(), 2);
    assert_eq!(verified.proofs()[0].key_id(), Some("key-1"));
    assert_eq!(verified.proofs()[1].key_id(), Some("key-2"));
    assert!(verified
        .proofs()
        .iter()
        .all(|proof| proof.public_jwk().is_some()));
    Ok(())
}

#[test]
fn direct_attestation_enforces_security_property_policy() -> Result<(), AttestationProofTestError> {
    let proofs = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec![key_attestation_jwt(Some("nonce-1"))?],
    };
    let mut verification_context = context(true)?;
    let metadata = attestation_metadata("ES256", Some("iso_18045_high"));
    let local = KeyAttestationLocalPolicy::new(300, 60)?
        .require_certification()
        .require_status();
    verification_context.key_attestation_policy = Some(
        KeyAttestationPolicy::from_metadata_and_local_policy(&metadata, local)?,
    );

    let result = verifier().verify(&proofs, &verification_context);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::AttestationSecurityPropertiesRejected)
    );
    Ok(())
}

#[test]
fn direct_attestation_preserves_algorithm_policy_rejection_reason(
) -> Result<(), AttestationProofTestError> {
    let proofs = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec![key_attestation_jwt(Some("nonce-1"))?],
    };
    let mut verification_context = context(true)?;
    verification_context.key_attestation_policy = Some(KeyAttestationPolicy::from_proof_metadata(
        &attestation_metadata("EdDSA", None),
        300,
        60,
    )?);

    let result = verifier().verify(&proofs, &verification_context);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::AttestationAlgorithmRejected)
    );
    Ok(())
}

#[test]
fn key_attestation_policy_is_derived_from_selected_proof_metadata(
) -> Result<(), AttestationProofTestError> {
    let metadata = ProofTypeMetadata {
        proof_signing_alg_values_supported: vec!["ES256".to_owned(), "ES256".to_owned()],
        key_attestations_required: Some(KeyAttestationsRequired {
            key_storage: Some(vec!["iso_18045_moderate".to_owned()]),
            user_authentication: Some(vec!["future_registry_value".to_owned()]),
            preferred_key_storage_status_period: None,
        }),
    };

    let policy = KeyAttestationPolicy::from_proof_metadata(&metadata, 300, 60)?;
    assert_eq!(
        policy.accepted_algorithms(),
        [KeyAttestationAlgorithm::Es256]
    );
    assert_eq!(
        policy.accepted_key_storage(),
        Some([AttackPotentialResistance::Iso18045Moderate].as_slice())
    );
    assert!(policy
        .accepted_user_authentication()
        .and_then(|values| values.first())
        .is_some_and(|value| !value.is_registered()));
    Ok(())
}

#[test]
fn key_attestation_policy_rejects_unimplemented_advertised_algorithm() {
    let metadata = ProofTypeMetadata {
        proof_signing_alg_values_supported: vec!["RS256".to_owned()],
        key_attestations_required: Some(KeyAttestationsRequired {
            key_storage: None,
            user_authentication: None,
            preferred_key_storage_status_period: None,
        }),
    };

    assert_eq!(
        KeyAttestationPolicy::from_proof_metadata(&metadata, 300, 60)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidProofPolicy)
    );
}

#[test]
fn key_attestation_proof_verifier_rejects_missing_nonce() -> Result<(), AttestationProofTestError> {
    let proofs = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec![key_attestation_jwt(None)?],
    };

    let result = verifier().verify(&proofs, &context(true)?);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn key_attestation_proof_verifier_rejects_trust_failure() -> Result<(), AttestationProofTestError> {
    struct RejectingTrustVerifier;

    impl KeyAttestationTrustVerifier for RejectingTrustVerifier {
        fn verify_key_attestation(
            &self,
            _jwt: &KeyAttestationJwt,
            _parsed: &ParsedKeyAttestation,
        ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
            Err(AttestationError::new(AttestationStatus::TrustRejected))
        }
    }

    let proofs = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec![key_attestation_jwt(Some("nonce-1"))?],
    };
    let verifier = KeyAttestationProofVerifier::new(Arc::new(RejectingTrustVerifier));

    let result = verifier.verify(&proofs, &context(true)?);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::AttestationTrustRejected)
    );
    Ok(())
}

#[test]
fn key_attestation_proof_verifier_rejects_mixed_proof_types(
) -> Result<(), AttestationProofTestError> {
    let proofs = Proofs {
        jwt: vec!["a.b.c".to_owned()],
        di_vp: Vec::new(),
        attestation: vec![key_attestation_jwt(Some("nonce-1"))?],
    };

    let result = verifier().verify(&proofs, &context(true)?);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

fn verifier() -> KeyAttestationProofVerifier {
    KeyAttestationProofVerifier::new(Arc::new(AcceptingTrustVerifier))
}

fn context(nonce_required: bool) -> Result<ProofVerificationContext, AttestationProofTestError> {
    Ok(ProofVerificationContext {
        credential_issuer: ISSUER.to_owned(),
        selector: CredentialSelector::ConfigurationId("pid".to_owned()),
        client_id: None,
        accepted_proof_algorithms: vec![
            ProofAlgorithm::EdDsa,
            ProofAlgorithm::Es256,
            ProofAlgorithm::Es256k,
        ],
        nonce_required,
        current_time: 1_700_000_000,
        key_attestation_policy: Some(KeyAttestationPolicy::from_proof_metadata(
            &attestation_metadata("ES256", None),
            300,
            60,
        )?),
    })
}

fn attestation_metadata(algorithm: &str, key_storage: Option<&str>) -> ProofTypeMetadata {
    ProofTypeMetadata {
        proof_signing_alg_values_supported: vec![algorithm.to_owned()],
        key_attestations_required: Some(KeyAttestationsRequired {
            key_storage: key_storage.map(|value| vec![value.to_owned()]),
            user_authentication: None,
            preferred_key_storage_status_period: None,
        }),
    }
}

fn key_attestation_jwt(nonce: Option<&str>) -> Result<String, AttestationProofTestError> {
    key_attestation_jwt_with_keys(nonce, vec![attested_key("key-1")])
}

fn key_attestation_jwt_with_keys(
    nonce: Option<&str>,
    attested_keys: Vec<Value>,
) -> Result<String, AttestationProofTestError> {
    let mut claims = json!({
        "iat": 1_699_999_999_i64,
        "exp": 1_700_000_100_i64,
        "key_storage": ["iso_18045_moderate"],
        "user_authentication": ["iso_18045_high"],
        "certification": "https://certification.example/key-storage",
        "status": {"status_list": {"idx": 7}},
        "attested_keys": attested_keys
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = Value::String(nonce.to_owned());
    }
    compact_jwt(
        &json!({
            "typ": "key-attestation+jwt",
            "alg": "ES256",
            "kid": "key-attester-1"
        }),
        &claims,
    )
}

fn attested_key(key_id: &str) -> Value {
    if key_id == "key-1" {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": key_id,
            "x": "B_zLQ0UJb5Yhcm_E5De-DPgcQxCB8yjlVJZyOaxVIu4",
            "y": "DZcUdT7G939Veqc3FCadWs_rcpS-vc_8Z8FaZREVX4A"
        })
    } else {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": key_id,
            "x": "bd_77DacquIWpfuZCAps4BN5nYvqANOYBNepDXNQLYI"
        })
    }
}

fn accepted_trust_evidence(
    parsed: &ParsedKeyAttestation,
) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
    let status = if parsed.status().is_some() {
        KeyAttestationStatusEvidence::Valid {
            evaluated_at: 1_700_000_000,
        }
    } else {
        KeyAttestationStatusEvidence::NotPresent
    };
    Ok(KeyAttestationTrustEvidenceInput {
        verified_signing_input: parsed.signing_input().to_owned(),
        signer_identity: "attester.example".to_owned(),
        policy_version: "policy-v1".to_owned(),
        source_snapshot: "snapshot-1".to_owned(),
        anchor: "anchor-1".to_owned(),
        evaluated_at: 1_700_000_000,
        valid_until: 1_700_000_600,
        purpose: KeyAttestationTrustPurpose::CredentialBinding,
        status,
    })
}

fn compact_jwt(header: &Value, claims: &Value) -> Result<String, AttestationProofTestError> {
    let header_json = serde_json::to_vec(header).map_err(|_| AttestationProofTestError::Json)?;
    let claims_json = serde_json::to_vec(claims).map_err(|_| AttestationProofTestError::Json)?;
    Ok([
        bytes_to_base64url(&header_json),
        bytes_to_base64url(&claims_json),
        bytes_to_base64url(b"signature"),
    ]
    .join("."))
}

impl From<openid4vci_issuer::IssuerError> for AttestationProofTestError {
    fn from(_error: openid4vci_issuer::IssuerError) -> Self {
        Self::Attestation
    }
}
