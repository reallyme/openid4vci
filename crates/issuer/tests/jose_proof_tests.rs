// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity-backed JWT proof verifier tests.

#![cfg(feature = "identity-jose")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use openid4vci_attestation::{
    AttackPotentialResistance, AttestationResult, KeyAttestationJwt, KeyAttestationStatusEvidence,
    KeyAttestationTrustEvidenceInput, KeyAttestationTrustPurpose, KeyAttestationTrustVerifier,
    ParsedKeyAttestation,
};
use openid4vci_issuer::{
    IssuerError, IssuerResult, IssuerStatus, JoseJwtProofVerifier, KeyAttestationPolicy,
    ProofAlgorithm, ProofKeyBinding, ProofKeyResolver, ProofVerificationContext, ProofVerifier,
};
use openid4vci_types::{CredentialSelector, KeyAttestationsRequired, ProofTypeMetadata, Proofs};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::{generate_keypair, sign};
use reallyme_crypto::ed25519::{generate_ed25519_keypair_from_seed, sign_ed25519};
use reallyme_crypto::jwk::{p256_public_key_to_jwk, JwkOptions};
use reallyme_crypto::p256::{decompress_public_key, p256_ecdsa_der_to_jose_signature};
use reallyme_jose::Jwk;
use serde_json::json;
use thiserror::Error;

#[path = "support/jose_proof_fixtures.rs"]
mod jose_proof_fixtures;
use jose_proof_fixtures::{
    kid_bound_proof, public_jwk_value, public_jwk_with_kid, x5c_bound_proof,
};

const ISSUER: &str = "https://issuer.example";
const NONCE: &str = "nonce-1";
const SEED: [u8; 32] = [7_u8; 32];
const OTHER_SEED: [u8; 32] = [9_u8; 32];
const PROOF_TYP: &str = "openid4vci-proof+jwt";
const RESOLVED_KEY_ID: &str = "did:example:issuer#key-1";
const X5C_LEAF: &str = "base64-der-leaf-certificate";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
enum JoseProofTestError {
    #[error("key")]
    Key,
    #[error("sign")]
    Sign,
    #[error("verify")]
    Verify,
}

#[test]
fn jose_verifier_accepts_signed_jwt_proof() -> Result<(), JoseProofTestError> {
    let jwt = proof_jwt(NONCE)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let verified = JoseJwtProofVerifier::new()
        .verify(&proofs, &context(true))
        .map_err(|_| JoseProofTestError::Verify)?;

    assert_eq!(verified.binding_key_count(), 1);
    assert_eq!(verified.proofs().len(), 1);
    assert_eq!(verified.proofs()[0].nonce(), Some(NONCE));
    assert_eq!(verified.proofs()[0].audience(), Some(ISSUER));
    Ok(())
}

#[test]
fn jose_verifier_binds_optional_issuer_claim_to_oauth_client() -> Result<(), JoseProofTestError> {
    let proofs = Proofs {
        jwt: vec![signed_proof(json!({
            "iss": "wallet-client",
            "aud": ISSUER,
            "nonce": NONCE,
            "iat": 1_700_000_000_u64
        }))?],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    let mut matching = context(true);
    matching.client_id = Some("wallet-client".to_owned());
    JoseJwtProofVerifier::new()
        .verify(&proofs, &matching)
        .map_err(|_| JoseProofTestError::Verify)?;

    let mut mismatching = context(true);
    mismatching.client_id = Some("other-client".to_owned());
    assert_eq!(
        JoseJwtProofVerifier::new()
            .verify(&proofs, &mismatching)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn jose_verifier_rejects_issuer_claim_for_anonymous_grant() -> Result<(), JoseProofTestError> {
    let proofs = Proofs {
        jwt: vec![signed_proof(json!({
            "iss": "wallet-client",
            "aud": ISSUER,
            "nonce": NONCE,
            "iat": 1_700_000_000_u64
        }))?],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    assert_eq!(
        JoseJwtProofVerifier::new()
            .verify(&proofs, &context(true))
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn jose_verifier_rejects_proof_algorithm_not_advertised_for_configuration(
) -> Result<(), JoseProofTestError> {
    let proofs = Proofs {
        jwt: vec![proof_jwt(NONCE)?],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    let mut verification_context = context(true);
    verification_context.accepted_proof_algorithms = vec![ProofAlgorithm::Es256];

    let result = JoseJwtProofVerifier::new().verify(&proofs, &verification_context);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn jose_verifier_normalizes_p256_confirmation_key_to_uncompressed_sec1(
) -> Result<(), JoseProofTestError> {
    let (jwt, expected_public_key) = p256_proof_jwt()?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let verified = JoseJwtProofVerifier::new()
        .verify(&proofs, &context(true))
        .map_err(|_| JoseProofTestError::Verify)?;
    let confirmation_key = verified
        .proofs()
        .first()
        .and_then(|proof| proof.confirmation_key())
        .ok_or(JoseProofTestError::Verify)?;

    assert_eq!(confirmation_key.public_key, expected_public_key);
    assert_eq!(confirmation_key.public_key.len(), 65);
    assert_eq!(confirmation_key.public_key.first().copied(), Some(0x04));
    Ok(())
}

#[test]
fn jose_verifier_accepts_kid_inside_embedded_jwk_without_top_level_kid(
) -> Result<(), JoseProofTestError> {
    let claims = json!({
        "aud": ISSUER,
        "nonce": NONCE,
        "iat": 1_700_000_000_u64
    });
    let header = json!({
        "alg": "EdDSA",
        "typ": PROOF_TYP,
        "jwk": public_jwk_with_kid(Some("wallet-binding-key"))?
    });
    let proofs = Proofs {
        jwt: vec![signed_proof_with_header(header, claims)?],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let verified = JoseJwtProofVerifier::new()
        .verify(&proofs, &context(true))
        .map_err(|_| JoseProofTestError::Verify)?;

    assert_eq!(verified.binding_key_count(), 1);
    Ok(())
}

#[test]
fn jose_verifier_rejects_tampered_signature() -> Result<(), JoseProofTestError> {
    let mut jwt = proof_jwt(NONCE)?;
    jwt.push('a');
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let result = JoseJwtProofVerifier::new().verify(&proofs, &context(true));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn jose_verifier_rejects_tampered_proof_before_attestation_trust() -> Result<(), JoseProofTestError>
{
    let key_attestation = key_attestation_jwt(vec![public_jwk_value(&SEED)?], Some(NONCE), true)?;
    let mut jwt = proof_jwt_with_key_attestation(NONCE, key_attestation)?;
    jwt.push('a');
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let verifier = CountingKeyAttestationVerifier {
        calls: Arc::clone(&calls),
    };

    let result = JoseJwtProofVerifier::new()
        .with_key_attestation_verifier(Arc::new(verifier))
        .verify(&proofs, &context(true));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn jose_verifier_rejects_missing_required_nonce() -> Result<(), JoseProofTestError> {
    let jwt = proof_jwt_without_nonce()?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let result = JoseJwtProofVerifier::new().verify(&proofs, &context(true));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn jose_verifier_accepts_fresh_proof_without_nonce_when_endpoint_is_absent(
) -> Result<(), JoseProofTestError> {
    let proofs = Proofs {
        jwt: vec![proof_jwt_without_nonce()?],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let verified = JoseJwtProofVerifier::new()
        .verify(&proofs, &context(false))
        .map_err(|_| JoseProofTestError::Verify)?;

    assert_eq!(verified.binding_key_count(), 1);
    assert_eq!(verified.proofs()[0].nonce(), None);
    Ok(())
}

#[test]
fn jose_verifier_accepts_header_key_attestation() -> Result<(), JoseProofTestError> {
    let key_attestation = key_attestation_jwt(vec![public_jwk_value(&SEED)?], Some(NONCE), true)?;
    let jwt = proof_jwt_with_key_attestation(NONCE, key_attestation)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let verified = JoseJwtProofVerifier::new()
        .with_key_attestation_verifier(Arc::new(TrustingKeyAttestationVerifier))
        .verify(&proofs, &context(true))
        .map_err(|_| JoseProofTestError::Verify)?;

    assert_eq!(verified.binding_key_count(), 1);
    assert!(verified.includes_key_attestation());
    assert_eq!(verified.key_attestations().len(), 1);
    assert_eq!(
        verified.key_attestations()[0].key_storage(),
        Some([AttackPotentialResistance::Iso18045Moderate].as_slice())
    );
    assert_eq!(
        verified.key_attestations()[0].user_authentication(),
        Some([AttackPotentialResistance::Iso18045High].as_slice())
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
fn jose_verifier_rejects_proof_algorithm_absent_from_attestation_metadata_policy(
) -> Result<(), JoseProofTestError> {
    let key_attestation = key_attestation_jwt(vec![public_jwk_value(&SEED)?], Some(NONCE), true)?;
    let jwt = proof_jwt_with_key_attestation(NONCE, key_attestation)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    let mut verification_context = context(true);
    let policy = verification_context
        .key_attestation_policy
        .as_mut()
        .ok_or(JoseProofTestError::Verify)?;
    *policy = key_attestation_policy_for_algorithm("ES256")?;

    let result = JoseJwtProofVerifier::new()
        .with_key_attestation_verifier(Arc::new(TrustingKeyAttestationVerifier))
        .verify(&proofs, &verification_context);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::AttestationAlgorithmRejected)
    );
    Ok(())
}

#[test]
fn jose_verifier_rejects_header_key_attestation_without_verifier() -> Result<(), JoseProofTestError>
{
    let key_attestation = key_attestation_jwt(vec![public_jwk_value(&SEED)?], Some(NONCE), true)?;
    let jwt = proof_jwt_with_key_attestation(NONCE, key_attestation)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let result = JoseJwtProofVerifier::new().verify(&proofs, &context(true));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn jose_verifier_rejects_header_key_attestation_for_different_key() -> Result<(), JoseProofTestError>
{
    let key_attestation =
        key_attestation_jwt(vec![public_jwk_value(&OTHER_SEED)?], Some(NONCE), true)?;
    let jwt = proof_jwt_with_key_attestation(NONCE, key_attestation)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let result = JoseJwtProofVerifier::new()
        .with_key_attestation_verifier(Arc::new(TrustingKeyAttestationVerifier))
        .verify(&proofs, &context(true));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn jose_verifier_rejects_header_key_attestation_without_exp() -> Result<(), JoseProofTestError> {
    let key_attestation = key_attestation_jwt(vec![public_jwk_value(&SEED)?], Some(NONCE), false)?;
    let jwt = proof_jwt_with_key_attestation(NONCE, key_attestation)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let result = JoseJwtProofVerifier::new()
        .with_key_attestation_verifier(Arc::new(TrustingKeyAttestationVerifier))
        .verify(&proofs, &context(true));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn jose_verifier_rejects_expired_header_key_attestation() -> Result<(), JoseProofTestError> {
    let key_attestation = key_attestation_jwt_with_exp(
        vec![public_jwk_value(&SEED)?],
        Some(NONCE),
        Some(1_700_000_000),
    )?;
    let jwt = proof_jwt_with_key_attestation(NONCE, key_attestation)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let result = JoseJwtProofVerifier::new()
        .with_key_attestation_verifier(Arc::new(TrustingKeyAttestationVerifier))
        .verify(&proofs, &context(true));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

/// Resolver that returns the shared test public key for a known `kid`.
struct TestKidResolver;

impl ProofKeyResolver for TestKidResolver {
    fn resolve(&self, binding: &ProofKeyBinding, _alg: &str) -> IssuerResult<Jwk> {
        match binding {
            ProofKeyBinding::Kid(kid) if kid == RESOLVED_KEY_ID => {
                public_jwk_with_kid(Some(RESOLVED_KEY_ID))
                    .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))
            }
            _ => Err(IssuerError::new(IssuerStatus::InvalidProof)),
        }
    }
}

/// Test resolver standing in for certification-path validation and extraction
/// of the public key from the first certificate in an `x5c` chain.
struct TestX5cResolver;

impl ProofKeyResolver for TestX5cResolver {
    fn resolve(&self, binding: &ProofKeyBinding, _alg: &str) -> IssuerResult<Jwk> {
        match binding {
            ProofKeyBinding::X5c(chain) if chain.first().map(String::as_str) == Some(X5C_LEAF) => {
                public_jwk_with_kid(None).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))
            }
            _ => Err(IssuerError::new(IssuerStatus::InvalidProof)),
        }
    }
}

struct TrustingKeyAttestationVerifier;

impl KeyAttestationTrustVerifier for TrustingKeyAttestationVerifier {
    fn verify_key_attestation(
        &self,
        _jwt: &KeyAttestationJwt,
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
}

struct CountingKeyAttestationVerifier {
    calls: Arc<AtomicUsize>,
}

impl KeyAttestationTrustVerifier for CountingKeyAttestationVerifier {
    fn verify_key_attestation(
        &self,
        jwt: &KeyAttestationJwt,
        parsed: &ParsedKeyAttestation,
    ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        TrustingKeyAttestationVerifier.verify_key_attestation(jwt, parsed)
    }
}

#[test]
fn jose_verifier_resolves_kid_binding() -> Result<(), JoseProofTestError> {
    let jwt = kid_bound_proof(NONCE)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let verified = JoseJwtProofVerifier::new()
        .with_key_resolver(Arc::new(TestKidResolver))
        .verify(&proofs, &context(true))
        .map_err(|_| JoseProofTestError::Verify)?;

    assert_eq!(verified.binding_key_count(), 1);
    assert_eq!(verified.proofs()[0].key_id(), Some(RESOLVED_KEY_ID));
    Ok(())
}

#[test]
fn jose_verifier_rejects_kid_binding_without_resolver() -> Result<(), JoseProofTestError> {
    let jwt = kid_bound_proof(NONCE)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    // The default verifier accepts only inline header `jwk`; a `kid` binding
    // fails closed when no resolver is configured.
    let result = JoseJwtProofVerifier::new().verify(&proofs, &context(true));
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn jose_verifier_resolves_x5c_leaf_key_binding() -> Result<(), JoseProofTestError> {
    let jwt = x5c_bound_proof(NONCE)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let verified = JoseJwtProofVerifier::new()
        .with_key_resolver(Arc::new(TestX5cResolver))
        .verify(&proofs, &context(true))
        .map_err(|_| JoseProofTestError::Verify)?;

    assert_eq!(verified.binding_key_count(), 1);
    assert_eq!(verified.proofs().len(), 1);
    Ok(())
}

#[test]
fn jose_verifier_rejects_x5c_binding_without_resolver() -> Result<(), JoseProofTestError> {
    let jwt = x5c_bound_proof(NONCE)?;
    let proofs = Proofs {
        jwt: vec![jwt],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };

    let result = JoseJwtProofVerifier::new().verify(&proofs, &context(true));
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

fn context(nonce_required: bool) -> ProofVerificationContext {
    let key_attestation_policy = match KeyAttestationPolicy::from_proof_metadata(
        &ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["EdDSA".to_owned(), "ES256".to_owned()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: None,
                user_authentication: None,
                preferred_key_storage_status_period: None,
            }),
        },
        300,
        0,
    ) {
        Ok(policy) => policy,
        Err(_) => std::process::abort(),
    };
    ProofVerificationContext {
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
        key_attestation_policy: Some(key_attestation_policy),
    }
}

fn key_attestation_policy_for_algorithm(
    algorithm: &str,
) -> Result<KeyAttestationPolicy, JoseProofTestError> {
    KeyAttestationPolicy::from_proof_metadata(
        &ProofTypeMetadata {
            proof_signing_alg_values_supported: vec![algorithm.to_owned()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: None,
                user_authentication: None,
                preferred_key_storage_status_period: None,
            }),
        },
        300,
        0,
    )
    .map_err(|_| JoseProofTestError::Verify)
}

fn proof_jwt(nonce: &str) -> Result<String, JoseProofTestError> {
    signed_proof(json!({
        "aud": ISSUER,
        "nonce": nonce,
        "iat": 1_700_000_000_u64
    }))
}

fn proof_jwt_without_nonce() -> Result<String, JoseProofTestError> {
    signed_proof(json!({
        "aud": ISSUER,
        "iat": 1_700_000_000_u64
    }))
}

fn proof_jwt_with_key_attestation(
    nonce: &str,
    key_attestation: String,
) -> Result<String, JoseProofTestError> {
    let claims = json!({
        "aud": ISSUER,
        "nonce": nonce,
        "iat": 1_700_000_000_u64
    });
    let jwk_value = public_jwk_value(&SEED)?;
    signed_proof_with_header(
        json!({
            "alg": "EdDSA",
            "typ": PROOF_TYP,
            "jwk": jwk_value,
            "key_attestation": key_attestation
        }),
        claims,
    )
}

/// Builds a final-spec key proof that binds the public key in the JOSE header
/// (`jwk`), signing the compact JWT with the matching Ed25519 private key.
fn signed_proof(claims: serde_json::Value) -> Result<String, JoseProofTestError> {
    let header = json!({
        "alg": "EdDSA",
        "typ": PROOF_TYP,
        "jwk": public_jwk_value(&SEED)?
    });
    signed_proof_with_header(header, claims)
}

fn signed_proof_with_header(
    header: serde_json::Value,
    claims: serde_json::Value,
) -> Result<String, JoseProofTestError> {
    let (_public_key, private_key) =
        generate_ed25519_keypair_from_seed(&SEED).map_err(|_| JoseProofTestError::Key)?;
    let header_json = serde_json::to_vec(&header).map_err(|_| JoseProofTestError::Sign)?;
    let claims_json = serde_json::to_vec(&claims).map_err(|_| JoseProofTestError::Sign)?;
    let header_b64 = bytes_to_base64url(&header_json);
    let payload_b64 = bytes_to_base64url(&claims_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign_ed25519(&private_key, signing_input.as_bytes())
        .map_err(|_| JoseProofTestError::Sign)?;
    Ok(format!(
        "{signing_input}.{}",
        bytes_to_base64url(&signature)
    ))
}

fn p256_proof_jwt() -> Result<(String, Vec<u8>), JoseProofTestError> {
    let (public_key, private_key) =
        generate_keypair(Algorithm::P256).map_err(|_| JoseProofTestError::Key)?;
    let expected_public_key =
        decompress_public_key(&public_key).map_err(|_| JoseProofTestError::Key)?;
    let jwk = p256_public_key_to_jwk(
        &public_key,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: None,
        },
    )
    .map_err(|_| JoseProofTestError::Key)?;
    let header = json!({
        "alg": "ES256",
        "typ": PROOF_TYP,
        "jwk": jwk
    });
    let claims = json!({
        "aud": ISSUER,
        "nonce": NONCE,
        "iat": 1_700_000_000_u64
    });
    let header_json = serde_json::to_vec(&header).map_err(|_| JoseProofTestError::Sign)?;
    let claims_json = serde_json::to_vec(&claims).map_err(|_| JoseProofTestError::Sign)?;
    let header_b64 = bytes_to_base64url(&header_json);
    let payload_b64 = bytes_to_base64url(&claims_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature_der = sign(
        Algorithm::P256,
        private_key.as_slice(),
        signing_input.as_bytes(),
    )
    .map_err(|_| JoseProofTestError::Sign)?;
    let signature =
        p256_ecdsa_der_to_jose_signature(&signature_der).map_err(|_| JoseProofTestError::Sign)?;
    Ok((
        format!("{signing_input}.{}", bytes_to_base64url(&signature)),
        expected_public_key,
    ))
}

fn key_attestation_jwt(
    attested_keys: Vec<serde_json::Value>,
    nonce: Option<&str>,
    include_exp: bool,
) -> Result<String, JoseProofTestError> {
    key_attestation_jwt_with_exp(
        attested_keys,
        nonce,
        include_exp.then_some(1_800_000_000_u64),
    )
}

fn key_attestation_jwt_with_exp(
    attested_keys: Vec<serde_json::Value>,
    nonce: Option<&str>,
    expiration: Option<u64>,
) -> Result<String, JoseProofTestError> {
    let header = json!({
        "alg": "ES256",
        "typ": "key-attestation+jwt"
    });
    let mut claims = json!({
        "iat": 1_700_000_000_u64,
        "key_storage": ["iso_18045_moderate"],
        "user_authentication": ["iso_18045_high"],
        "certification": "https://certification.example/key-storage",
        "status": {"status_list": {"idx": 7}},
        "attested_keys": attested_keys
    });
    if let Some(expiration) = expiration {
        claims["exp"] = json!(expiration);
    }
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    let header_json = serde_json::to_vec(&header).map_err(|_| JoseProofTestError::Sign)?;
    let claims_json = serde_json::to_vec(&claims).map_err(|_| JoseProofTestError::Sign)?;
    let header_b64 = bytes_to_base64url(&header_json);
    let payload_b64 = bytes_to_base64url(&claims_json);
    Ok(format!(
        "{header_b64}.{payload_b64}.{}",
        bytes_to_base64url(b"signature")
    ))
}
