// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `reallyme-jose` backed proof verification.
//!
//! This adapter is the OpenID4VCI-to-Identity boundary for JWT key proofs. It
//! verifies the compact JWT signature with `reallyme-jose`, extracts the public
//! key from the proof's final-spec JOSE header binding, and then reuses the issuer crate's
//! OpenID4VCI-specific nonce and audience policy checks.

use std::sync::Arc;

use openid4vci_attestation::{
    verify_key_attestation, KeyAttestationJwt, KeyAttestationTrustVerifier,
    KeyAttestationValidationContext, VerifiedKeyAttestation,
};
use openid4vci_types::Proofs;
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_jose::jwt::{
    decode_verify_jwt_signature_only_with_header_validation, JwtHeaderValidationOptions,
};
use reallyme_jose::Jwk;
use serde_json::Value;

use crate::error::{IssuerError, IssuerResult, IssuerStatus};
use crate::proof::{
    validate_common_proof_claims, CompactProofJwtParser, ConfirmationJwk, ProofAlgorithm,
    ProofKind, ProofVerificationContext, ProofVerifier, UnverifiedProofClaims,
    UnverifiedProofKeyBinding, VerifiedProof, VerifiedProofSet,
};

use crate::proof::PROOF_JWT_TYP;
use crate::verify_attestation::attestation_error;

const ACCEPTED_PROOF_TYP_VALUES: &[&str] = &[PROOF_JWT_TYP];
const EC_COORDINATE_BYTES: usize = 32;
const EC_UNCOMPRESSED_SEC1_BYTES: usize = 65;
const EC_UNCOMPRESSED_SEC1_PREFIX: u8 = 0x04;

/// A proof key binding carried in the JOSE header (OpenID4VCI 1.0 Appendix F.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofKeyBinding {
    /// Inline public JWK (`jwk`).
    Jwk(Value),
    /// Key identifier (`kid`), for example a DID URL, to be resolved externally.
    Kid(String),
    /// X.509 certificate chain (`x5c`), base64 DER entries, leaf first.
    X5c(Vec<String>),
}

/// Resolves a `kid` or `x5c` proof-key binding to a verified public JWK.
///
/// The default [`JoseJwtProofVerifier`] accepts only inline header `jwk`
/// bindings; injecting a resolver enables `kid` (for example DID) and `x5c`
/// bindings. For `x5c`, the resolver must validate the certification path and
/// applicable policy, then return the public key from the first certificate;
/// returning some other trusted key would break the Appendix F.1 binding.
pub trait ProofKeyResolver: Send + Sync {
    /// Resolves the binding to a public JWK usable for the given JOSE `alg`.
    fn resolve(&self, binding: &ProofKeyBinding, alg: &str) -> IssuerResult<Jwk>;
}

/// JWT proof verifier backed by `reallyme-jose` and `reallyme-crypto`.
#[derive(Clone, Default)]
pub struct JoseJwtProofVerifier {
    parser: CompactProofJwtParser,
    key_resolver: Option<Arc<dyn ProofKeyResolver>>,
    key_attestation_verifier: Option<Arc<dyn KeyAttestationTrustVerifier>>,
}

impl JoseJwtProofVerifier {
    /// Creates a verifier using the default bounded proof parser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a verifier using an explicit compact-JWT parser.
    #[must_use]
    pub fn with_parser(parser: CompactProofJwtParser) -> Self {
        Self {
            parser,
            key_resolver: None,
            key_attestation_verifier: None,
        }
    }

    /// Enables `kid` / `x5c` proof-key binding resolution via an injected resolver.
    #[must_use]
    pub fn with_key_resolver(mut self, key_resolver: Arc<dyn ProofKeyResolver>) -> Self {
        self.key_resolver = Some(key_resolver);
        self
    }

    /// Enables verification of JWT proof `key_attestation` header values.
    #[must_use]
    pub fn with_key_attestation_verifier(
        mut self,
        key_attestation_verifier: Arc<dyn KeyAttestationTrustVerifier>,
    ) -> Self {
        self.key_attestation_verifier = Some(key_attestation_verifier);
        self
    }
}

impl ProofVerifier for JoseJwtProofVerifier {
    fn verify(
        &self,
        proofs: &Proofs,
        context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        if proofs.jwt.is_empty() || !proofs.di_vp.is_empty() || !proofs.attestation.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        let mut verified = Vec::with_capacity(proofs.jwt.len());
        let mut key_attestations = Vec::with_capacity(proofs.jwt.len());
        let mut all_proofs_include_key_attestation = true;
        for proof in &proofs.jwt {
            let (mut claims, proof_jwk, key_attestation) = self.verify_one(proof, context)?;
            all_proofs_include_key_attestation &= key_attestation.is_some();
            if let Some(key_attestation) = key_attestation {
                key_attestations.push(key_attestation);
            }
            let public_jwk = serde_json::to_value(&proof_jwk)
                .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
            let confirmation_key = ConfirmationJwk {
                algorithm: ProofAlgorithm::from_jws_alg(claims.algorithm.as_str())?,
                public_key: confirmation_public_key(
                    &proof_jwk,
                    ProofAlgorithm::from_jws_alg(claims.algorithm.as_str())?,
                )?,
                key_id: claims.key_id.clone(),
            };
            verified.push(VerifiedProof::new(
                ProofKind::Jwt,
                claims.nonce.take(),
                claims.audience.take(),
                claims.key_binding_id.take(),
                claims.key_id.take(),
                Some(public_jwk),
                Some(confirmation_key),
            )?);
        }
        reject_duplicate_binding_keys(&verified)?;
        if all_proofs_include_key_attestation != (key_attestations.len() == verified.len()) {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        VerifiedProofSet::new(verified, key_attestations)
    }
}

fn reject_duplicate_binding_keys(proofs: &[VerifiedProof]) -> IssuerResult<()> {
    for (index, proof) in proofs.iter().enumerate() {
        let key = proof
            .confirmation_key()
            .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
        if proofs[..index].iter().any(|candidate| {
            candidate.confirmation_key().is_some_and(|candidate| {
                candidate.algorithm == key.algorithm && candidate.public_key == key.public_key
            })
        }) {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
    }
    Ok(())
}

fn confirmation_public_key(jwk: &Jwk, algorithm: ProofAlgorithm) -> IssuerResult<Vec<u8>> {
    match (jwk, algorithm) {
        (Jwk::Ec(ec), ProofAlgorithm::Es256) if ec.crv == "P-256" => {
            uncompressed_ec_public_key(&ec.x, &ec.y)
        }
        (Jwk::Ec(ec), ProofAlgorithm::Es256k) if ec.crv == "secp256k1" => {
            uncompressed_ec_public_key(&ec.x, &ec.y)
        }
        (Jwk::Okp(_), ProofAlgorithm::EdDsa) => jwk
            .public_key_bytes()
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof)),
        _ => Err(IssuerError::new(IssuerStatus::InvalidProof)),
    }
}

fn uncompressed_ec_public_key(x: &str, y: &str) -> IssuerResult<Vec<u8>> {
    let x = base64url_to_bytes(x).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
    let y = base64url_to_bytes(y).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
    if x.len() != EC_COORDINATE_BYTES || y.len() != EC_COORDINATE_BYTES {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }

    // ConfirmationJwk has one canonical EC representation. Keeping both
    // affine coordinates avoids pushing SEC1 decompression or COSE's optional
    // y-parity representation into credential-format adapters.
    let mut public_key = Vec::with_capacity(EC_UNCOMPRESSED_SEC1_BYTES);
    public_key.push(EC_UNCOMPRESSED_SEC1_PREFIX);
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);
    Ok(public_key)
}

impl JoseJwtProofVerifier {
    fn verify_one(
        &self,
        jwt: &str,
        context: &ProofVerificationContext,
    ) -> IssuerResult<(UnverifiedProofClaims, Jwk, Option<VerifiedKeyAttestation>)> {
        let mut claims = self.parser.parse_unverified(jwt)?;
        validate_common_proof_claims(&claims, context)?;
        let proof_algorithm = ProofAlgorithm::from_jws_alg(claims.algorithm.as_str())?;
        if context.accepted_proof_algorithms.is_empty()
            || !context.accepted_proof_algorithms.contains(&proof_algorithm)
        {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        let jwk = self.resolve_proof_jwk(&claims, claims.algorithm.as_str())?;
        let public_key = jwk
            .public_key_bytes()
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
        // Authenticate the RFC 7515 proof before invoking signer-trust or
        // status adapters for its key attestation. The attestation still binds
        // the same verified JWK below, but invalid proof traffic cannot trigger
        // an external trust decision first.
        decode_verify_jwt_signature_only_with_header_validation::<Value>(
            jwt,
            &jwk,
            &public_key,
            &JwtHeaderValidationOptions::new(false, true, ACCEPTED_PROOF_TYP_VALUES),
        )
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
        let key_attestation = self.verify_key_attestation_header(&mut claims, &jwk, context)?;
        Ok((claims, jwk, key_attestation))
    }

    /// Resolves the proof key from the JOSE header: an inline `jwk` is used
    /// directly; a `kid` or `x5c` binding is resolved through the injected
    /// [`ProofKeyResolver`], failing closed when none is configured.
    fn resolve_proof_jwk(&self, claims: &UnverifiedProofClaims, alg: &str) -> IssuerResult<Jwk> {
        let binding = match claims.proof_key_binding.as_ref() {
            Some(UnverifiedProofKeyBinding::Jwk(value)) => {
                return proof_confirmation_jwk(value, alg);
            }
            Some(UnverifiedProofKeyBinding::Kid(kid)) => ProofKeyBinding::Kid(kid.clone()),
            Some(UnverifiedProofKeyBinding::X5c(chain)) => ProofKeyBinding::X5c(chain.clone()),
            None => return Err(IssuerError::new(IssuerStatus::InvalidProof)),
        };
        let resolver = self
            .key_resolver
            .as_ref()
            .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
        resolver.resolve(&binding, alg)
    }

    fn verify_key_attestation_header(
        &self,
        claims: &mut UnverifiedProofClaims,
        proof_jwk: &Jwk,
        context: &ProofVerificationContext,
    ) -> IssuerResult<Option<VerifiedKeyAttestation>> {
        let Some(key_attestation) = claims.key_attestation.take() else {
            return Ok(None);
        };
        let verifier = self
            .key_attestation_verifier
            .as_ref()
            .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
        let key_attestation = KeyAttestationJwt::new(key_attestation)
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
        let policy = context
            .key_attestation_policy
            .as_ref()
            .ok_or(IssuerError::new(IssuerStatus::InvalidProofPolicy))?;
        // OpenID4VCI 1.0 Final Appendix F.1 requires both the outer key-proof
        // `alg` and the nested key-attestation `alg` to match the selected
        // `proof_signing_alg_values_supported` metadata. The policy below is
        // derived from that exact metadata object, so checking only the nested
        // attestation would permit an unadvertised proof algorithm.
        if !policy
            .accepted_algorithms()
            .iter()
            .any(|algorithm| algorithm.jose_name() == claims.algorithm)
        {
            return Err(IssuerError::new(IssuerStatus::AttestationAlgorithmRejected));
        }
        let validation_context = KeyAttestationValidationContext {
            nonce_required: context.nonce_required,
            expected_nonce: claims.nonce.clone(),
            // OpenID4VCI final requires `exp` when a key attestation is carried
            // in a JWT proof header, because the key proof can otherwise outlive
            // the attestation semantics it relies on.
            temporal_policy: policy.temporal_policy(context.current_time, true)?,
            accepted_algorithms: policy.accepted_algorithms().to_vec(),
        };
        let verified =
            verify_key_attestation(&key_attestation, &validation_context, verifier.as_ref())
                .map_err(attestation_error)?;
        policy.validate(&verified)?;
        if attested_keys_contain_proof_key(
            verified.attested_keys(),
            proof_jwk,
            claims.algorithm.as_str(),
        )? {
            Ok(Some(verified))
        } else {
            Err(IssuerError::new(IssuerStatus::InvalidProof))
        }
    }
}

fn attested_keys_contain_proof_key(
    attested_keys: &[openid4vci_attestation::VerifiedBindingKey],
    proof_jwk: &Jwk,
    alg: &str,
) -> IssuerResult<bool> {
    let proof_key = proof_jwk
        .public_key_bytes()
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
    for attested_key in attested_keys {
        let mut value = attested_key.public_jwk().clone();
        ensure_jwk_algorithm(&mut value, alg)?;
        let jwk = serde_json::from_value::<Jwk>(value)
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
        let attested_public_key = jwk
            .public_key_bytes()
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
        if attested_public_key == proof_key {
            return Ok(true);
        }
    }
    Ok(false)
}

fn proof_confirmation_jwk(header_jwk: &Value, alg: &str) -> IssuerResult<Jwk> {
    // OpenID4VCI 1.0 Appendix F.1: the proof key is bound in the JOSE header.
    // The draft-era payload `cnf.jwk` fallback is not accepted.
    let mut value = header_jwk.clone();
    if value.get("d").is_some() {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    ensure_jwk_algorithm(&mut value, alg)?;
    // A `kid` inside an embedded JWK identifies that JWK; it does not require
    // the JOSE protected header to carry a second, top-level `kid`. The generic
    // JWT verifier interprets a JWK `kid` as a detached-key selection binding,
    // so remove it from this verification-only copy. The public key remains
    // cryptographically bound because the JWK itself is protected by the JWS.
    value
        .as_object_mut()
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?
        .remove("kid");
    serde_json::from_value::<Jwk>(value).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))
}

fn ensure_jwk_algorithm(value: &mut Value, alg: &str) -> IssuerResult<()> {
    let object = value
        .as_object_mut()
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    match object.get("alg").and_then(Value::as_str) {
        Some(existing) if existing == alg => Ok(()),
        Some(_) => Err(IssuerError::new(IssuerStatus::InvalidProof)),
        None => {
            object.insert("alg".to_owned(), Value::String(alg.to_owned()));
            Ok(())
        }
    }
}
