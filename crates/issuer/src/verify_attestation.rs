// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer proof verifier for the OpenID4VCI `attestation` proof type.

use std::sync::Arc;

use openid4vci_attestation::{
    verify_key_attestation, AttestationStatus, BindingKeyAlgorithm, KeyAttestationJwt,
    KeyAttestationTrustVerifier, KeyAttestationValidationContext,
};
use openid4vci_types::Proofs;

use crate::error::{IssuerError, IssuerResult, IssuerStatus};
use crate::proof::{
    ConfirmationJwk, ProofAlgorithm, ProofKind, ProofVerificationContext, ProofVerifier,
    VerifiedProof, VerifiedProofSet,
};

/// Verifies direct key-attestation proof requests.
#[derive(Clone)]
pub struct KeyAttestationProofVerifier {
    trust_verifier: Arc<dyn KeyAttestationTrustVerifier + Send + Sync>,
    expected_nonce: Option<String>,
    expiration_required: bool,
}

impl KeyAttestationProofVerifier {
    /// Creates a verifier with injected trust-chain/signature validation.
    ///
    /// With no fixed expected nonce, this verifier proves that the attestation
    /// carries a nonce when the context requires one and returns that value in
    /// the verified proof set. Replay safety is completed by the Credential
    /// Endpoint's atomic `NonceManager::consume`; calling a proof verifier in
    /// isolation is deliberately not an issuance authorization decision.
    #[must_use]
    pub fn new(trust_verifier: Arc<dyn KeyAttestationTrustVerifier + Send + Sync>) -> Self {
        Self {
            trust_verifier,
            expected_nonce: None,
            expiration_required: false,
        }
    }

    /// Configures an exact nonce expected in the key attestation.
    #[must_use]
    pub fn with_expected_nonce(mut self, nonce: String) -> Self {
        self.expected_nonce = Some(nonce);
        self
    }

    /// Requires the key attestation to carry an expiration time.
    #[must_use]
    pub const fn require_expiration(mut self) -> Self {
        self.expiration_required = true;
        self
    }
}

impl ProofVerifier for KeyAttestationProofVerifier {
    fn verify(
        &self,
        proofs: &Proofs,
        context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        if !proofs.jwt.is_empty() || !proofs.di_vp.is_empty() || proofs.attestation.len() != 1 {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        let jwt =
            KeyAttestationJwt::new(proofs.attestation[0].clone()).map_err(attestation_error)?;
        let policy = context
            .key_attestation_policy
            .as_ref()
            .ok_or(IssuerError::new(IssuerStatus::InvalidProofPolicy))?;
        let verified = verify_key_attestation(
            &jwt,
            &KeyAttestationValidationContext {
                nonce_required: context.nonce_required,
                expected_nonce: self.expected_nonce.clone(),
                temporal_policy: policy
                    .temporal_policy(context.current_time, self.expiration_required)?,
                accepted_algorithms: policy.accepted_algorithms().to_vec(),
            },
            self.trust_verifier.as_ref(),
        )
        .map_err(attestation_error)?;
        policy.validate(&verified)?;
        let mut binding_proofs = Vec::with_capacity(verified.attested_keys().len());
        for key in verified.attested_keys() {
            let algorithm = match key.algorithm() {
                BindingKeyAlgorithm::P256 => ProofAlgorithm::Es256,
                BindingKeyAlgorithm::Secp256K1 => ProofAlgorithm::Es256k,
                BindingKeyAlgorithm::Ed25519 => ProofAlgorithm::EdDsa,
            };
            if context.accepted_proof_algorithms.is_empty()
                || !context.accepted_proof_algorithms.contains(&algorithm)
            {
                return Err(IssuerError::new(IssuerStatus::InvalidProof));
            }
            binding_proofs.push(VerifiedProof::new(
                ProofKind::Attestation,
                verified.nonce().map(str::to_owned),
                None,
                None,
                key.key_id().map(str::to_owned),
                Some(key.public_jwk().clone()),
                Some(ConfirmationJwk {
                    algorithm,
                    public_key: key.public_key_bytes(),
                    key_id: key.key_id().map(str::to_owned),
                }),
            )?);
        }
        if verified.attested_key_count()
            != u32::try_from(binding_proofs.len())
                .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?
        {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        VerifiedProofSet::new(binding_proofs, vec![verified])
    }
}

pub(crate) fn attestation_error(error: openid4vci_attestation::AttestationError) -> IssuerError {
    match error.status() {
        AttestationStatus::InvalidNonce => IssuerError::new(IssuerStatus::InvalidNonce),
        AttestationStatus::SignatureRejected => {
            IssuerError::new(IssuerStatus::AttestationSignatureRejected)
        }
        AttestationStatus::TrustRejected => {
            IssuerError::new(IssuerStatus::AttestationTrustRejected)
        }
        AttestationStatus::TrustIndeterminate => {
            IssuerError::new(IssuerStatus::AttestationTrustIndeterminate)
        }
        AttestationStatus::TrustEvidenceStale => {
            IssuerError::new(IssuerStatus::AttestationTrustEvidenceStale)
        }
        AttestationStatus::TrustEvidenceFutureIssued => {
            IssuerError::new(IssuerStatus::AttestationTrustEvidenceFutureIssued)
        }
        AttestationStatus::InvalidTrustEvidence => {
            IssuerError::new(IssuerStatus::InvalidAttestationTrustEvidence)
        }
        AttestationStatus::StatusRejected => {
            IssuerError::new(IssuerStatus::AttestationStatusRejected)
        }
        AttestationStatus::StatusIndeterminate => {
            IssuerError::new(IssuerStatus::AttestationStatusIndeterminate)
        }
        AttestationStatus::Expired => IssuerError::new(IssuerStatus::AttestationExpired),
        AttestationStatus::Stale => IssuerError::new(IssuerStatus::AttestationStale),
        AttestationStatus::FutureIssued => IssuerError::new(IssuerStatus::AttestationFutureIssued),
        AttestationStatus::UnsupportedAttestedKey | AttestationStatus::DuplicateAttestedKey => {
            IssuerError::new(IssuerStatus::InvalidAttestedKey)
        }
        AttestationStatus::UnsupportedAlgorithm | AttestationStatus::AlgorithmNotAllowed => {
            IssuerError::new(IssuerStatus::AttestationAlgorithmRejected)
        }
        AttestationStatus::MissingJwt
        | AttestationStatus::InvalidJwt
        | AttestationStatus::InvalidHeader
        | AttestationStatus::InvalidClaims => IssuerError::new(IssuerStatus::InvalidProof),
    }
}
