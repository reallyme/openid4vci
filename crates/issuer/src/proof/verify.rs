// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public proof models and verifier boundary.

use openid4vci_attestation::VerifiedKeyAttestation;
use openid4vci_types::{CredentialSelector, Proofs};
use serde_json::Value;
use zeroize::Zeroize;

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

use super::attestation_policy::KeyAttestationPolicy;

/// Proof families accepted at the credential endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofKind {
    /// JWT key proof.
    Jwt,
    /// Data Integrity Verifiable Presentation proof.
    DiVp,
    /// Key attestation proof JWT.
    Attestation,
}

/// Supported signature algorithms for proof key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAlgorithm {
    /// EdDSA over Ed25519.
    EdDsa,
    /// ECDSA over P-256 with SHA-256.
    Es256,
    /// ECDSA over secp256k1 with SHA-256.
    Es256k,
}

impl ProofAlgorithm {
    /// Parses one JOSE algorithm supported by the built-in proof verifiers.
    pub fn from_jose_name(value: &str) -> IssuerResult<Self> {
        match value {
            "EdDSA" => Ok(Self::EdDsa),
            "ES256" => Ok(Self::Es256),
            "ES256K" => Ok(Self::Es256k),
            _ => Err(IssuerError::new(IssuerStatus::InvalidProof)),
        }
    }

    pub(crate) fn from_jws_alg(value: &str) -> IssuerResult<Self> {
        Self::from_jose_name(value)
    }
}

/// Normalized public confirmation key recovered from a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationJwk {
    /// JWS algorithm associated with the key.
    pub algorithm: ProofAlgorithm,
    /// Public key bytes normalized for verifier backends.
    ///
    /// Ed25519 is raw 32-byte public key material. EC keys are SEC1
    /// uncompressed form: `0x04 || x || y`.
    pub public_key: Vec<u8>,
    /// Optional key identifier from the JWK.
    pub key_id: Option<String>,
}

/// Issuer-controlled context applied while verifying credential proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofVerificationContext {
    /// Credential Issuer Identifier expected in the proof audience/domain.
    pub credential_issuer: String,
    /// Credential target being requested.
    pub selector: CredentialSelector,
    /// OAuth client identifier for a non-anonymous grant.
    ///
    /// A proof JWT `iss`, when present, must equal this value. `None` denotes
    /// an anonymous pre-authorized flow, for which `iss` must be absent.
    pub client_id: Option<String>,
    /// Proof-signing algorithms advertised for the selected credential
    /// configuration and proof type. An empty list fails closed.
    pub accepted_proof_algorithms: Vec<ProofAlgorithm>,
    /// Whether a `c_nonce` is required by issuer metadata.
    pub nonce_required: bool,
    /// Current Unix time applied to nested key-attestation evidence.
    ///
    /// OpenID4VCI 1.0 Final Appendix F.4 proof freshness is enforced by the
    /// credential endpoint's expiring, single-use server nonce. This clock is
    /// additionally required for the attestation's independent `iat`/`exp`.
    pub current_time: i64,
    /// Optional constraints that trusted key attestations must satisfy.
    pub key_attestation_policy: Option<KeyAttestationPolicy>,
}

/// A proof whose signature, claims, and key reference were validated.
pub struct VerifiedProof {
    /// Proof member that was verified.
    kind: ProofKind,
    /// Verified OpenID4VCI nonce claim.
    nonce: Option<String>,
    /// Verified audience claim.
    audience: Option<String>,
    /// Verified key binding identifier, when carried by the proof.
    key_binding_id: Option<String>,
    /// Optional key identifier from the proof header.
    key_id: Option<String>,
    /// Sanitized public proof key suitable for credential `cnf.jwk` binding.
    public_jwk: Option<Value>,
    /// Normalized public proof key retained for non-JOSE credential binding.
    confirmation_key: Option<ConfirmationJwk>,
}

impl VerifiedProof {
    /// Creates a provider receipt for one proof after signature and claim checks.
    ///
    /// Implementations of [`ProofVerifier`] are trusted security providers. The
    /// constructor deliberately validates receipt shape while leaving
    /// cryptographic verification to that provider contract.
    pub fn new(
        kind: ProofKind,
        nonce: Option<String>,
        audience: Option<String>,
        key_binding_id: Option<String>,
        key_id: Option<String>,
        public_jwk: Option<Value>,
        confirmation_key: Option<ConfirmationJwk>,
    ) -> IssuerResult<Self> {
        if public_jwk.is_none() || confirmation_key.is_none() {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        Ok(Self {
            kind,
            nonce,
            audience,
            key_binding_id,
            key_id,
            public_jwk,
            confirmation_key,
        })
    }

    /// Returns the verified proof family.
    #[must_use]
    pub const fn kind(&self) -> ProofKind {
        self.kind
    }

    /// Returns the verified nonce claim.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Returns the verified audience claim.
    #[must_use]
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    /// Returns the verified key-binding identifier.
    #[must_use]
    pub fn key_binding_id(&self) -> Option<&str> {
        self.key_binding_id.as_deref()
    }

    /// Returns the verified key identifier.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Returns the sanitized public JWK.
    #[must_use]
    pub fn public_jwk(&self) -> Option<&Value> {
        self.public_jwk.as_ref()
    }

    /// Returns the normalized confirmation key.
    #[must_use]
    pub fn confirmation_key(&self) -> Option<&ConfirmationJwk> {
        self.confirmation_key.as_ref()
    }
}

impl Drop for VerifiedProof {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.audience.zeroize();
        self.key_binding_id.zeroize();
        self.key_id.zeroize();
    }
}

/// Aggregate result for all proofs carried by one credential request.
pub struct VerifiedProofSet {
    /// Number of credential-binding keys accepted.
    binding_key_count: u32,
    /// Whether a key attestation proof was accepted.
    includes_key_attestation: bool,
    /// Trusted key-attestation evidence retained for issuance policy.
    key_attestations: Vec<VerifiedKeyAttestation>,
    /// Individual verified proofs.
    proofs: Vec<VerifiedProof>,
}

impl VerifiedProofSet {
    /// Builds a self-consistent aggregate receipt from individual provider receipts.
    pub fn new(
        proofs: Vec<VerifiedProof>,
        key_attestations: Vec<VerifiedKeyAttestation>,
    ) -> IssuerResult<Self> {
        if proofs.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        let first_kind = proofs[0].kind;
        if proofs.iter().any(|proof| proof.kind != first_kind) {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        let binding_key_count = u32::try_from(proofs.len())
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
        let includes_key_attestation = match first_kind {
            ProofKind::Attestation => key_attestations.len() == 1,
            ProofKind::Jwt => key_attestations.len() == proofs.len(),
            ProofKind::DiVp => false,
        };
        Ok(Self {
            binding_key_count,
            includes_key_attestation,
            key_attestations,
            proofs,
        })
    }

    /// Returns the number of credential-binding keys.
    #[must_use]
    pub const fn binding_key_count(&self) -> u32 {
        self.binding_key_count
    }

    /// Returns whether every binding key is covered by trusted attestation evidence.
    #[must_use]
    pub const fn includes_key_attestation(&self) -> bool {
        self.includes_key_attestation
    }

    /// Returns individual verified proof receipts in request order.
    #[must_use]
    pub fn proofs(&self) -> &[VerifiedProof] {
        &self.proofs
    }

    /// Returns trusted key-attestation evidence retained for issuance policy.
    #[must_use]
    pub fn key_attestations(&self) -> &[VerifiedKeyAttestation] {
        &self.key_attestations
    }

    /// Returns credential-binding keys in the verified proof order.
    ///
    /// Issuers must preserve this order when producing a multi-credential
    /// response so credential `n` is bound to proof `n`. The method also keeps
    /// provider implementations from silently accepting a verifier that
    /// reports a cardinality inconsistent with its sanitized proof records.
    pub fn ordered_public_jwks(&self) -> IssuerResult<Vec<&Value>> {
        let binding_key_count = usize::try_from(self.binding_key_count)
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
        if binding_key_count == 0 || self.proofs.len() != binding_key_count {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        let mut keys = Vec::with_capacity(binding_key_count);
        for proof in &self.proofs {
            keys.push(
                proof
                    .public_jwk
                    .as_ref()
                    .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?,
            );
        }
        Ok(keys)
    }

    /// Returns normalized credential-binding keys in verified proof order.
    pub fn ordered_confirmation_keys(&self) -> IssuerResult<Vec<&ConfirmationJwk>> {
        let binding_key_count = usize::try_from(self.binding_key_count)
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
        if binding_key_count == 0 || self.proofs.len() != binding_key_count {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
        let mut keys = Vec::with_capacity(binding_key_count);
        for proof in &self.proofs {
            keys.push(
                proof
                    .confirmation_key
                    .as_ref()
                    .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?,
            );
        }
        Ok(keys)
    }
}

/// Transport-neutral verifier boundary for credential request proofs.
pub trait ProofVerifier {
    /// Verifies the supplied `proofs` object.
    ///
    /// This operation does not consume freshness state. Issuance callers must
    /// pass the returned proof set through the Credential Endpoint, which
    /// atomically consumes its server-issued nonce before issuing.
    fn verify(
        &self,
        proofs: &Proofs,
        context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet>;
}
