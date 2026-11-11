// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETSI TS 119 472-3 Credential Request proof-shape policy.

use core::fmt;

use openid4vci_types::Proofs;

/// Proof transport selected for an ETSI-profiled Credential Request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtsiCredentialProofMechanism {
    /// One JWT proof carrying a Wallet Unit Attestation in its protected header.
    Jwt,
    /// One Wallet Unit Attestation used directly as the proof.
    Attestation,
}

/// Stable ETSI Credential Request proof-policy failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtsiCredentialProofErrorReason {
    /// A cryptographically bound credential request omitted its proof.
    ProofRequired,
    /// The request used a proof family not admitted by ETSI TS 119 472-3.
    UnsupportedProofMechanism,
    /// The selected proof array did not contain exactly one element.
    InvalidProofCardinality,
    /// The proof object failed the base OpenID4VCI shape checks.
    InvalidProof,
}

impl fmt::Display for EtsiCredentialProofErrorReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProofRequired => "proof_required",
            Self::UnsupportedProofMechanism => "unsupported_proof_mechanism",
            Self::InvalidProofCardinality => "invalid_proof_cardinality",
            Self::InvalidProof => "invalid_proof",
        })
    }
}

/// Typed ETSI Credential Request proof-policy error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{reason}")]
pub struct EtsiCredentialProofError {
    reason: EtsiCredentialProofErrorReason,
}

impl EtsiCredentialProofError {
    const fn new(reason: EtsiCredentialProofErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable failure reason.
    #[must_use]
    pub const fn reason(self) -> EtsiCredentialProofErrorReason {
        self.reason
    }
}

/// Validates the proof shape required by ETSI TS 119 472-3 clauses 4.6.1.1–4.6.1.3.
///
/// Cryptographic verification of the JWT, Wallet Unit Attestation, nonce, and
/// first attested key remains an issuer responsibility. This helper deliberately
/// establishes only the request shape before expensive signature processing.
pub fn validate_etsi_credential_request_proofs(
    proofs: Option<&Proofs>,
    proof_required: bool,
) -> Result<Option<EtsiCredentialProofMechanism>, EtsiCredentialProofError> {
    let Some(proofs) = proofs else {
        return if proof_required {
            Err(EtsiCredentialProofError::new(
                EtsiCredentialProofErrorReason::ProofRequired,
            ))
        } else {
            Ok(None)
        };
    };
    proofs
        .validate()
        .map_err(|_| EtsiCredentialProofError::new(EtsiCredentialProofErrorReason::InvalidProof))?;
    if !proofs.di_vp.is_empty() {
        return Err(EtsiCredentialProofError::new(
            EtsiCredentialProofErrorReason::UnsupportedProofMechanism,
        ));
    }
    if !proofs.jwt.is_empty() {
        return if proofs.jwt.len() == 1 {
            Ok(Some(EtsiCredentialProofMechanism::Jwt))
        } else {
            Err(EtsiCredentialProofError::new(
                EtsiCredentialProofErrorReason::InvalidProofCardinality,
            ))
        };
    }
    if !proofs.attestation.is_empty() {
        return if proofs.attestation.len() == 1 {
            Ok(Some(EtsiCredentialProofMechanism::Attestation))
        } else {
            Err(EtsiCredentialProofError::new(
                EtsiCredentialProofErrorReason::InvalidProofCardinality,
            ))
        };
    }
    Err(EtsiCredentialProofError::new(
        EtsiCredentialProofErrorReason::UnsupportedProofMechanism,
    ))
}

#[cfg(test)]
#[path = "etsi_credential_request_tests.rs"]
mod tests;
