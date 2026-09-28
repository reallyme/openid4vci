// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attestation typed errors.

use thiserror::Error;

/// Result alias for attestation helpers.
pub type AttestationResult<T> = Result<T, AttestationError>;

/// Attestation validation status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationStatus {
    /// A required JWT was absent or empty.
    MissingJwt,
    /// A JWT shape was malformed.
    InvalidJwt,
    /// The JOSE header violates the key attestation profile.
    InvalidHeader,
    /// The JWT claims violate the key attestation profile.
    InvalidClaims,
    /// The attestation nonce was absent or incorrect.
    InvalidNonce,
    /// The JWT algorithm is not permitted for attestation.
    UnsupportedAlgorithm,
    /// The supported algorithm is excluded by the selected issuer policy.
    AlgorithmNotAllowed,
    /// The attestation has expired under the configured clock-skew policy.
    Expired,
    /// The attestation issuance time is beyond the permitted future skew.
    FutureIssued,
    /// The attestation issuance time is older than the permitted maximum age.
    Stale,
    /// An attested JWK uses an unsupported key type, curve, or operation.
    UnsupportedAttestedKey,
    /// Two attested JWKs identify the same cryptographic public key.
    DuplicateAttestedKey,
    /// The attestation signature was cryptographically rejected.
    SignatureRejected,
    /// The attestation signer or certification path was rejected by policy.
    TrustRejected,
    /// Trust evidence could not be established conclusively.
    TrustIndeterminate,
    /// The trust decision expired before the attestation was consumed.
    TrustEvidenceStale,
    /// The trust decision was evaluated beyond the trusted current time.
    TrustEvidenceFutureIssued,
    /// The attestation status mechanism reported a revoked or invalid state.
    StatusRejected,
    /// A present attestation status mechanism could not be evaluated conclusively.
    StatusIndeterminate,
    /// Trusted provenance returned by an adapter was incomplete or inconsistent.
    InvalidTrustEvidence,
}

/// Typed attestation error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{status:?}")]
pub struct AttestationError {
    status: AttestationStatus,
}

impl AttestationError {
    /// Creates an attestation error.
    #[must_use]
    pub const fn new(status: AttestationStatus) -> Self {
        Self { status }
    }

    /// Returns the deterministic status code.
    #[must_use]
    pub const fn status(&self) -> AttestationStatus {
        self.status
    }
}
