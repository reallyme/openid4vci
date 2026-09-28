// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed issuer engine errors.

use core::fmt::{Display, Formatter};

use openid4vci_types::{IssuerProblemStatus, ProblemDetails};
use thiserror::Error;

/// Result alias for issuer operations.
pub type IssuerResult<T> = Result<T, IssuerError>;

/// Stable issuer error status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssuerStatus {
    /// The request was malformed.
    InvalidRequest,
    /// The requested credential configuration is unknown.
    UnsupportedCredential,
    /// The requested credential identifier is unknown.
    UnknownCredentialIdentifier,
    /// Proofs were required but absent.
    ProofRequired,
    /// At least one proof was invalid.
    InvalidProof,
    /// Issuer proof policy was incomplete or inconsistent with metadata.
    InvalidProofPolicy,
    /// Attestation signature was rejected.
    AttestationSignatureRejected,
    /// Attestation signer trust was rejected.
    AttestationTrustRejected,
    /// Attestation signer trust could not be determined conclusively.
    AttestationTrustIndeterminate,
    /// Attestation signer-trust evidence expired before it was consumed.
    AttestationTrustEvidenceStale,
    /// Attestation signer-trust evidence was evaluated beyond the trusted clock.
    AttestationTrustEvidenceFutureIssued,
    /// Attestation status was rejected.
    AttestationStatusRejected,
    /// Attestation status could not be determined conclusively.
    AttestationStatusIndeterminate,
    /// Attestation temporal policy rejected expired evidence.
    AttestationExpired,
    /// Attestation temporal policy rejected stale evidence.
    AttestationStale,
    /// Attestation temporal policy rejected future-issued evidence.
    AttestationFutureIssued,
    /// Attestation algorithm was unsupported or excluded by selected metadata policy.
    AttestationAlgorithmRejected,
    /// Trusted key-security properties did not satisfy issuer policy.
    AttestationSecurityPropertiesRejected,
    /// Attestation trust provenance was incomplete or internally inconsistent.
    InvalidAttestationTrustEvidence,
    /// Attested binding key was unsupported or duplicated.
    InvalidAttestedKey,
    /// At least one proof nonce was invalid.
    InvalidNonce,
    /// Response encryption was required but absent.
    EncryptionRequired,
    /// Response encryption parameters were present but invalid or unsupported.
    InvalidEncryptionParameters,
    /// Deferred issuance transaction was unknown.
    InvalidTransaction,
    /// Notification identifier was unknown.
    InvalidNotificationId,
    /// The backing store failed.
    StorageUnavailable,
    /// Credential encoding or signing failed.
    EncodingFailed,
}

impl From<IssuerStatus> for IssuerProblemStatus {
    fn from(value: IssuerStatus) -> Self {
        match value {
            IssuerStatus::InvalidRequest => Self::InvalidRequest,
            IssuerStatus::UnsupportedCredential => Self::UnsupportedCredential,
            IssuerStatus::UnknownCredentialIdentifier => Self::UnknownCredentialIdentifier,
            IssuerStatus::ProofRequired => Self::ProofRequired,
            IssuerStatus::InvalidProof
            | IssuerStatus::InvalidProofPolicy
            | IssuerStatus::AttestationSignatureRejected
            | IssuerStatus::AttestationTrustRejected
            | IssuerStatus::AttestationTrustIndeterminate
            | IssuerStatus::AttestationTrustEvidenceStale
            | IssuerStatus::AttestationTrustEvidenceFutureIssued
            | IssuerStatus::AttestationStatusRejected
            | IssuerStatus::AttestationStatusIndeterminate
            | IssuerStatus::AttestationExpired
            | IssuerStatus::AttestationStale
            | IssuerStatus::AttestationFutureIssued
            | IssuerStatus::AttestationAlgorithmRejected
            | IssuerStatus::AttestationSecurityPropertiesRejected
            | IssuerStatus::InvalidAttestationTrustEvidence
            | IssuerStatus::InvalidAttestedKey => Self::InvalidProof,
            IssuerStatus::InvalidNonce => Self::InvalidNonce,
            IssuerStatus::EncryptionRequired | IssuerStatus::InvalidEncryptionParameters => {
                Self::EncryptionRequired
            }
            IssuerStatus::InvalidTransaction => Self::InvalidTransaction,
            IssuerStatus::InvalidNotificationId => Self::InvalidNotificationId,
            IssuerStatus::StorageUnavailable => Self::StorageUnavailable,
            IssuerStatus::EncodingFailed => Self::EncodingFailed,
        }
    }
}

impl From<IssuerError> for ProblemDetails {
    fn from(value: IssuerError) -> Self {
        ProblemDetails::from_issuer_status(value.status.into(), None)
    }
}

impl Display for IssuerStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedCredential => "unknown_credential_configuration",
            Self::UnknownCredentialIdentifier => "unknown_credential_identifier",
            Self::ProofRequired => "proof_required",
            Self::InvalidProof
            | Self::InvalidProofPolicy
            | Self::AttestationSignatureRejected
            | Self::AttestationTrustRejected
            | Self::AttestationTrustIndeterminate
            | Self::AttestationTrustEvidenceStale
            | Self::AttestationTrustEvidenceFutureIssued
            | Self::AttestationStatusRejected
            | Self::AttestationStatusIndeterminate
            | Self::AttestationExpired
            | Self::AttestationStale
            | Self::AttestationFutureIssued
            | Self::AttestationAlgorithmRejected
            | Self::AttestationSecurityPropertiesRejected
            | Self::InvalidAttestationTrustEvidence
            | Self::InvalidAttestedKey => "invalid_proof",
            Self::InvalidNonce => "invalid_nonce",
            Self::EncryptionRequired | Self::InvalidEncryptionParameters => {
                "invalid_encryption_parameters"
            }
            Self::InvalidTransaction => "invalid_transaction_id",
            Self::InvalidNotificationId => "invalid_notification_id",
            Self::StorageUnavailable => "storage_unavailable",
            Self::EncodingFailed => "encoding_failed",
        })
    }
}

/// Issuer engine error with deterministic, non-secret context.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{status}")]
pub struct IssuerError {
    status: IssuerStatus,
}

impl IssuerError {
    /// Creates an issuer error from a status code.
    #[must_use]
    pub const fn new(status: IssuerStatus) -> Self {
        Self { status }
    }

    /// Returns the stable status code.
    #[must_use]
    pub const fn status(&self) -> IssuerStatus {
        self.status
    }
}
