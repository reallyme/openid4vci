// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet-side typed errors.

use thiserror::Error;

/// Result alias for wallet request builders.
pub type WalletResult<T> = Result<T, WalletError>;

/// Wallet-side request builder status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletStatus {
    /// A required value was absent.
    MissingRequiredValue,
    /// A string value was empty.
    InvalidString,
    /// A nested OpenID4VCI wire object failed validation.
    InvalidRequest,
    /// Issuer-advertised JWE parameters are unsupported or malformed.
    InvalidEncryptionParameters,
    /// A Credential Request could not be encoded or encrypted.
    EncryptionFailed,
    /// An encrypted Credential Response failed authentication or decoding.
    EncryptedResponseRejected,
    /// A referenced credential offer could not be resolved.
    OfferResolutionRequired,
    /// A Credential Offer selected an authorization server outside issuer metadata.
    InvalidAuthorizationServer,
    /// A plaintext response was supplied after response encryption was requested.
    ResponseEncryptionRequired,
    /// The Credential Request must be transported as an encrypted JWE.
    RequestEncryptionRequired,
    /// Credential Issuer Metadata could not be acquired from its well-known location.
    IssuerMetadataResolutionFailed,
    /// Credential Issuer Metadata was malformed or did not bind to the requested issuer.
    InvalidIssuerMetadata,
    /// Credential Issuer Metadata named an issuer other than the requested identifier.
    IssuerMetadataIssuerMismatch,
    /// Signed Credential Issuer Metadata has an invalid JWS or claims shape.
    InvalidSignedMetadata,
    /// Signed Credential Issuer Metadata is expired.
    ExpiredSignedMetadata,
    /// Signed metadata was issued beyond allowed clock skew.
    FutureSignedMetadata,
    /// Signed metadata is older than wallet freshness policy permits.
    StaleSignedMetadata,
    /// Signed metadata named an asymmetric algorithm this implementation does not support.
    SignedMetadataUnsupportedAlgorithm,
    /// Signed metadata used a supported algorithm excluded by wallet policy.
    SignedMetadataAlgorithmNotAllowed,
    /// Signed metadata signature was cryptographically rejected.
    SignedMetadataSignatureRejected,
    /// Signed metadata signer was rejected by trust policy.
    UntrustedSignedMetadata,
    /// Signed metadata trust could not be established conclusively.
    SignedMetadataTrustIndeterminate,
    /// Signed metadata trust evidence expired before it was consumed.
    SignedMetadataTrustEvidenceStale,
    /// Signed metadata trust evidence was evaluated beyond the trusted clock.
    SignedMetadataTrustEvidenceFutureIssued,
    /// Signed metadata trust provenance was incomplete or inconsistent.
    InvalidSignedMetadataTrustEvidence,
}

/// Typed wallet error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{status:?}")]
pub struct WalletError {
    status: WalletStatus,
}

impl WalletError {
    /// Creates a wallet error.
    #[must_use]
    pub const fn new(status: WalletStatus) -> Self {
        Self { status }
    }

    /// Returns the deterministic status value.
    #[must_use]
    pub const fn status(&self) -> WalletStatus {
        self.status
    }
}
