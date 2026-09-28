// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9457 Problem Details support for HTTP adapters.

use serde::{Deserialize, Serialize};

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::validation::to_json;

/// Media type for RFC 9457 problem details JSON.
pub const PROBLEM_JSON_CONTENT_TYPE: &str = "application/problem+json";

/// Problem type categories used by the OpenID4VCI HTTP boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemType {
    /// Invalid client input.
    InvalidRequest,
    /// Invalid or missing proof.
    InvalidProof,
    /// Invalid nonce.
    InvalidNonce,
    /// Invalid notification identifier (OpenID4VCI 1.0 §11.3 `invalid_notification_id`).
    InvalidNotificationId,
    /// Malformed Notification Request (OpenID4VCI 1.0 §11.3 `invalid_notification_request`).
    InvalidNotificationRequest,
    /// Requested credential configuration is unknown
    /// (OpenID4VCI 1.0 §8.3.1.2 `unknown_credential_configuration`).
    UnsupportedCredential,
    /// Requested credential identifier is unknown
    /// (OpenID4VCI 1.0 §8.3.1.2 `unknown_credential_identifier`).
    UnknownCredentialIdentifier,
    /// Credential Request encryption parameters were missing or invalid
    /// (OpenID4VCI 1.0 §8.3.1.2 `invalid_encryption_parameters`).
    EncryptionRequired,
    /// Deferred transaction identifier is invalid or expired
    /// (OpenID4VCI 1.0 §9.3 `invalid_transaction_id`).
    InvalidTransaction,
    /// The request body is too large.
    PayloadTooLarge,
    /// Backing storage is unavailable.
    StorageUnavailable,
    /// Server-side failure.
    ServerError,
}

impl ProblemType {
    /// Stable OpenID4VCI / OAuth error code emitted on the wire.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidProof => "invalid_proof",
            Self::InvalidNonce => "invalid_nonce",
            Self::InvalidNotificationId => "invalid_notification_id",
            Self::InvalidNotificationRequest => "invalid_notification_request",
            Self::UnsupportedCredential => "unknown_credential_configuration",
            Self::UnknownCredentialIdentifier => "unknown_credential_identifier",
            Self::EncryptionRequired => "invalid_encryption_parameters",
            Self::InvalidTransaction => "invalid_transaction_id",
            Self::PayloadTooLarge => "request_too_large",
            Self::StorageUnavailable => "storage_unavailable",
            Self::ServerError => "server_error",
        }
    }

    /// Recommended HTTP status code.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidRequest | Self::InvalidProof | Self::InvalidNonce => 400,
            Self::InvalidNotificationId | Self::InvalidNotificationRequest => 400,
            Self::UnsupportedCredential | Self::UnknownCredentialIdentifier => 400,
            Self::EncryptionRequired => 400,
            Self::InvalidTransaction => 400,
            Self::PayloadTooLarge => 413,
            Self::StorageUnavailable => 503,
            Self::ServerError => 500,
        }
    }
}

/// RFC 9457 problem details body with OAuth-compatible error code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// Problem type URI.
    #[serde(rename = "type")]
    pub type_url: String,
    /// Short problem title.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Optional occurrence URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// OAuth-style error code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProblemDetails {
    /// Builds problem details from a problem category.
    #[must_use]
    pub fn new(problem_type: ProblemType, instance: Option<String>) -> Self {
        let code = problem_type.error_code();
        Self {
            type_url: "about:blank".to_owned(),
            title: code.to_owned(),
            status: problem_type.status(),
            instance,
            error: Some(code.to_owned()),
        }
    }

    /// Maps a typed OpenID4VCI error into a problem details body.
    #[must_use]
    pub fn from_error(error: OpenId4VciError, instance: Option<String>) -> Self {
        let problem_type = match error.reason() {
            Reason::PayloadTooLarge => ProblemType::PayloadTooLarge,
            Reason::ProofRequired | Reason::InvalidProofs => ProblemType::InvalidProof,
            // A malformed Notification Request body maps to `invalid_notification_request`;
            // an unknown `notification_id` is surfaced separately by the issuer engine
            // as `IssuerStatus::InvalidNotificationId`.
            Reason::InvalidNotification => ProblemType::InvalidNotificationRequest,
            _ => ProblemType::InvalidRequest,
        };
        Self::new(problem_type, instance)
    }

    /// Maps an issuer engine status code into an RFC 9457 problem body.
    #[must_use]
    pub fn from_issuer_status(status: IssuerProblemStatus, instance: Option<String>) -> Self {
        Self::new(status.problem_type(), instance)
    }

    /// Serializes problem details through the bounded domain JSON boundary.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        to_json(self)
    }
}

/// Issuer status categories known by the RFC 9457 problem mapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerProblemStatus {
    /// The request was malformed.
    InvalidRequest,
    /// The requested credential configuration is unknown.
    UnsupportedCredential,
    /// The requested credential identifier is unknown.
    UnknownCredentialIdentifier,
    /// Proofs were required but absent.
    ProofRequired,
    /// The proof was invalid.
    InvalidProof,
    /// The nonce was invalid.
    InvalidNonce,
    /// Response encryption was required but absent.
    EncryptionRequired,
    /// Deferred transaction was invalid.
    InvalidTransaction,
    /// Notification identifier was invalid.
    InvalidNotificationId,
    /// Storage was unavailable.
    StorageUnavailable,
    /// Credential encoding failed.
    EncodingFailed,
}

impl IssuerProblemStatus {
    /// Returns the RFC 9457 problem category for this issuer status.
    #[must_use]
    pub const fn problem_type(self) -> ProblemType {
        match self {
            Self::InvalidRequest => ProblemType::InvalidRequest,
            Self::UnsupportedCredential => ProblemType::UnsupportedCredential,
            Self::UnknownCredentialIdentifier => ProblemType::UnknownCredentialIdentifier,
            Self::ProofRequired | Self::InvalidProof => ProblemType::InvalidProof,
            Self::InvalidNonce => ProblemType::InvalidNonce,
            Self::EncryptionRequired => ProblemType::EncryptionRequired,
            Self::InvalidTransaction => ProblemType::InvalidTransaction,
            Self::InvalidNotificationId => ProblemType::InvalidNotificationId,
            Self::StorageUnavailable => ProblemType::StorageUnavailable,
            Self::EncodingFailed => ProblemType::ServerError,
        }
    }
}
