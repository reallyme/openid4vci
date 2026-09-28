// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed error model for OpenID4VCI wire validation.

use core::fmt::{Display, Formatter};

use thiserror::Error;

/// Result alias for this crate.
pub type OpenId4VciResult<T> = Result<T, OpenId4VciError>;

/// Deterministic, non-PII reason codes for protocol validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// A required field was missing.
    MissingRequiredField,
    /// A field that must be absent was present.
    ForbiddenField,
    /// A string was empty or contained prohibited control characters.
    InvalidString,
    /// A URL was malformed or used a disallowed scheme.
    InvalidUrl,
    /// JSON serialization or deserialization failed.
    InvalidJson,
    /// A JSON document exceeded this crate's defensive size limit.
    PayloadTooLarge,
    /// A credential request did not identify exactly one credential target.
    InvalidCredentialSelector,
    /// A proofs object was absent or empty when a proof was required.
    ProofRequired,
    /// A proofs object used an unsupported or malformed proof type.
    InvalidProofs,
    /// The credential response mixed immediate and deferred response members.
    InvalidCredentialResponse,
    /// A notification event or identifier was malformed.
    InvalidNotification,
    /// A JWK contained secret material or was not an asymmetric public key.
    InvalidJwk,
    /// A public JWK Set was empty, malformed, or ambiguously identified.
    InvalidJwkSet,
}

impl Display for Reason {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MissingRequiredField => "missing_required_field",
            Self::ForbiddenField => "forbidden_field",
            Self::InvalidString => "invalid_string",
            Self::InvalidUrl => "invalid_url",
            Self::InvalidJson => "invalid_json",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidCredentialSelector => "invalid_credential_selector",
            Self::ProofRequired => "proof_required",
            Self::InvalidProofs => "invalid_proofs",
            Self::InvalidCredentialResponse => "invalid_credential_response",
            Self::InvalidNotification => "invalid_notification",
            Self::InvalidJwk => "invalid_jwk",
            Self::InvalidJwkSet => "invalid_jwk_set",
        })
    }
}

/// Error value with a typed reason and no secret-bearing context.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{reason}")]
pub struct OpenId4VciError {
    reason: Reason,
}

impl OpenId4VciError {
    /// Creates an error from a deterministic reason code.
    #[must_use]
    pub const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Returns the non-PII reason code.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }
}
