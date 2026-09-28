// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OAuth-style OpenID4VCI endpoint error responses.

use core::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::validation::{is_optional_non_empty, parse_json, to_json, CLOSED_OPERATION_JSON};

/// OpenID4VCI and OAuth error code values used by issuance endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialErrorCode {
    /// The Credential Request is malformed.
    InvalidCredentialRequest,
    /// The proof is missing or invalid.
    InvalidProof,
    /// The nonce is missing, expired, or invalid.
    InvalidNonce,
    /// The credential configuration identifier is unknown.
    UnknownCredentialConfiguration,
    /// The credential identifier is unknown.
    UnknownCredentialIdentifier,
    /// Response encryption parameters are missing or invalid.
    InvalidEncryptionParameters,
    /// Credential issuance was denied.
    CredentialRequestDenied,
}

/// Error codes emitted by the Deferred Credential Endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeferredCredentialErrorCode {
    /// The Deferred Credential Request is malformed.
    InvalidCredentialRequest,
    /// The transaction identifier is unknown, expired, or already consumed.
    InvalidTransactionId,
    /// Response encryption parameters are missing or invalid.
    InvalidEncryptionParameters,
    /// Credential issuance was denied.
    CredentialRequestDenied,
}

/// Error response emitted by the Deferred Credential Endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredCredentialErrorResponse {
    /// Stable deferred-endpoint error code.
    pub error: DeferredCredentialErrorCode,
}

/// Error codes emitted by the Notification Endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NotificationErrorCode {
    /// The Notification Request is malformed.
    InvalidNotificationRequest,
    /// The notification identifier is unknown.
    InvalidNotificationId,
}

/// Error response emitted by the Notification Endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationErrorResponse {
    /// Stable notification-endpoint error code.
    pub error: NotificationErrorCode,
}

impl DeferredCredentialErrorResponse {
    /// Parses a bounded deferred-endpoint error response.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        parse_json(body, CLOSED_OPERATION_JSON)
    }

    /// Serializes the deferred-endpoint error response.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        to_json(self)
    }
}

impl NotificationErrorResponse {
    /// Parses a bounded notification-endpoint error response.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        parse_json(body, CLOSED_OPERATION_JSON)
    }

    /// Serializes the notification-endpoint error response.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        to_json(self)
    }
}

/// OAuth-style error response body emitted by OpenID4VCI endpoints.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialErrorResponse {
    /// Stable error code.
    pub error: CredentialErrorCode,
    /// Optional non-sensitive ASCII implementation guidance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl Debug for CredentialErrorResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialErrorResponse")
            .field("error", &self.error)
            .field(
                "error_description",
                &self.error_description.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for CredentialErrorResponse {
    fn drop(&mut self) {
        self.error_description.zeroize();
    }
}

impl CredentialErrorResponse {
    /// Parses and validates an OAuth-style OpenID4VCI endpoint error.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        let response: Self = parse_json(body, CLOSED_OPERATION_JSON)?;
        response.validate()?;
        Ok(response)
    }

    /// Serializes a validated error response.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        self.validate()?;
        to_json(self)
    }

    /// Validates the optional final-spec ASCII description.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        is_optional_non_empty(&self.error_description)?;
        if self.error_description.as_ref().is_some_and(|description| {
            !description
                .bytes()
                .all(|byte| matches!(byte, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        }) {
            return Err(OpenId4VciError::new(Reason::InvalidString));
        }
        Ok(())
    }
}
