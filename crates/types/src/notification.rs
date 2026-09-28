// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Notification Endpoint request types.

use core::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::validation::{
    is_optional_non_empty, parse_json, to_json, validate_non_empty_asciiish,
    EXTENSIBLE_DOCUMENT_JSON,
};

/// Final-spec notification event values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    /// Credential was accepted and stored by the Wallet.
    CredentialAccepted,
    /// Issuance failed for a non-user-deletion reason.
    CredentialFailure,
    /// Credential was deleted or issuance was abandoned by user action.
    CredentialDeleted,
}

/// Notification Endpoint request body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRequest {
    /// Identifier received in the Credential Response.
    pub notification_id: String,
    /// Event being reported.
    pub event: NotificationEvent,
    /// Optional ASCII diagnostic description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_description: Option<String>,
}

impl Debug for NotificationRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NotificationRequest")
            .field("notification_id", &"<redacted>")
            .field("event", &self.event)
            .field(
                "event_description",
                &self.event_description.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for NotificationRequest {
    fn drop(&mut self) {
        self.notification_id.zeroize();
        self.event_description.zeroize();
    }
}

impl NotificationRequest {
    /// Parses and validates notification JSON.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        // OpenID4VCI 1.0 §11.1 requires Credential Issuers to ignore
        // unrecognized notification parameters.
        let request: Self = parse_json(body, EXTENSIBLE_DOCUMENT_JSON)?;
        request.validate()?;
        Ok(request)
    }

    /// Serializes a validated notification request.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        self.validate()?;
        to_json(self)
    }

    /// Validates final-spec notification shape and ASCII description rules.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_non_empty_asciiish(&self.notification_id)?;
        is_optional_non_empty(&self.event_description)?;
        if let Some(description) = &self.event_description {
            for byte in description.as_bytes() {
                let valid = matches!(*byte, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e);
                if !valid {
                    return Err(OpenId4VciError::new(Reason::InvalidNotification));
                }
            }
        }
        Ok(())
    }
}

#[path = "tests/notification_tests.rs"]
#[cfg(test)]
mod notification_tests;
