// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CSPRNG-backed opaque identifiers for issuer-managed protocol state.

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::RngOutputKind;
use reallyme_crypto::csprng::{generate_bytes, OsSecureRandom};

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

const OPAQUE_IDENTIFIER_RANDOM_BYTES: usize = 32;

/// Generates unpredictable deferred-transaction identifiers.
pub trait TransactionIdGenerator {
    /// Returns a fresh transaction identifier.
    fn generate_transaction_id(&self) -> IssuerResult<String>;
}

/// Operating-system CSPRNG-backed deferred-transaction identifier generator.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsTransactionIdGenerator;

impl TransactionIdGenerator for OsTransactionIdGenerator {
    fn generate_transaction_id(&self) -> IssuerResult<String> {
        generate_opaque_identifier()
    }
}

/// Generates unpredictable notification identifiers.
pub trait NotificationIdGenerator {
    /// Returns a fresh notification identifier.
    fn generate_notification_id(&self) -> IssuerResult<String>;
}

/// Operating-system CSPRNG-backed notification identifier generator.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsNotificationIdGenerator;

impl NotificationIdGenerator for OsNotificationIdGenerator {
    fn generate_notification_id(&self) -> IssuerResult<String> {
        generate_opaque_identifier()
    }
}

fn generate_opaque_identifier() -> IssuerResult<String> {
    let mut random = OsSecureRandom;
    let value =
        generate_bytes::<OPAQUE_IDENTIFIER_RANDOM_BYTES>(&mut random, RngOutputKind::Generic)
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
    Ok(bytes_to_base64url(value.as_bytes()))
}
