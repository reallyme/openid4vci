// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet-side boundary validation helpers.

use secrecy::{ExposeSecret, SecretString};

use crate::error::{WalletError, WalletResult, WalletStatus};

const MAX_PUBLIC_STRING_BYTES: usize = 16 * 1024;

/// Validates a public, non-secret request string.
pub fn validate_public_string(value: &str) -> WalletResult<()> {
    if value.len() > MAX_PUBLIC_STRING_BYTES
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
    {
        return Err(WalletError::new(WalletStatus::InvalidString));
    }
    Ok(())
}

/// Validates a secret-bearing request string before exposing it at the boundary.
pub fn validate_secret(value: &SecretString) -> WalletResult<()> {
    validate_public_string(value.expose_secret())
}
