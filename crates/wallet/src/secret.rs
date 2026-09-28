// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret-bearing wallet wrappers.

use secrecy::{ExposeSecret, SecretString};
use zeroize::ZeroizeOnDrop;

use crate::error::WalletResult;
use crate::validate::validate_secret;

/// Secret-bearing OAuth authorization code.
#[derive(ZeroizeOnDrop)]
pub struct AuthorizationCode {
    code: SecretString,
}

impl AuthorizationCode {
    /// Creates an authorization code wrapper.
    pub fn new(code: SecretString) -> WalletResult<Self> {
        validate_secret(&code)?;
        Ok(Self { code })
    }

    /// Exposes the secret only when constructing the outgoing token request.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.code.expose_secret()
    }
}

/// Secret-bearing pre-authorized code.
#[derive(ZeroizeOnDrop)]
pub struct PreAuthorizedCode {
    code: SecretString,
}

impl PreAuthorizedCode {
    /// Creates a pre-authorized code wrapper.
    pub fn new(code: SecretString) -> WalletResult<Self> {
        validate_secret(&code)?;
        Ok(Self { code })
    }

    /// Exposes the secret only when constructing the outgoing token request.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.code.expose_secret()
    }
}

/// Secret-bearing transaction code.
#[derive(ZeroizeOnDrop)]
pub struct TransactionCode {
    code: SecretString,
}

impl TransactionCode {
    /// Creates a transaction code wrapper.
    pub fn new(code: SecretString) -> WalletResult<Self> {
        validate_secret(&code)?;
        Ok(Self { code })
    }

    /// Exposes the secret only when constructing the outgoing token request.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.code.expose_secret()
    }
}
