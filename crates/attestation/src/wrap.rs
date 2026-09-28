// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attestation JWT wrappers.

use secrecy::{ExposeSecret, SecretString};
use zeroize::ZeroizeOnDrop;

use crate::error::AttestationResult;
use crate::validate::validate_compact_jwt;

/// Secret-bearing wallet attestation JWT wrapper.
#[derive(ZeroizeOnDrop)]
pub struct WalletAttestationJwt {
    jwt: SecretString,
}

impl WalletAttestationJwt {
    /// Creates a wallet attestation JWT wrapper after structural validation.
    pub fn new(jwt: SecretString) -> AttestationResult<Self> {
        validate_compact_jwt(jwt.expose_secret())?;
        Ok(Self { jwt })
    }

    /// Exposes the JWT only at the adapter boundary that must transmit it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.jwt.expose_secret()
    }
}

/// Secret-bearing client-attestation PoP JWT wrapper.
#[derive(ZeroizeOnDrop)]
pub struct ClientAttestationPopJwt {
    jwt: SecretString,
}

impl ClientAttestationPopJwt {
    /// Creates a client-attestation PoP JWT wrapper after structural validation.
    pub fn new(jwt: SecretString) -> AttestationResult<Self> {
        validate_compact_jwt(jwt.expose_secret())?;
        Ok(Self { jwt })
    }

    /// Exposes the JWT only at the adapter boundary that must transmit it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.jwt.expose_secret()
    }
}

/// Key attestation JWT conveyed through an OpenID4VCI proof.
///
/// The compact representation contains claim material even though it is
/// encoded. Keeping the owner non-`Debug` and zeroizing its allocation on drop
/// prevents accidental log disclosure and reduces memory remanence.
#[derive(ZeroizeOnDrop)]
pub struct KeyAttestationJwt {
    jwt: String,
}

impl KeyAttestationJwt {
    /// Creates a key attestation wrapper after compact-JWT shape validation.
    pub fn new(jwt: String) -> AttestationResult<Self> {
        validate_compact_jwt(&jwt)?;
        Ok(Self { jwt })
    }

    /// Returns the JWT value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.jwt
    }
}
