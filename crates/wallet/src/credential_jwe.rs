// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet adapters for encrypted Credential Requests and Responses.

use core::fmt::{Debug, Formatter};

use openid4vci_types::{
    CredentialRequest, CredentialRequestEncryptionMetadata, CredentialResponse,
    CredentialResponseEncryption, DeferredCredentialRequest,
};
use reallyme_jose::jwe::{CompactJweEncryptRequest, JweContentEncryptionAlgorithm};
use zeroize::{Zeroize, Zeroizing};

use crate::credential_jwe_key::{
    decrypt_with_private_key, encrypt_for_public_jwk, select_request_encryption_key,
    validate_response_encryption_key, CredentialJwePrivateKey,
};
use crate::{WalletError, WalletResult, WalletStatus};

const MAX_CREDENTIAL_REQUEST_PLAINTEXT_BYTES: usize = 131_072;
const MAX_CREDENTIAL_RESPONSE_PLAINTEXT_BYTES: usize = 131_072;
const MAX_COMPACT_JWE_BYTES: usize = 262_144;

/// JWE content-encryption algorithms supported for OpenID4VCI messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialJweContentEncryptionAlgorithm {
    /// AES-128 in Galois/Counter Mode.
    A128Gcm,
    /// AES-192 in Galois/Counter Mode.
    A192Gcm,
    /// AES-256 in Galois/Counter Mode.
    A256Gcm,
}

impl CredentialJweContentEncryptionAlgorithm {
    /// Parse an issuer-advertised JWE `enc` value.
    pub fn parse(value: &str) -> WalletResult<Self> {
        match value {
            "A128GCM" => Ok(Self::A128Gcm),
            "A192GCM" => Ok(Self::A192Gcm),
            "A256GCM" => Ok(Self::A256Gcm),
            _ => Err(encryption_parameters_error()),
        }
    }

    const fn jose(self) -> JweContentEncryptionAlgorithm {
        match self {
            Self::A128Gcm => JweContentEncryptionAlgorithm::A128Gcm,
            Self::A192Gcm => JweContentEncryptionAlgorithm::A192Gcm,
            Self::A256Gcm => JweContentEncryptionAlgorithm::A256Gcm,
        }
    }
}

/// Encrypted compact-JWE Credential Request body.
pub struct EncryptedCredentialRequest {
    compact_jwe: Zeroizing<String>,
}

impl EncryptedCredentialRequest {
    /// Borrow the compact body for an `application/jwt` HTTP request.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.compact_jwe.as_str()
    }
}

impl Debug for EncryptedCredentialRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("EncryptedCredentialRequest([REDACTED])")
    }
}

/// Encrypts Credential Requests to issuer-advertised ECDH-ES public keys.
#[derive(Debug, Default, Clone, Copy)]
pub struct JoseJweCredentialRequestEncryptor;

impl JoseJweCredentialRequestEncryptor {
    /// Construct a production encryptor backed by the operating-system CSPRNG.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Encrypt a validated request for transport as `application/jwt`.
    pub fn encrypt_request(
        &self,
        request: &CredentialRequest,
        issuer_metadata: &CredentialRequestEncryptionMetadata,
    ) -> WalletResult<EncryptedCredentialRequest> {
        request
            .validate()
            .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
        let plaintext = request
            .to_json()
            .map_err(|_| WalletError::new(WalletStatus::EncryptionFailed))?;
        self.encrypt_serialized_request(plaintext, issuer_metadata)
    }

    /// Encrypt a validated Deferred Credential Request for `application/jwt` transport.
    pub fn encrypt_deferred_request(
        &self,
        request: &DeferredCredentialRequest,
        issuer_metadata: &CredentialRequestEncryptionMetadata,
    ) -> WalletResult<EncryptedCredentialRequest> {
        request
            .validate()
            .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
        let plaintext = request
            .to_json()
            .map_err(|_| WalletError::new(WalletStatus::EncryptionFailed))?;
        self.encrypt_serialized_request(plaintext, issuer_metadata)
    }

    fn encrypt_serialized_request(
        &self,
        plaintext: String,
        issuer_metadata: &CredentialRequestEncryptionMetadata,
    ) -> WalletResult<EncryptedCredentialRequest> {
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() > MAX_CREDENTIAL_REQUEST_PLAINTEXT_BYTES {
            return Err(WalletError::new(WalletStatus::EncryptionFailed));
        }
        let selection = select_request_encryption_key(issuer_metadata)?;
        let algorithm = selection.content_encryption_algorithm.jose();
        let mut encryption = CompactJweEncryptRequest::new(plaintext.as_bytes(), algorithm);
        encryption = encryption.with_kid(selection.kid);
        let mut random = reallyme_crypto::csprng::OsSecureRandom;
        let compact_jwe = encrypt_for_public_jwk(&encryption, selection.public_jwk, &mut random)?;
        if compact_jwe.len() > MAX_COMPACT_JWE_BYTES {
            return Err(WalletError::new(WalletStatus::EncryptionFailed));
        }
        Ok(EncryptedCredentialRequest {
            compact_jwe: Zeroizing::new(compact_jwe),
        })
    }
}

/// Decrypts compact-JWE Credential Responses with a wallet-owned private key.
pub struct JoseJweCredentialResponseDecryptor {
    private_key: CredentialJwePrivateKey,
    expected_content_encryption_algorithm: CredentialJweContentEncryptionAlgorithm,
}

impl JoseJweCredentialResponseDecryptor {
    /// Construct a decryptor bound to the exact algorithm requested by the Wallet.
    pub fn new(
        private_key: CredentialJwePrivateKey,
        requested_encryption: &CredentialResponseEncryption,
    ) -> WalletResult<Self> {
        requested_encryption
            .validate()
            .map_err(|_| encryption_parameters_error())?;
        if requested_encryption.zip.is_some() {
            return Err(encryption_parameters_error());
        }
        validate_response_encryption_key(&private_key, requested_encryption.jwk.as_value())?;
        let expected_content_encryption_algorithm =
            CredentialJweContentEncryptionAlgorithm::parse(&requested_encryption.enc)?;
        Ok(Self {
            private_key,
            expected_content_encryption_algorithm,
        })
    }

    /// Authenticate, decrypt, and strictly parse one Credential Response.
    pub fn decrypt_response(&self, compact_jwe: &str) -> WalletResult<CredentialResponse> {
        if compact_jwe.is_empty() || compact_jwe.len() > MAX_COMPACT_JWE_BYTES {
            return Err(encrypted_response_error());
        }
        let mut plaintext = decrypt_with_private_key(
            compact_jwe,
            &self.private_key,
            self.expected_content_encryption_algorithm.jose(),
        )?;
        if plaintext.len() > MAX_CREDENTIAL_RESPONSE_PLAINTEXT_BYTES {
            return Err(encrypted_response_error());
        }
        let plaintext = match String::from_utf8(core::mem::take(&mut *plaintext)) {
            Ok(value) => Zeroizing::new(value),
            Err(error) => {
                let mut rejected = Zeroizing::new(error.into_bytes());
                rejected.zeroize();
                return Err(encrypted_response_error());
            }
        };
        CredentialResponse::parse_json(plaintext.as_str()).map_err(|_| encrypted_response_error())
    }
}

const fn encryption_parameters_error() -> WalletError {
    WalletError::new(WalletStatus::InvalidEncryptionParameters)
}

const fn encrypted_response_error() -> WalletError {
    WalletError::new(WalletStatus::EncryptedResponseRejected)
}

#[cfg(test)]
#[path = "credential_jwe_tests.rs"]
mod tests;
