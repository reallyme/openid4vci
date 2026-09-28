// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential response encryption boundary.
//!
//! OpenID4VCI encrypted Credential and Deferred Credential responses are JWT
//! bodies containing compact JWE. Actual JOSE encryption stays injected so this
//! crate can enforce protocol routing without owning key-management details.

use core::fmt::{Debug, Formatter};
use std::borrow::Cow;

use openid4vci_types::{
    CredentialRequest, CredentialResponse, CredentialResponseEncryption,
    CredentialResponseEncryptionMetadata, DeferredCredentialRequest,
};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

/// Maximum compact JWE response accepted from an encryption backend.
pub const DEFAULT_MAX_ENCRYPTED_RESPONSE_BYTES: usize = 256 * 1024;
/// Maximum cleartext Credential Request JSON retained across adapter boundaries.
pub const DEFAULT_MAX_CREDENTIAL_REQUEST_JSON_BYTES: usize = 64 * 1024;
const COMPACT_JWE_SEGMENT_COUNT: usize = 5;

/// HTTP/media response body produced by issuer endpoint logic.
#[derive(Debug, PartialEq)]
pub enum CredentialResponseBody {
    /// Plain JSON Credential Response.
    Json(CredentialResponse),
    /// Encrypted compact JWE response body with `application/jwt`. `deferred`
    /// records whether the encrypted response is a still-pending deferred
    /// response, which the plaintext body would otherwise reveal via
    /// `transaction_id` (OpenID4VCI 1.0 §8.3 / §9.2 require HTTP 202 then).
    Jwt {
        /// Encrypted compact JWE body.
        encrypted: EncryptedCredentialResponse,
        /// Whether this is a pending deferred response (202).
        deferred: bool,
    },
}

impl CredentialResponseBody {
    /// Returns whether the response is a still-pending deferred response, which
    /// adapters serialize with HTTP status 202 rather than 200.
    #[must_use]
    pub fn is_deferred(&self) -> bool {
        match self {
            Self::Json(response) => response.transaction_id.is_some(),
            Self::Jwt { deferred, .. } => *deferred,
        }
    }
}

/// Compact JWE credential response.
#[derive(PartialEq, Eq)]
pub struct EncryptedCredentialResponse {
    compact_jwe: String,
}

impl Debug for EncryptedCredentialResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EncryptedCredentialResponse")
            .field("compact_jwe", &"<redacted>")
            .finish()
    }
}

impl Drop for EncryptedCredentialResponse {
    fn drop(&mut self) {
        self.compact_jwe.zeroize();
    }
}

impl EncryptedCredentialResponse {
    /// Creates a compact JWE wrapper after structural checks.
    pub fn new(compact_jwe: String) -> IssuerResult<Self> {
        validate_compact_jwe(&compact_jwe)?;
        Ok(Self { compact_jwe })
    }

    /// Returns the compact serialized JWE.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.compact_jwe
    }

    /// Consumes the wrapper and returns the compact serialized JWE.
    #[must_use]
    pub fn into_string(mut self) -> String {
        core::mem::take(&mut self.compact_jwe)
    }
}

/// Injected encryption backend for Credential Response bodies.
pub trait CredentialResponseEncryptor: Send + Sync {
    /// Performs provider-specific validation without issuing or consuming any
    /// one-time state. Endpoint code calls this before nonce consumption and
    /// before a deferred transaction is removed from storage.
    fn validate_parameters(&self, encryption: &CredentialResponseEncryption) -> IssuerResult<()>;

    /// Encrypts a validated Credential Response using wallet-supplied JWE parameters.
    fn encrypt_response(
        &self,
        response: &CredentialResponse,
        encryption: &CredentialResponseEncryption,
    ) -> IssuerResult<EncryptedCredentialResponse>;
}

/// Injected decryption backend for encrypted Credential Request bodies.
///
/// OpenID4VCI 1.0 §8.2 allows the Credential Request to be sent as a compact
/// JWE. Adapters inject a concrete JOSE/JWE backend (for example, backed by
/// `reallyme-jose`) so the issuer engine and HTTP layer stay key-management
/// agnostic, mirroring [`CredentialResponseEncryptor`].
pub trait CredentialRequestDecryptor: Send + Sync {
    /// Decrypts and authenticates a compact-JWE Credential Request body.
    ///
    /// The returned plaintext does not itself confer transport provenance.
    /// Callers must pass the provider through [`decrypt_credential_request_json`]
    /// so the issuer boundary, rather than application code, creates that
    /// capability.
    fn decrypt_request(&self, compact_jwe: &str) -> IssuerResult<DecryptedCredentialRequestJson>;
}

/// Zeroizing plaintext emitted by a trusted Credential Request decryptor.
///
/// This owner deliberately cannot be converted directly into a parsed request.
/// Only [`decrypt_credential_request_json`] can attach authenticated transport
/// provenance after invoking a configured decryptor.
pub struct DecryptedCredentialRequestJson {
    value: Zeroizing<String>,
}

impl DecryptedCredentialRequestJson {
    /// Takes ownership of bounded UTF-8 plaintext after provider authentication.
    pub fn new(value: String) -> IssuerResult<Self> {
        let value = Zeroizing::new(value);
        validate_request_json_size(&value)?;
        Ok(Self { value })
    }

    /// Borrows authenticated plaintext for provider-focused test vectors.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }
}

/// Invokes the trusted decryptor and creates authenticated request provenance.
pub fn decrypt_credential_request_json(
    decryptor: &dyn CredentialRequestDecryptor,
    compact_jwe: &str,
) -> IssuerResult<CredentialRequestJson> {
    let decrypted = decryptor.decrypt_request(compact_jwe)?;
    Ok(CredentialRequestJson {
        value: decrypted.value,
        provenance: RequestEncryptionProvenance::AuthenticatedDecryption,
    })
}

/// Owned cleartext Credential Request JSON.
///
/// The wrapper deliberately omits `Debug`, cloning, and ownership-transfer
/// helpers. Callers can borrow the text for immediate strict parsing, while the
/// allocation is cleared when the boundary owner is dropped.
pub struct CredentialRequestJson {
    value: Zeroizing<String>,
    provenance: RequestEncryptionProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestEncryptionProvenance {
    Plaintext,
    AuthenticatedDecryption,
}

/// Parsed Credential Request retaining its transport-security provenance.
pub struct CredentialRequestInput {
    request: CredentialRequest,
    provenance: RequestEncryptionProvenance,
}

impl CredentialRequestInput {
    /// Borrows the validated request for authorization and issuance selection.
    #[must_use]
    pub const fn request(&self) -> &CredentialRequest {
        &self.request
    }

    pub(crate) const fn was_decrypted(&self) -> bool {
        matches!(
            self.provenance,
            RequestEncryptionProvenance::AuthenticatedDecryption
        )
    }
}

/// Parsed Deferred Credential Request retaining transport-security provenance.
pub struct DeferredCredentialRequestInput {
    request: DeferredCredentialRequest,
    provenance: RequestEncryptionProvenance,
}

impl DeferredCredentialRequestInput {
    /// Borrows the validated request for transaction authorization.
    #[must_use]
    pub const fn request(&self) -> &DeferredCredentialRequest {
        &self.request
    }

    pub(crate) const fn was_decrypted(&self) -> bool {
        matches!(
            self.provenance,
            RequestEncryptionProvenance::AuthenticatedDecryption
        )
    }
}

impl CredentialRequestJson {
    /// Validates and takes ownership of cleartext Credential Request JSON.
    pub fn new(value: String) -> IssuerResult<Self> {
        let value = Zeroizing::new(value);
        validate_request_json_size(&value)?;
        Ok(Self {
            value,
            provenance: RequestEncryptionProvenance::Plaintext,
        })
    }

    /// Borrows the cleartext only for immediate domain parsing.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    /// Strictly parses a Credential Request while retaining provenance.
    pub fn parse_credential_request(&self) -> IssuerResult<CredentialRequestInput> {
        let request = CredentialRequest::parse_json(self.as_str())
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
        Ok(CredentialRequestInput {
            request,
            provenance: self.provenance,
        })
    }

    /// Strictly parses a Deferred Credential Request while retaining provenance.
    pub fn parse_deferred_credential_request(
        &self,
    ) -> IssuerResult<DeferredCredentialRequestInput> {
        let request = DeferredCredentialRequest::parse_json(self.as_str())
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
        Ok(DeferredCredentialRequestInput {
            request,
            provenance: self.provenance,
        })
    }
}

fn validate_request_json_size(value: &str) -> IssuerResult<()> {
    if value.is_empty() || value.len() > DEFAULT_MAX_CREDENTIAL_REQUEST_JSON_BYTES {
        return Err(IssuerError::new(IssuerStatus::InvalidRequest));
    }
    Ok(())
}

/// Enforces OpenID4VCI 1.0 §8.2: a Credential Request that asks for response
/// encryption MUST itself have been sent encrypted, so an attacker cannot
/// substitute the wallet's response-encryption key on a plaintext request. Both
/// facts are supplied by the transport adapter.
pub fn require_encrypted_request_for_response_encryption(
    response_encryption_requested: bool,
    request_was_encrypted: bool,
) -> IssuerResult<()> {
    if response_encryption_requested && !request_was_encrypted {
        return Err(IssuerError::new(IssuerStatus::EncryptionRequired));
    }
    Ok(())
}

/// Validates wallet-supplied response encryption parameters against issuer policy.
pub fn validate_response_encryption_parameters(
    encryption: &CredentialResponseEncryption,
    metadata: Option<&CredentialResponseEncryptionMetadata>,
) -> IssuerResult<()> {
    let alg = jwk_alg(encryption.jwk.as_value())?;
    if let Some(metadata) = metadata {
        let Some(alg_values_supported) = &metadata.alg_values_supported else {
            return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
        };
        if !alg_values_supported.iter().any(|value| value == alg) {
            return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
        }
        let Some(enc_values_supported) = &metadata.enc_values_supported else {
            return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
        };
        if !enc_values_supported
            .iter()
            .any(|value| value == &encryption.enc)
        {
            return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
        }
        if let Some(zip) = encryption.zip.as_deref() {
            let Some(zip_values_supported) = &metadata.zip_values_supported else {
                return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
            };
            if !zip_values_supported.iter().any(|value| value == zip) {
                return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
            }
        }
        return Ok(());
    }
    // Encryption is a negotiated issuer capability. Accepting arbitrary
    // wallet-selected algorithms when no capability was advertised bypasses
    // the issuer's algorithm policy.
    Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))
}

/// Selects the response-encryption parameters that an encryption provider must apply.
///
/// The selected parameters remain byte-for-byte faithful to the authenticated
/// request. OpenID4VCI requires a supplied `zip` value to cause compression;
/// silently removing an unadvertised value would produce a response that no
/// longer follows the Wallet's authenticated encryption request.
pub fn select_response_encryption_parameters<'a>(
    encryption: &'a CredentialResponseEncryption,
    metadata: Option<&CredentialResponseEncryptionMetadata>,
) -> IssuerResult<Cow<'a, CredentialResponseEncryption>> {
    validate_response_encryption_parameters(encryption, metadata)?;
    Ok(Cow::Borrowed(encryption))
}

fn validate_compact_jwe(value: &str) -> IssuerResult<()> {
    if value.is_empty() || value.len() > DEFAULT_MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let mut count = 0usize;
    for segment in value.split('.') {
        if count != 1 && segment.is_empty() {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        if !segment.is_ascii() {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        count = count
            .checked_add(1)
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    }
    if count == COMPACT_JWE_SEGMENT_COUNT {
        Ok(())
    } else {
        Err(IssuerError::new(IssuerStatus::EncodingFailed))
    }
}

fn jwk_alg(jwk: &Value) -> IssuerResult<&str> {
    jwk.get("alg")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.is_ascii())
        .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))
}

#[path = "tests/credential_request_json_tests.rs"]
#[cfg(test)]
mod credential_request_json_tests;
