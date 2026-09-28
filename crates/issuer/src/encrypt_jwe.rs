// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `reallyme-jose` backed Credential Request and Response JWE adapters.
//!
//! The issuer engine owns the OpenID4VCI policy boundary: which wallet JWK
//! shapes are acceptable, how failures map to issuer errors, and how encrypted
//! request plaintext enters the existing JSON parser. JOSE owns compact-JWE
//! serialization, ECDH-ES key agreement, AES-GCM sealing, and authentication.

use openid4vci_types::{CredentialResponse, CredentialResponseEncryption};
use reallyme_jose::jwe::{
    decrypt_compact_jwe_bytes, encrypt_compact_jwe_bytes, CompactJweEncryptRequest,
    CompactJwePolicy, CompactJweProtectedHeader, JweContentEncryptionAlgorithm,
    JweContentEncryptionKeyResolver, JweError, JweKeyManagementAlgorithm,
    P256EcdhEsJweKeyEncryptor, P256EcdhEsJweKeyResolver,
};
#[cfg(feature = "native")]
use reallyme_jose::jwe::{
    P384EcdhEsJweKeyEncryptor, P384EcdhEsJweKeyResolver, P521EcdhEsJweKeyEncryptor,
    P521EcdhEsJweKeyResolver,
};
use reallyme_jose::SecureRandom;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::encrypt::{
    CredentialRequestDecryptor, CredentialResponseEncryptor, DecryptedCredentialRequestJson,
    EncryptedCredentialResponse, DEFAULT_MAX_CREDENTIAL_REQUEST_JSON_BYTES,
};
use crate::error::{IssuerError, IssuerResult, IssuerStatus};
use jwk::{
    ec_public_key_sec1_from_jwk, jwk_crv, optional_ascii_string, validate_ec_public_key,
    validate_optional_kid, validate_wallet_jwk, CURVE_P256, P256_COORDINATE_BYTES,
};
#[cfg(feature = "native")]
use jwk::{CURVE_P384, CURVE_P521, P384_COORDINATE_BYTES, P521_COORDINATE_BYTES};

mod jwk;

const JWE_ALG_ECDH_ES: &str = "ECDH-ES";
/// Maximum cleartext Credential Response passed to a JWE provider.
///
/// This is intentionally below the compact response cap because base64url and
/// protected-header expansion increase the final wire size.
const MAX_CREDENTIAL_RESPONSE_JWE_PLAINTEXT_BYTES: usize = 131_072;

const OPENID4VCI_REQUEST_KEY_MANAGEMENT_ALGORITHMS: &[JweKeyManagementAlgorithm] =
    &[JweKeyManagementAlgorithm::EcdhEs];
const OPENID4VCI_REQUEST_CONTENT_ENCRYPTION_ALGORITHMS: &[JweContentEncryptionAlgorithm] = &[
    JweContentEncryptionAlgorithm::A128Gcm,
    JweContentEncryptionAlgorithm::A192Gcm,
    JweContentEncryptionAlgorithm::A256Gcm,
];

/// Concrete compact-JWE response encryptor backed by `reallyme-jose`.
#[derive(Debug, Default, Clone, Copy)]
pub struct JoseJweCredentialResponseEncryptor;

impl JoseJweCredentialResponseEncryptor {
    /// Builds an encryptor using the operating-system CSPRNG for JWE IVs and
    /// ephemeral ECDH key material.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CredentialResponseEncryptor for JoseJweCredentialResponseEncryptor {
    fn validate_parameters(&self, encryption: &CredentialResponseEncryption) -> IssuerResult<()> {
        if encryption.zip.is_some() {
            return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
        }
        let _ = content_encryption_algorithm(&encryption.enc)?;
        validate_wallet_jwk(encryption.jwk.as_value())?;
        let coordinate_len = match jwk_crv(encryption.jwk.as_value())? {
            CURVE_P256 => P256_COORDINATE_BYTES,
            #[cfg(feature = "native")]
            CURVE_P384 => P384_COORDINATE_BYTES,
            #[cfg(feature = "native")]
            CURVE_P521 => P521_COORDINATE_BYTES,
            _ => return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters)),
        };
        let curve = jwk_crv(encryption.jwk.as_value())?;
        let public_key =
            ec_public_key_sec1_from_jwk(encryption.jwk.as_value(), curve, coordinate_len)?;
        validate_ec_public_key(curve, &public_key)?;
        let _ = optional_ascii_string(encryption.jwk.as_value(), "kid")?;
        Ok(())
    }

    fn encrypt_response(
        &self,
        response: &CredentialResponse,
        encryption: &CredentialResponseEncryption,
    ) -> IssuerResult<EncryptedCredentialResponse> {
        self.validate_parameters(encryption)?;
        let enc = content_encryption_algorithm(&encryption.enc)?;
        let kid = optional_ascii_string(encryption.jwk.as_value(), "kid")?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(response)
                .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
        );
        if plaintext.len() > MAX_CREDENTIAL_RESPONSE_JWE_PLAINTEXT_BYTES {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        let mut request = CompactJweEncryptRequest::new(&plaintext, enc);
        if let Some(kid) = kid {
            request = request.with_kid(kid);
        }
        let mut rng = reallyme_crypto::csprng::OsSecureRandom;
        let compact = encrypt_for_wallet(&request, encryption.jwk.as_value(), &mut rng)?;
        EncryptedCredentialResponse::new(compact)
    }
}

/// Private ECDH-ES key used to decrypt encrypted Credential Requests.
///
/// The private scalar is held in a zeroizing buffer. The optional `kid` is not
/// secret; when configured it is enforced against the protected JWE header so a
/// service cannot silently decrypt traffic addressed to a different advertised
/// issuer key.
pub enum JoseJwePrivateKey {
    /// P-256 ECDH private scalar.
    P256 {
        /// P-256 private scalar bytes.
        private_key: Zeroizing<Vec<u8>>,
        /// Optional advertised key identifier required in encrypted requests.
        kid: Option<String>,
    },
    #[cfg(feature = "native")]
    /// P-384 ECDH private scalar.
    P384 {
        /// P-384 private scalar bytes.
        private_key: Zeroizing<Vec<u8>>,
        /// Optional advertised key identifier required in encrypted requests.
        kid: Option<String>,
    },
    #[cfg(feature = "native")]
    /// P-521 ECDH private scalar.
    P521 {
        /// P-521 private scalar bytes.
        private_key: Zeroizing<Vec<u8>>,
        /// Optional advertised key identifier required in encrypted requests.
        kid: Option<String>,
    },
}

impl JoseJwePrivateKey {
    /// Builds a P-256 private key for encrypted Credential Request decryption.
    pub fn p256(private_key: Vec<u8>, kid: Option<String>) -> IssuerResult<Self> {
        validate_private_key_len(private_key.len(), P256_COORDINATE_BYTES)?;
        validate_optional_kid(kid.as_deref())?;
        Ok(Self::P256 {
            private_key: Zeroizing::new(private_key),
            kid,
        })
    }

    #[cfg(feature = "native")]
    /// Builds a P-384 private key for encrypted Credential Request decryption.
    pub fn p384(private_key: Vec<u8>, kid: Option<String>) -> IssuerResult<Self> {
        validate_private_key_len(private_key.len(), P384_COORDINATE_BYTES)?;
        validate_optional_kid(kid.as_deref())?;
        Ok(Self::P384 {
            private_key: Zeroizing::new(private_key),
            kid,
        })
    }

    #[cfg(feature = "native")]
    /// Builds a P-521 private key for encrypted Credential Request decryption.
    pub fn p521(private_key: Vec<u8>, kid: Option<String>) -> IssuerResult<Self> {
        validate_private_key_len(private_key.len(), P521_COORDINATE_BYTES)?;
        validate_optional_kid(kid.as_deref())?;
        Ok(Self::P521 {
            private_key: Zeroizing::new(private_key),
            kid,
        })
    }

    fn kid(&self) -> Option<&str> {
        match self {
            Self::P256 { kid, .. } => kid.as_deref(),
            #[cfg(feature = "native")]
            Self::P384 { kid, .. } | Self::P521 { kid, .. } => kid.as_deref(),
        }
    }
}

/// Concrete compact-JWE request decryptor backed by `reallyme-jose`.
pub struct JoseJweCredentialRequestDecryptor {
    private_key: JoseJwePrivateKey,
}

impl JoseJweCredentialRequestDecryptor {
    /// Builds a decryptor for one issuer request-encryption key.
    #[must_use]
    pub const fn new(private_key: JoseJwePrivateKey) -> Self {
        Self { private_key }
    }
}

impl CredentialRequestDecryptor for JoseJweCredentialRequestDecryptor {
    fn decrypt_request(&self, compact_jwe: &str) -> IssuerResult<DecryptedCredentialRequestJson> {
        let mut plaintext = decrypt_for_issuer(compact_jwe, &self.private_key)?;
        if plaintext.len() > DEFAULT_MAX_CREDENTIAL_REQUEST_JSON_BYTES {
            return Err(IssuerError::new(IssuerStatus::InvalidRequest));
        }
        match String::from_utf8(core::mem::take(&mut *plaintext)) {
            Ok(value) => DecryptedCredentialRequestJson::new(value),
            Err(error) => {
                // `FromUtf8Error` owns the rejected plaintext. Rewrap it so the
                // allocation is cleared instead of being dropped unchanged.
                let _rejected = Zeroizing::new(error.into_bytes());
                Err(IssuerError::new(IssuerStatus::InvalidRequest))
            }
        }
    }
}

fn encrypt_for_wallet<R: SecureRandom + ?Sized>(
    request: &CompactJweEncryptRequest<'_>,
    jwk: &Value,
    rng: &mut R,
) -> IssuerResult<String> {
    validate_wallet_jwk(jwk)?;
    match jwk_crv(jwk)? {
        CURVE_P256 => {
            let public_key = ec_public_key_sec1_from_jwk(jwk, CURVE_P256, P256_COORDINATE_BYTES)?;
            let mut encryptor = P256EcdhEsJweKeyEncryptor::new(&public_key);
            encrypt_compact_jwe_bytes(request, &mut encryptor, rng).map_err(map_encrypt_error)
        }
        #[cfg(feature = "native")]
        CURVE_P384 => {
            let public_key = ec_public_key_sec1_from_jwk(jwk, CURVE_P384, P384_COORDINATE_BYTES)?;
            let mut encryptor = P384EcdhEsJweKeyEncryptor::new(&public_key);
            encrypt_compact_jwe_bytes(request, &mut encryptor, rng).map_err(map_encrypt_error)
        }
        #[cfg(feature = "native")]
        CURVE_P521 => {
            let public_key = ec_public_key_sec1_from_jwk(jwk, CURVE_P521, P521_COORDINATE_BYTES)?;
            let mut encryptor = P521EcdhEsJweKeyEncryptor::new(&public_key);
            encrypt_compact_jwe_bytes(request, &mut encryptor, rng).map_err(map_encrypt_error)
        }
        _ => Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters)),
    }
}

fn decrypt_for_issuer(
    compact_jwe: &str,
    key: &JoseJwePrivateKey,
) -> IssuerResult<Zeroizing<Vec<u8>>> {
    let mut policy = CompactJwePolicy::new(
        OPENID4VCI_REQUEST_KEY_MANAGEMENT_ALGORITHMS,
        OPENID4VCI_REQUEST_CONTENT_ENCRYPTION_ALGORITHMS,
    );
    if let Some(kid) = key.kid() {
        policy = policy.require_kid().with_expected_kid(kid);
    }
    match key {
        JoseJwePrivateKey::P256 { private_key, .. } => {
            let resolver = P256EcdhEsJweKeyResolver::new(private_key);
            decrypt_with_expected_kid(compact_jwe, &policy, key.kid(), &resolver)
        }
        #[cfg(feature = "native")]
        JoseJwePrivateKey::P384 { private_key, .. } => {
            let resolver = P384EcdhEsJweKeyResolver::new(private_key);
            decrypt_with_expected_kid(compact_jwe, &policy, key.kid(), &resolver)
        }
        #[cfg(feature = "native")]
        JoseJwePrivateKey::P521 { private_key, .. } => {
            let resolver = P521EcdhEsJweKeyResolver::new(private_key);
            decrypt_with_expected_kid(compact_jwe, &policy, key.kid(), &resolver)
        }
    }
}

fn decrypt_with_expected_kid(
    compact_jwe: &str,
    policy: &CompactJwePolicy<'_>,
    expected_kid: Option<&str>,
    resolver: &dyn JweContentEncryptionKeyResolver,
) -> IssuerResult<Zeroizing<Vec<u8>>> {
    let checking_resolver = ExpectedKidResolver {
        expected_kid,
        inner: resolver,
    };
    decrypt_compact_jwe_bytes(compact_jwe, policy, &checking_resolver).map_err(map_decrypt_error)
}

struct ExpectedKidResolver<'a> {
    expected_kid: Option<&'a str>,
    inner: &'a dyn JweContentEncryptionKeyResolver,
}

impl JweContentEncryptionKeyResolver for ExpectedKidResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        if let Some(expected) = self.expected_kid {
            if header.kid.as_deref() != Some(expected) {
                return Err(JweError::HeaderPolicyMismatch);
            }
        }
        self.inner
            .resolve_content_encryption_key(header, encrypted_key)
    }
}

fn content_encryption_algorithm(value: &str) -> IssuerResult<JweContentEncryptionAlgorithm> {
    match value {
        "A128GCM" => Ok(JweContentEncryptionAlgorithm::A128Gcm),
        "A192GCM" => Ok(JweContentEncryptionAlgorithm::A192Gcm),
        "A256GCM" => Ok(JweContentEncryptionAlgorithm::A256Gcm),
        _ => Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters)),
    }
}

fn validate_private_key_len(actual: usize, expected: usize) -> IssuerResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(IssuerError::new(IssuerStatus::InvalidRequest))
    }
}

fn map_encrypt_error(error: JweError) -> IssuerError {
    match error {
        JweError::InvalidKeyAgreementKey
        | JweError::InvalidContentEncryptionKey
        | JweError::UnsupportedContentEncryptionAlgorithm
        | JweError::UnsupportedKeyManagementAlgorithm
        | JweError::MissingRequiredHeaderParameter
        | JweError::HeaderPolicyMismatch
        | JweError::KidPolicyMismatch
        | JweError::TypPolicyMismatch
        | JweError::CtyPolicyMismatch
        | JweError::ApuPolicyMismatch
        | JweError::ApvPolicyMismatch => {
            IssuerError::new(IssuerStatus::InvalidEncryptionParameters)
        }
        JweError::InvalidPayloadJson
        | JweError::InvalidHeader
        | JweError::InvalidContentCipherInput
        | JweError::InvalidEncryptedKey
        | JweError::InvalidCompact
        | JweError::InvalidEncoding
        | JweError::InputTooLarge
        | JweError::Decrypt
        | JweError::Encrypt
        | JweError::InvalidSharedSecret
        | JweError::KeyDerivation
        | JweError::LengthOverflow
        | JweError::Randomness => IssuerError::new(IssuerStatus::EncodingFailed),
        _ => IssuerError::new(IssuerStatus::EncodingFailed),
    }
}

fn map_decrypt_error(_error: JweError) -> IssuerError {
    IssuerError::new(IssuerStatus::InvalidRequest)
}
