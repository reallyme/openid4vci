// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ECDH-ES key validation and dispatch for wallet JWE operations.

use openid4vci_types::CredentialRequestEncryptionMetadata;
use reallyme_codec::{base64url::base64url_to_bytes, jcs::canonicalize_trusted_json_value};
use reallyme_jose::jwe::{
    decrypt_compact_jwe_bytes, encrypt_compact_jwe_bytes, CompactJweEncryptRequest,
    CompactJwePolicy, CompactJweProtectedHeader, JweContentEncryptionKeyResolver, JweError,
    JweKeyManagementAlgorithm, P256EcdhEsJweKeyEncryptor, P256EcdhEsJweKeyResolver,
};
use reallyme_jose::SecureRandom;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::credential_jwe::CredentialJweContentEncryptionAlgorithm;
use crate::validate_credential_jwk_bounds::{validate_public_jwk_shape, MAX_PUBLIC_JWK_BYTES};
use crate::{WalletError, WalletResult, WalletStatus};

const JWE_ALGORITHM: &str = "ECDH-ES";
const JWK_KEY_TYPE: &str = "EC";
const JWK_USE: &str = "enc";
const CURVE_P256: &str = "P-256";
const P256_COORDINATE_BYTES: usize = 32;
pub(crate) struct SelectedRequestEncryptionKey<'a> {
    pub(crate) public_jwk: &'a Value,
    pub(crate) kid: &'a str,
    pub(crate) content_encryption_algorithm: CredentialJweContentEncryptionAlgorithm,
}

/// Wallet-owned ECDH private key for encrypted Credential Responses.
pub struct CredentialJwePrivateKey {
    private_key: Zeroizing<[u8; P256_COORDINATE_BYTES]>,
    kid: Option<String>,
}

impl CredentialJwePrivateKey {
    /// Construct a P-256 decryption key.
    pub fn p256(
        private_key: Zeroizing<[u8; P256_COORDINATE_BYTES]>,
        kid: Option<String>,
    ) -> WalletResult<Self> {
        validate_private_key(&private_key, kid.as_deref())?;
        Ok(Self { private_key, kid })
    }

    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

pub(crate) fn encrypt_for_public_jwk<R: SecureRandom + ?Sized>(
    request: &CompactJweEncryptRequest<'_>,
    public_jwk: &Value,
    random: &mut R,
) -> WalletResult<String> {
    validate_public_jwk(public_jwk)?;
    match jwk_string(public_jwk, "crv")? {
        CURVE_P256 => {
            let key = uncompressed_public_key(public_jwk, CURVE_P256, P256_COORDINATE_BYTES)?;
            encrypt_compact_jwe_bytes(request, &mut P256EcdhEsJweKeyEncryptor::new(&key), random)
                .map_err(map_encrypt_error)
        }
        _ => Err(jwe_error()),
    }
}

pub(crate) fn select_request_encryption_key(
    metadata: &CredentialRequestEncryptionMetadata,
) -> WalletResult<SelectedRequestEncryptionKey<'_>> {
    metadata
        .validate()
        .map_err(|_| encryption_parameters_error())?;
    let keys = metadata.jwks.keys();

    let content_encryption_algorithm = select_content_encryption_algorithm(
        metadata.enc_values_supported.iter().map(String::as_str),
    )?;
    let public_jwk = keys
        .iter()
        .find(|jwk| {
            let value = jwk.as_value();
            value.get("alg").and_then(Value::as_str) == Some(JWE_ALGORITHM)
                && value.get("kty").and_then(Value::as_str) == Some(JWK_KEY_TYPE)
                && value.get("crv").and_then(Value::as_str) == Some(CURVE_P256)
        })
        .ok_or_else(encryption_parameters_error)?;
    validate_public_jwk(public_jwk.as_value())?;
    let kid = required_kid(public_jwk.as_value())?;
    Ok(SelectedRequestEncryptionKey {
        public_jwk: public_jwk.as_value(),
        kid,
        content_encryption_algorithm,
    })
}

pub(crate) fn validate_response_encryption_key(
    private_key: &CredentialJwePrivateKey,
    public_jwk: &Value,
) -> WalletResult<()> {
    validate_public_jwk(public_jwk)?;
    if jwk_string(public_jwk, "crv")? != CURVE_P256
        || optional_kid(public_jwk)? != private_key.kid()
    {
        return Err(encryption_parameters_error());
    }
    let advertised = uncompressed_public_key(public_jwk, CURVE_P256, P256_COORDINATE_BYTES)?;
    let (derived_compressed, _validated_private_copy) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&private_key.private_key)
            .map_err(|_| encryption_parameters_error())?;
    let derived = reallyme_crypto::p256::decompress_public_key(&derived_compressed)
        .map_err(|_| encryption_parameters_error())?;
    if advertised != derived {
        return Err(encryption_parameters_error());
    }
    Ok(())
}

pub(crate) fn decrypt_with_private_key(
    compact_jwe: &str,
    key: &CredentialJwePrivateKey,
    expected_content_encryption_algorithm: reallyme_jose::jwe::JweContentEncryptionAlgorithm,
) -> WalletResult<Zeroizing<Vec<u8>>> {
    const KEY_ALGORITHMS: &[JweKeyManagementAlgorithm] = &[JweKeyManagementAlgorithm::EcdhEs];
    let content_algorithms = [expected_content_encryption_algorithm];
    let mut policy = CompactJwePolicy::new(KEY_ALGORITHMS, &content_algorithms);
    if let Some(kid) = key.kid() {
        policy = policy.require_kid().with_expected_kid(kid);
    }
    decrypt_with_resolver(
        compact_jwe,
        &policy,
        key.kid(),
        &P256EcdhEsJweKeyResolver::new(key.private_key.as_ref()),
    )
}

fn decrypt_with_resolver(
    compact_jwe: &str,
    policy: &CompactJwePolicy<'_>,
    expected_kid: Option<&str>,
    resolver: &dyn JweContentEncryptionKeyResolver,
) -> WalletResult<Zeroizing<Vec<u8>>> {
    let resolver = ExpectedKidResolver {
        expected_kid,
        inner: resolver,
    };
    decrypt_compact_jwe_bytes(compact_jwe, policy, &resolver).map_err(map_decrypt_error)
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
        if self
            .expected_kid
            .is_some_and(|expected| header.kid.as_deref() != Some(expected))
        {
            return Err(JweError::HeaderPolicyMismatch);
        }
        self.inner
            .resolve_content_encryption_key(header, encrypted_key)
    }
}

pub(crate) fn optional_kid(jwk: &Value) -> WalletResult<Option<&str>> {
    match jwk.get("kid") {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && value.is_ascii() => Ok(Some(value)),
        Some(_) => Err(jwe_error()),
    }
}

fn required_kid(jwk: &Value) -> WalletResult<&str> {
    optional_kid(jwk)?.ok_or_else(encryption_parameters_error)
}

fn select_content_encryption_algorithm<'a>(
    advertised: impl Iterator<Item = &'a str>,
) -> WalletResult<CredentialJweContentEncryptionAlgorithm> {
    let mut supports_a128_gcm = false;
    let mut supports_a192_gcm = false;
    let mut supports_a256_gcm = false;
    for value in advertised {
        match CredentialJweContentEncryptionAlgorithm::parse(value) {
            Ok(CredentialJweContentEncryptionAlgorithm::A128Gcm) => supports_a128_gcm = true,
            Ok(CredentialJweContentEncryptionAlgorithm::A192Gcm) => supports_a192_gcm = true,
            Ok(CredentialJweContentEncryptionAlgorithm::A256Gcm) => supports_a256_gcm = true,
            Err(_) => {}
        }
    }
    if supports_a256_gcm {
        Ok(CredentialJweContentEncryptionAlgorithm::A256Gcm)
    } else if supports_a128_gcm {
        Ok(CredentialJweContentEncryptionAlgorithm::A128Gcm)
    } else if supports_a192_gcm {
        Ok(CredentialJweContentEncryptionAlgorithm::A192Gcm)
    } else {
        Err(encryption_parameters_error())
    }
}

fn validate_public_jwk(jwk: &Value) -> WalletResult<()> {
    validate_public_jwk_shape(jwk).map_err(|_| jwe_error())?;
    let canonical = Zeroizing::new(canonicalize_trusted_json_value(jwk).map_err(|_| jwe_error())?);
    let object = jwk.as_object().ok_or_else(jwe_error)?;
    if canonical.len() > MAX_PUBLIC_JWK_BYTES
        || jwk_string(jwk, "alg")? != JWE_ALGORITHM
        || jwk_string(jwk, "kty")? != JWK_KEY_TYPE
        || object.contains_key("d")
        || object
            .get("use")
            .and_then(Value::as_str)
            .is_some_and(|value| value != JWK_USE)
    {
        return Err(jwe_error());
    }
    optional_kid(jwk)?;
    Ok(())
}

fn uncompressed_public_key(
    jwk: &Value,
    expected_curve: &str,
    coordinate_length: usize,
) -> WalletResult<Vec<u8>> {
    if jwk_string(jwk, "crv")? != expected_curve {
        return Err(jwe_error());
    }
    let x = decode_coordinate(jwk, "x", coordinate_length)?;
    let y = decode_coordinate(jwk, "y", coordinate_length)?;
    let coordinates_length = coordinate_length.checked_mul(2).ok_or_else(jwe_error)?;
    let capacity = coordinates_length.checked_add(1).ok_or_else(jwe_error)?;
    let mut uncompressed = Vec::with_capacity(capacity);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    if uncompressed.len() != capacity {
        return Err(jwe_error());
    }
    Ok(uncompressed)
}

fn decode_coordinate(jwk: &Value, name: &'static str, length: usize) -> WalletResult<Vec<u8>> {
    let decoded = base64url_to_bytes(jwk_string(jwk, name)?).map_err(|_| jwe_error())?;
    if decoded.len() != length {
        return Err(jwe_error());
    }
    Ok(decoded)
}

fn jwk_string<'a>(jwk: &'a Value, name: &'static str) -> WalletResult<&'a str> {
    jwk.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.is_ascii())
        .ok_or_else(jwe_error)
}

fn validate_private_key(
    private_key: &[u8; P256_COORDINATE_BYTES],
    kid: Option<&str>,
) -> WalletResult<()> {
    if kid.is_some_and(|value| value.is_empty() || !value.is_ascii()) {
        return Err(jwe_error());
    }
    reallyme_crypto::p256::generate_p256_keypair_from_secret_key(private_key)
        .map(|_| ())
        .map_err(|_| jwe_error())?;
    Ok(())
}

fn map_encrypt_error(_error: JweError) -> WalletError {
    WalletError::new(WalletStatus::EncryptionFailed)
}

fn map_decrypt_error(_error: JweError) -> WalletError {
    WalletError::new(WalletStatus::EncryptedResponseRejected)
}

const fn jwe_error() -> WalletError {
    encryption_parameters_error()
}

const fn encryption_parameters_error() -> WalletError {
    WalletError::new(WalletStatus::InvalidEncryptionParameters)
}
