// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 7518 `DEF` compression for encrypted Credential Responses.

use std::io::Read;

use flate2::read::DeflateEncoder;
use flate2::Compression;
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_jose::jwe::{
    derive_ecdh_es_content_encryption_key, CompactJweProtectedHeader,
    JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm,
};
use reallyme_jose::SecureRandom;
use serde::Serialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::encrypt::DEFAULT_MAX_ENCRYPTED_RESPONSE_BYTES;
use crate::error::{IssuerError, IssuerResult, IssuerStatus};

use super::jwk::{ec_public_key_sec1_from_jwk, jwk_crv, CURVE_P256, P256_COORDINATE_BYTES};
#[cfg(feature = "native")]
use super::jwk::{CURVE_P384, CURVE_P521, P384_COORDINATE_BYTES, P521_COORDINATE_BYTES};

const JWE_ALG_ECDH_ES: &str = "ECDH-ES";
const JWE_COMPRESSION_DEFLATE: &str = "DEF";
const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;
const DEFLATE_OUTPUT_MARGIN_BYTES: usize = 1_024;

#[derive(Serialize)]
struct DeflatedProtectedHeader<'a> {
    alg: &'static str,
    enc: JweContentEncryptionAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    epk: &'a Value,
    zip: &'static str,
}

pub(super) fn encrypt_deflated_response<R: SecureRandom + ?Sized>(
    plaintext: &[u8],
    enc: JweContentEncryptionAlgorithm,
    wallet_jwk: &Value,
    kid: Option<&str>,
    rng: &mut R,
) -> IssuerResult<String> {
    let compressed = deflate(plaintext)?;
    let (epk, shared_secret) = prepare_ephemeral_key(wallet_jwk)?;
    let kdf_header = CompactJweProtectedHeader {
        alg: JweKeyManagementAlgorithm::EcdhEs,
        enc,
        kid: kid.map(str::to_owned),
        apu: None,
        apv: None,
        epk: Some(epk.clone()),
        typ: None,
        cty: None,
    };
    let cek = derive_ecdh_es_content_encryption_key(&shared_secret, &kdf_header)
        .map_err(|_| encoding_failed())?;
    let protected_json = Zeroizing::new(
        serde_json::to_vec(&DeflatedProtectedHeader {
            alg: JWE_ALG_ECDH_ES,
            enc,
            kid,
            epk: &epk,
            zip: JWE_COMPRESSION_DEFLATE,
        })
        .map_err(|_| encoding_failed())?,
    );
    let protected = Zeroizing::new(bytes_to_base64url(&protected_json));
    let mut nonce = [0_u8; reallyme_crypto::aes::AES_128_GCM_NONCE_LENGTH];
    rng.fill_secure(
        &mut nonce,
        reallyme_crypto::core::RngOutputKind::AeadNonce12,
    )
    .map_err(|_| encoding_failed())?;
    let ciphertext_with_tag =
        encrypt_content(enc, &cek, &nonce, protected.as_bytes(), &compressed)?;
    let split_at = ciphertext_with_tag
        .as_bytes()
        .len()
        .checked_sub(enc.tag_len())
        .ok_or_else(encoding_failed)?;
    let ciphertext = ciphertext_with_tag
        .as_bytes()
        .get(..split_at)
        .ok_or_else(encoding_failed)?;
    let tag = ciphertext_with_tag
        .as_bytes()
        .get(split_at..)
        .ok_or_else(encoding_failed)?;
    format_compact_jwe(&protected, &nonce, ciphertext, tag)
}

fn deflate(plaintext: &[u8]) -> IssuerResult<Zeroizing<Vec<u8>>> {
    let capacity = plaintext
        .len()
        .checked_add(DEFLATE_OUTPUT_MARGIN_BYTES)
        .ok_or_else(encoding_failed)?;
    let mut output = Zeroizing::new(Vec::with_capacity(capacity));
    let mut encoder = DeflateEncoder::new(plaintext, Compression::default());
    encoder
        .read_to_end(&mut output)
        .map_err(|_| encoding_failed())?;
    if output.is_empty() || output.len() > DEFAULT_MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(encoding_failed());
    }
    Ok(output)
}

fn prepare_ephemeral_key(wallet_jwk: &Value) -> IssuerResult<(Value, Zeroizing<Vec<u8>>)> {
    match jwk_crv(wallet_jwk)? {
        CURVE_P256 => {
            let recipient =
                ec_public_key_sec1_from_jwk(wallet_jwk, CURVE_P256, P256_COORDINATE_BYTES)?;
            let (ephemeral_public, ephemeral_private) =
                reallyme_crypto::p256::generate_p256_keypair().map_err(|_| encoding_failed())?;
            let shared_secret =
                reallyme_crypto::p256::derive_p256_shared_secret(&ephemeral_private, &recipient)
                    .map_err(|_| encoding_failed())?;
            let epk = ephemeral_public_jwk(
                &ephemeral_public,
                CURVE_P256,
                P256_COORDINATE_BYTES,
                reallyme_crypto::p256::decompress_public_key,
            )?;
            Ok((epk, shared_secret))
        }
        #[cfg(feature = "native")]
        CURVE_P384 => {
            let recipient =
                ec_public_key_sec1_from_jwk(wallet_jwk, CURVE_P384, P384_COORDINATE_BYTES)?;
            let (ephemeral_public, ephemeral_private) =
                reallyme_crypto::p384::generate_p384_keypair().map_err(|_| encoding_failed())?;
            let shared_secret =
                reallyme_crypto::p384::derive_p384_shared_secret(&ephemeral_private, &recipient)
                    .map_err(|_| encoding_failed())?;
            let epk = ephemeral_public_jwk(
                &ephemeral_public,
                CURVE_P384,
                P384_COORDINATE_BYTES,
                reallyme_crypto::p384::decompress_public_key,
            )?;
            Ok((epk, shared_secret))
        }
        #[cfg(feature = "native")]
        CURVE_P521 => {
            let recipient =
                ec_public_key_sec1_from_jwk(wallet_jwk, CURVE_P521, P521_COORDINATE_BYTES)?;
            let (ephemeral_public, ephemeral_private) =
                reallyme_crypto::p521::generate_p521_keypair().map_err(|_| encoding_failed())?;
            let shared_secret =
                reallyme_crypto::p521::derive_p521_shared_secret(&ephemeral_private, &recipient)
                    .map_err(|_| encoding_failed())?;
            let epk = ephemeral_public_jwk(
                &ephemeral_public,
                CURVE_P521,
                P521_COORDINATE_BYTES,
                reallyme_crypto::p521::decompress_public_key,
            )?;
            Ok((epk, shared_secret))
        }
        _ => Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters)),
    }
}

fn ephemeral_public_jwk(
    public_key: &[u8],
    curve: &'static str,
    coordinate_len: usize,
    decompress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
) -> IssuerResult<Value> {
    let uncompressed = if public_key.len()
        == coordinate_len
            .checked_mul(2)
            .and_then(|length| length.checked_add(1))
            .ok_or_else(encoding_failed)?
        && public_key.first().copied() == Some(SEC1_UNCOMPRESSED_PREFIX)
    {
        public_key.to_vec()
    } else {
        decompress(public_key).map_err(|_| encoding_failed())?
    };
    let y_start = coordinate_len.checked_add(1).ok_or_else(encoding_failed)?;
    let y_end = y_start
        .checked_add(coordinate_len)
        .ok_or_else(encoding_failed)?;
    let x = uncompressed.get(1..y_start).ok_or_else(encoding_failed)?;
    let y = uncompressed
        .get(y_start..y_end)
        .ok_or_else(encoding_failed)?;
    if uncompressed.len() != y_end {
        return Err(encoding_failed());
    }
    Ok(json!({
        "kty": "EC",
        "crv": curve,
        "x": bytes_to_base64url(x),
        "y": bytes_to_base64url(y)
    }))
}

fn encrypt_content(
    enc: JweContentEncryptionAlgorithm,
    cek: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> IssuerResult<reallyme_crypto::aes::CiphertextWithTag> {
    match enc {
        JweContentEncryptionAlgorithm::A128Gcm => {
            let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(cek)
                .map_err(|_| encoding_failed())?;
            let nonce = reallyme_crypto::aes::Aes128GcmNonce::from_slice(nonce)
                .map_err(|_| encoding_failed())?;
            reallyme_crypto::aes::encrypt_aes128_gcm(
                &reallyme_crypto::aes::Aes128GcmEncryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    plaintext,
                },
            )
            .map_err(|_| encoding_failed())
        }
        JweContentEncryptionAlgorithm::A192Gcm => {
            let key = reallyme_crypto::aes::Aes192GcmKey::from_slice(cek)
                .map_err(|_| encoding_failed())?;
            let nonce = reallyme_crypto::aes::Aes192GcmNonce::from_slice(nonce)
                .map_err(|_| encoding_failed())?;
            reallyme_crypto::aes::encrypt_aes192_gcm(
                &reallyme_crypto::aes::Aes192GcmEncryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    plaintext,
                },
            )
            .map_err(|_| encoding_failed())
        }
        JweContentEncryptionAlgorithm::A256Gcm => {
            let key = reallyme_crypto::aes::Aes256GcmKey::from_slice(cek)
                .map_err(|_| encoding_failed())?;
            let nonce = reallyme_crypto::aes::Aes256GcmNonce::from_slice(nonce)
                .map_err(|_| encoding_failed())?;
            reallyme_crypto::aes::encrypt(&reallyme_crypto::aes::EncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
            .map_err(|_| encoding_failed())
        }
        _ => Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters)),
    }
}

fn format_compact_jwe(
    protected: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> IssuerResult<String> {
    let iv = bytes_to_base64url(nonce);
    let ciphertext = bytes_to_base64url(ciphertext);
    let tag = bytes_to_base64url(tag);
    let length = protected
        .len()
        .checked_add(iv.len())
        .and_then(|value| value.checked_add(ciphertext.len()))
        .and_then(|value| value.checked_add(tag.len()))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(encoding_failed)?;
    if length > DEFAULT_MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(encoding_failed());
    }
    let mut compact = String::with_capacity(length);
    compact.push_str(protected);
    compact.push_str("..");
    compact.push_str(&iv);
    compact.push('.');
    compact.push_str(&ciphertext);
    compact.push('.');
    compact.push_str(&tag);
    Ok(compact)
}

const fn encoding_failed() -> IssuerError {
    IssuerError::new(IssuerStatus::EncodingFailed)
}
