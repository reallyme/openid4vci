// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet JWK policy validation and SEC1 public-key conversion.

use reallyme_codec::{base64url::base64url_to_bytes, jcs::canonicalize_trusted_json_value};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

use super::JWE_ALG_ECDH_ES;

const JWK_KTY_EC: &str = "EC";
const JWK_USE_ENC: &str = "enc";
const JWK_KEY_OPERATION_DERIVE_KEY: &str = "deriveKey";
pub(super) const CURVE_P256: &str = "P-256";
#[cfg(feature = "native")]
pub(super) const CURVE_P384: &str = "P-384";
#[cfg(feature = "native")]
pub(super) const CURVE_P521: &str = "P-521";
pub(super) const P256_COORDINATE_BYTES: usize = 32;
#[cfg(feature = "native")]
pub(super) const P384_COORDINATE_BYTES: usize = 48;
#[cfg(feature = "native")]
pub(super) const P521_COORDINATE_BYTES: usize = 66;

/// Maximum canonical wallet JWK size accepted at provider dispatch.
const MAX_WALLET_JWK_JSON_BYTES: usize = 16_384;

pub(super) fn validate_wallet_jwk(jwk: &Value) -> IssuerResult<()> {
    let canonical = Zeroizing::new(
        canonicalize_trusted_json_value(jwk)
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?,
    );
    if canonical.len() > MAX_WALLET_JWK_JSON_BYTES || jwk_alg(jwk)? != JWE_ALG_ECDH_ES {
        return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
    }
    let object = jwk
        .as_object()
        .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?;
    let kty = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?;
    if kty != JWK_KTY_EC || object.contains_key("d") {
        return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
    }
    if object
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|value| value != JWK_USE_ENC)
    {
        return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
    }
    if let Some(key_ops) = object.get("key_ops") {
        let operations = key_ops
            .as_array()
            .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?;
        if operations.len() != 1
            || operations.first().and_then(Value::as_str) != Some(JWK_KEY_OPERATION_DERIVE_KEY)
        {
            return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
        }
    }
    validate_optional_kid(object.get("kid").and_then(Value::as_str))
}

pub(super) fn validate_ec_public_key(curve: &str, public_key: &[u8]) -> IssuerResult<()> {
    let valid = match curve {
        CURVE_P256 => p256::PublicKey::from_sec1_bytes(public_key).is_ok(),
        #[cfg(feature = "native")]
        CURVE_P384 => p384::PublicKey::from_sec1_bytes(public_key).is_ok(),
        #[cfg(feature = "native")]
        CURVE_P521 => p521::PublicKey::from_sec1_bytes(public_key).is_ok(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))
    }
}

pub(super) fn ec_public_key_sec1_from_jwk(
    jwk: &Value,
    expected_crv: &str,
    coordinate_len: usize,
) -> IssuerResult<Vec<u8>> {
    if jwk_crv(jwk)? != expected_crv {
        return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
    }
    let x = decode_coordinate(jwk, "x", coordinate_len)?;
    let y = decode_coordinate(jwk, "y", coordinate_len)?;
    let coordinates_len = coordinate_len
        .checked_mul(2)
        .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?;
    let capacity = coordinates_len
        .checked_add(1)
        .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?;
    let mut public_key = Vec::with_capacity(capacity);
    public_key.push(0x04);
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);
    if public_key.len() != capacity {
        return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
    }
    Ok(public_key)
}

fn decode_coordinate(
    jwk: &Value,
    field: &'static str,
    expected_len: usize,
) -> IssuerResult<Vec<u8>> {
    let encoded = jwk
        .get(field)
        .and_then(Value::as_str)
        .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?;
    let bytes = base64url_to_bytes(encoded)
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?;
    if bytes.len() != expected_len {
        return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
    }
    Ok(bytes)
}

fn jwk_alg(jwk: &Value) -> IssuerResult<&str> {
    jwk.get("alg")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.is_ascii())
        .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))
}

pub(super) fn jwk_crv(jwk: &Value) -> IssuerResult<&str> {
    jwk.get("crv")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.is_ascii())
        .ok_or(IssuerError::new(IssuerStatus::InvalidEncryptionParameters))
}

pub(super) fn optional_ascii_string<'a>(
    jwk: &'a Value,
    field: &'static str,
) -> IssuerResult<Option<&'a str>> {
    match jwk.get(field).and_then(Value::as_str) {
        Some(value) if value.is_empty() || !value.is_ascii() => {
            Err(IssuerError::new(IssuerStatus::InvalidRequest))
        }
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

pub(super) fn validate_optional_kid(kid: Option<&str>) -> IssuerResult<()> {
    if kid.is_some_and(|value| value.is_empty() || !value.is_ascii()) {
        return Err(IssuerError::new(IssuerStatus::InvalidRequest));
    }
    Ok(())
}
