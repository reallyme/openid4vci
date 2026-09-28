// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build OpenID4VCI key proof JWTs from wallet-owned signing material.

use core::fmt::{Debug, Formatter};

use reallyme_openid_oauth::jwt::sign_compact_jwt;
use reallyme_openid_oauth::{jwk_thumbprint, CompactJwt, DpopHeader, JwtSigner};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::Value;
use url::Url;
use zeroize::Zeroize;

use crate::{WalletError, WalletResult, WalletStatus};

const KEY_PROOF_JWT_TYPE: &str = "openid4vci-proof+jwt";

/// Validated inputs for one OpenID4VCI key proof JWT.
pub struct KeyProofJwtRequest {
    signing_algorithm: String,
    public_jwk: Value,
    public_jwk_thumbprint: String,
    audience: String,
    issued_at: i64,
    nonce: SecretString,
    key_attestation: Option<SecretString>,
}

impl KeyProofJwtRequest {
    /// Validate proof inputs and bind the public JWK to the selected algorithm.
    pub fn new(
        signing_algorithm: String,
        mut public_jwk: Value,
        audience: String,
        issued_at: i64,
        nonce: SecretString,
        key_attestation: Option<SecretString>,
    ) -> WalletResult<Self> {
        let thumbprint = jwk_thumbprint(&public_jwk).map_err(|_| proof_error());
        if validate_audience(&audience).is_err()
            || issued_at <= 0
            || nonce.expose_secret().is_empty()
            || DpopHeader::new(signing_algorithm.clone(), public_jwk.clone()).is_err()
            || !valid_optional_compact_jwt(&key_attestation)
        {
            zeroize_json_strings(&mut public_jwk);
            return Err(proof_error());
        }
        let public_jwk_thumbprint = thumbprint?;
        Ok(Self {
            signing_algorithm,
            public_jwk,
            public_jwk_thumbprint,
            audience,
            issued_at,
            nonce,
            key_attestation,
        })
    }

    /// Sign the validated request with the key bound at construction.
    pub fn sign(&self, signer: &dyn KeyProofSigner) -> WalletResult<CompactJwt> {
        if signer.algorithm() != self.signing_algorithm
            || signer.public_jwk_thumbprint() != self.public_jwk_thumbprint
        {
            return Err(proof_error());
        }
        let header = KeyProofHeader {
            algorithm: self.signing_algorithm.as_str(),
            public_jwk: &self.public_jwk,
            proof_type: KEY_PROOF_JWT_TYPE,
            key_attestation: self
                .key_attestation
                .as_ref()
                .map(SecretString::expose_secret),
        };
        let claims = KeyProofClaims {
            audience: self.audience.as_str(),
            issued_at: self.issued_at,
            nonce: self.nonce.expose_secret(),
        };
        sign_compact_jwt(&header, &claims, signer).map_err(|_| proof_error())
    }
}

impl Debug for KeyProofJwtRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyProofJwtRequest([REDACTED])")
    }
}

impl Drop for KeyProofJwtRequest {
    fn drop(&mut self) {
        self.signing_algorithm.zeroize();
        self.audience.zeroize();
        self.public_jwk_thumbprint.zeroize();
        zeroize_json_strings(&mut self.public_jwk);
    }
}

/// Signer contract that proves which public key backs a key-proof signature.
///
/// Implementations must derive the returned RFC 7638 thumbprint from the key
/// handle actually used by [`JwtSigner::sign`]. A caller-supplied label is not
/// sufficient for hardware-backed or remotely managed signers.
pub trait KeyProofSigner: JwtSigner {
    /// RFC 7638 thumbprint of the signing key's public JWK.
    fn public_jwk_thumbprint(&self) -> &str;
}

#[derive(Serialize)]
struct KeyProofHeader<'a> {
    #[serde(rename = "alg")]
    algorithm: &'a str,
    #[serde(rename = "jwk")]
    public_jwk: &'a Value,
    #[serde(rename = "typ")]
    proof_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_attestation: Option<&'a str>,
}

#[derive(Serialize)]
struct KeyProofClaims<'a> {
    #[serde(rename = "aud")]
    audience: &'a str,
    #[serde(rename = "iat")]
    issued_at: i64,
    nonce: &'a str,
}

fn validate_audience(value: &str) -> WalletResult<()> {
    let url = Url::parse(value).map_err(|_| proof_error())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(proof_error());
    }
    Ok(())
}

fn valid_optional_compact_jwt(value: &Option<SecretString>) -> bool {
    value
        .as_ref()
        .is_none_or(|jwt| CompactJwt::new(jwt.expose_secret().to_owned()).is_ok())
}

fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json_strings),
        Value::Object(values) => values.values_mut().for_each(zeroize_json_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

const fn proof_error() -> WalletError {
    WalletError::new(WalletStatus::InvalidRequest)
}

#[cfg(test)]
#[path = "build_key_proof_tests.rs"]
mod tests;
