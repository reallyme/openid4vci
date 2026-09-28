// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid_oauth::jwt::decode_compact_jwt;
use reallyme_openid_oauth::{jwk_thumbprint, JwtSigner, OauthError};
use secrecy::SecretString;
use serde_json::{json, Value};
use thiserror::Error;

use super::{KeyProofJwtRequest, KeyProofSigner};
use crate::{WalletError, WalletStatus};

const NONCE: &str = "credential-nonce-1";

struct TestSigner {
    algorithm: &'static str,
    public_jwk_thumbprint: String,
}

impl KeyProofSigner for TestSigner {
    fn public_jwk_thumbprint(&self) -> &str {
        &self.public_jwk_thumbprint
    }
}

impl JwtSigner for TestSigner {
    fn algorithm(&self) -> &str {
        self.algorithm
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, OauthError> {
        Ok(signing_input.to_vec())
    }
}

#[test]
fn signs_validated_key_proof_with_optional_attestation() -> Result<(), KeyProofTestError> {
    let request = KeyProofJwtRequest::new(
        "ES256".to_owned(),
        public_jwk(),
        "https://issuer.example/tenant".to_owned(),
        1_700_000_000,
        SecretString::from(NONCE.to_owned()),
        Some(SecretString::from("a.b.c".to_owned())),
    )?;
    let proof = request.sign(&test_signer("ES256")?)?;
    let (header, claims, _signature): (Value, Value, Vec<u8>) = decode_compact_jwt(&proof)?;

    assert_eq!(
        header.get("typ").and_then(Value::as_str),
        Some("openid4vci-proof+jwt")
    );
    assert_eq!(
        header.get("key_attestation").and_then(Value::as_str),
        Some("a.b.c")
    );
    assert_eq!(
        claims.get("aud").and_then(Value::as_str),
        Some("https://issuer.example/tenant")
    );
    assert_eq!(claims.get("nonce").and_then(Value::as_str), Some(NONCE));
    assert!(!format!("{request:?}").contains(NONCE));
    Ok(())
}

#[test]
fn rejects_invalid_audience_private_jwk_and_signer_mismatch() -> Result<(), KeyProofTestError> {
    let invalid_audience = KeyProofJwtRequest::new(
        "ES256".to_owned(),
        public_jwk(),
        "http://issuer.example".to_owned(),
        1_700_000_000,
        SecretString::from(NONCE.to_owned()),
        None,
    );
    assert_eq!(
        invalid_audience.err().map(|error| error.status()),
        Some(WalletStatus::InvalidRequest)
    );

    let private_jwk = KeyProofJwtRequest::new(
        "ES256".to_owned(),
        json!({"kty":"EC","crv":"P-256","x":"AQ","y":"Ag","d":"Aw"}),
        "https://issuer.example".to_owned(),
        1_700_000_000,
        SecretString::from(NONCE.to_owned()),
        None,
    );
    assert!(private_jwk.is_err());

    let request = valid_request()?;
    let mismatch = request.sign(&test_signer("ES384")?);
    assert!(mismatch.is_err());
    let wrong_key = TestSigner {
        algorithm: "ES256",
        public_jwk_thumbprint: jwk_thumbprint(&json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }))?,
    };
    assert!(request.sign(&wrong_key).is_err());
    Ok(())
}

fn test_signer(algorithm: &'static str) -> Result<TestSigner, OauthError> {
    Ok(TestSigner {
        algorithm,
        public_jwk_thumbprint: jwk_thumbprint(&public_jwk())?,
    })
}

fn valid_request() -> Result<KeyProofJwtRequest, WalletError> {
    KeyProofJwtRequest::new(
        "ES256".to_owned(),
        public_jwk(),
        "https://issuer.example".to_owned(),
        1_700_000_000,
        SecretString::from(NONCE.to_owned()),
        None,
    )
}

fn public_jwk() -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF4w6Fh-r4mYHj8v8M4u0DmytG2mM7jzZs0",
        "y": "x_FEzRu9r7S0Hk6Yz8rE4uY0cQp4G2fP5sM8nB1kD3A"
    })
}

#[derive(Debug, Error)]
enum KeyProofTestError {
    #[error("wallet")]
    Wallet(#[from] WalletError),
    #[error("oauth")]
    Oauth(#[from] OauthError),
}
