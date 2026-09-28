// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cryptographic signed-metadata provider tests.

use openid4vci_issuer::{IssuerError, IssuerMetadataSigner, IssuerResult, IssuerStatus};
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::verify;
use reallyme_crypto::jwk::Jwk;
use reallyme_crypto::p256::p256_ecdsa_jose_signature_to_der;
use serde_json::{json, Value};

use super::configure::metadata;
use super::run::{CONFORMANCE_ATTESTER_PUBLIC_X, CONFORMANCE_ATTESTER_PUBLIC_Y};
use super::sign_metadata::ExampleIssuerMetadataSigner;

#[test]
fn signed_metadata_contains_canonical_metadata_and_verifiable_claims() -> IssuerResult<()> {
    let mut request_encryption_public_key = [0_u8; 65];
    request_encryption_public_key[0] = 0x04;
    let metadata = metadata(
        "https://issuer.example/openid4vci/example-issuer/",
        "https://issuer.example/",
        &request_encryption_public_key,
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let signed = ExampleIssuerMetadataSigner.sign_metadata(&metadata, 1_700_000_000)?;
    let segments = signed.as_str().split('.').collect::<Vec<_>>();
    if segments.len() != 3 {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let header = decode_json(segments[0])?;
    let claims = decode_json(segments[1])?;
    assert_eq!(
        header.get("typ").and_then(Value::as_str),
        Some("openidvci-issuer-metadata+jwt")
    );
    assert_eq!(
        claims.get("sub").and_then(Value::as_str),
        Some(metadata.credential_issuer.as_str())
    );
    assert_eq!(
        claims.get("iat").and_then(Value::as_i64),
        Some(1_700_000_000)
    );
    assert_eq!(
        claims.get("credential_issuer").and_then(Value::as_str),
        Some(metadata.credential_issuer.as_str())
    );

    let public_jwk = serde_json::from_value::<Jwk>(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": CONFORMANCE_ATTESTER_PUBLIC_X,
        "y": CONFORMANCE_ATTESTER_PUBLIC_Y
    }))
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let public_key = public_jwk
        .public_key_bytes()
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let signature = base64url_to_bytes(segments[2])
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let der_signature = p256_ecdsa_jose_signature_to_der(&signature)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let signing_input = [segments[0], ".", segments[1]].concat();
    verify(
        Algorithm::P256,
        &public_key,
        signing_input.as_bytes(),
        &der_signature,
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn decode_json(segment: &str) -> IssuerResult<Value> {
    let bytes =
        base64url_to_bytes(segment).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    serde_json::from_slice(&bytes).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}
