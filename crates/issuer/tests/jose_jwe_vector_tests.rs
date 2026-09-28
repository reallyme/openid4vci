// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checked compact-JWE interop vectors for OpenID4VCI encryption surfaces.

#![cfg(feature = "identity-jose")]

use openid4vci_issuer::{
    CredentialRequestDecryptor, CredentialResponseEncryptor, JoseJweCredentialRequestDecryptor,
    JoseJweCredentialResponseEncryptor, JoseJwePrivateKey,
};
use openid4vci_types::{
    CredentialRequest, CredentialResponse, CredentialResponseEncryption, PublicJwk,
};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_jose::jwe::{decrypt_compact_jwe_json, CompactJwePolicy, P256EcdhEsJweKeyResolver};
use serde::Deserialize;
use serde_json::{json, Value};

use openid4vci_issuer::{IssuerError, IssuerResult, IssuerStatus};

const JWE_VECTOR_BODY: &str = include_str!("../../../vectors/openid4vci-jwe.json");

#[derive(Debug, Deserialize)]
struct JweVectorSuite {
    schema: String,
    cases: Vec<JweVectorCase>,
}

#[derive(Debug, Deserialize)]
struct JweVectorCase {
    id: String,
    purpose: JweVectorPurpose,
    alg: String,
    enc: String,
    kid: String,
    recipient_private_key_b64u: String,
    recipient_public_key_sec1_b64u: String,
    plaintext_json_utf8: String,
    compact: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JweVectorPurpose {
    CredentialRequestDecryption,
    CredentialResponseEncryption,
}

#[test]
fn checked_jwe_vectors_have_supported_compact_headers() -> IssuerResult<()> {
    for case in vector_suite()?.cases {
        assert_supported_vector_case(&case)?;
        assert_compact_header_matches_case(&case)?;
    }
    Ok(())
}

#[test]
fn checked_request_decryption_vector_uses_openid4vci_decryptor() -> IssuerResult<()> {
    for case in vector_suite()?.cases {
        if case.purpose != JweVectorPurpose::CredentialRequestDecryption {
            continue;
        }
        let private_key = JoseJwePrivateKey::p256(
            decode_bytes(&case.recipient_private_key_b64u)?,
            Some(case.kid.clone()),
        )?;
        let decryptor = JoseJweCredentialRequestDecryptor::new(private_key);

        let plaintext = decryptor.decrypt_request(&case.compact)?;
        let decoded = CredentialRequest::parse_json(plaintext.as_str())
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
        let expected = CredentialRequest::parse_json(&case.plaintext_json_utf8)
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;

        assert_eq!(decoded, expected, "{}", case.id);
    }
    Ok(())
}

#[test]
fn checked_response_encryption_vector_matches_openid4vci_response_model() -> IssuerResult<()> {
    for case in vector_suite()?.cases {
        if case.purpose != JweVectorPurpose::CredentialResponseEncryption {
            continue;
        }
        let recipient_private = decode_bytes(&case.recipient_private_key_b64u)?;
        let decoded: CredentialResponse = decrypt_compact_jwe_json(
            &case.compact,
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &P256EcdhEsJweKeyResolver::new(&recipient_private),
        )
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
        let expected = CredentialResponse::parse_json(&case.plaintext_json_utf8)
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;

        assert_eq!(decoded, expected, "{}", case.id);

        let response_encryption = CredentialResponseEncryption {
            jwk: p256_public_jwk(
                &decode_bytes(&case.recipient_public_key_sec1_b64u)?,
                &case.kid,
            )?,
            enc: case.enc.clone(),
            zip: None,
        };
        let encrypted = JoseJweCredentialResponseEncryptor::new()
            .encrypt_response(&expected, &response_encryption)?;
        let adapter_decoded: CredentialResponse = decrypt_compact_jwe_json(
            encrypted.as_str(),
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &P256EcdhEsJweKeyResolver::new(&recipient_private),
        )
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;

        assert_eq!(adapter_decoded, expected, "{}", case.id);
    }
    Ok(())
}

fn vector_suite() -> IssuerResult<JweVectorSuite> {
    let suite: JweVectorSuite = serde_json::from_str(JWE_VECTOR_BODY)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    if suite.schema != "reallyme.openid4vci.jwe.vectors.v1" {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    Ok(suite)
}

fn assert_supported_vector_case(case: &JweVectorCase) -> IssuerResult<()> {
    if case.alg != "ECDH-ES" || case.enc != "A128GCM" {
        return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
    }
    Ok(())
}

fn assert_compact_header_matches_case(case: &JweVectorCase) -> IssuerResult<()> {
    let mut segments = case.compact.split('.');
    let protected = segments
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    for _ in 0..4 {
        segments
            .next()
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    }
    if segments.next().is_some() {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let protected: Value = serde_json::from_slice(&decode_bytes(protected)?)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    if protected.get("alg").and_then(Value::as_str) != Some(case.alg.as_str())
        || protected.get("enc").and_then(Value::as_str) != Some(case.enc.as_str())
        || protected.get("kid").and_then(Value::as_str) != Some(case.kid.as_str())
        || protected.get("epk").is_none()
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    Ok(())
}

fn decode_bytes(value: &str) -> IssuerResult<Vec<u8>> {
    base64url_to_bytes(value).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn p256_public_jwk(public_key_sec1: &[u8], kid: &str) -> IssuerResult<PublicJwk> {
    let uncompressed = if public_key_sec1.len() == 65 && public_key_sec1.first() == Some(&0x04) {
        public_key_sec1.to_vec()
    } else {
        reallyme_crypto::p256::decompress_public_key(public_key_sec1)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?
    };
    let x = uncompressed
        .get(1..33)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let y = uncompressed
        .get(33..65)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;

    PublicJwk::new(json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-ES",
        "use": "enc",
        "kid": kid,
        "x": bytes_to_base64url(x),
        "y": bytes_to_base64url(y)
    }))
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}
