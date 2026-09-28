// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Concrete `reallyme-jose` JWE adapter tests.

#![cfg(feature = "identity-jose")]

use openid4vci_issuer::{
    CredentialRequestDecryptor, CredentialResponseEncryptor, JoseJweCredentialRequestDecryptor,
    JoseJweCredentialResponseEncryptor, JoseJwePrivateKey,
};
use openid4vci_types::{
    CredentialEnvelope, CredentialRequest, CredentialResponse, CredentialResponseEncryption,
    Proofs, PublicJwk,
};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_jose::jwe::{
    decrypt_compact_jwe_json, encrypt_compact_jwe_bytes, CompactJweEncryptRequest,
    CompactJwePolicy, JweContentEncryptionAlgorithm, P256EcdhEsJweKeyEncryptor,
    P256EcdhEsJweKeyResolver,
};
use serde_json::{json, Value};

use openid4vci_issuer::{IssuerError, IssuerResult, IssuerStatus};

#[test]
fn jose_jwe_response_encryptor_roundtrips_p256_ecdh_es() -> IssuerResult<()> {
    let recipient_secret = private_scalar(5);
    let (recipient_public, recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope::compact("credential-sd-jwt".to_owned())],
        Some("notification-1".to_owned()),
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let encryption = CredentialResponseEncryption {
        jwk: p256_public_jwk(&recipient_public, Some("wallet-key-1"))?,
        enc: "A128GCM".to_owned(),
        zip: None,
    };
    let encrypted =
        JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &encryption)?;
    let decoded_result: Result<CredentialResponse, reallyme_jose::jwe::JweError> =
        decrypt_compact_jwe_json(
            encrypted.as_str(),
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &P256EcdhEsJweKeyResolver::new(&recipient_private),
        );
    assert!(decoded_result.is_ok(), "{:?}", decoded_result.err());
    let decoded = decoded_result.map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;

    assert_eq!(decoded, response);
    Ok(())
}

#[test]
fn jose_jwe_request_decryptor_roundtrips_p256_ecdh_es() -> IssuerResult<()> {
    let issuer_secret = private_scalar(7);
    let (issuer_public, issuer_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&issuer_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let plaintext =
        serde_json::to_vec(&request).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let compact = encrypt_request_for_issuer(&plaintext, &issuer_public, "issuer-key-1")?;
    let private_key =
        JoseJwePrivateKey::p256(issuer_private.to_vec(), Some("issuer-key-1".to_owned()))?;
    let decryptor = JoseJweCredentialRequestDecryptor::new(private_key);

    let decrypted = decryptor.decrypt_request(&compact)?;
    let mapped = CredentialRequest::parse_json(decrypted.as_str())
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;

    assert_eq!(mapped, request);
    Ok(())
}

#[test]
fn jose_jwe_request_decryptor_rejects_wrong_kid() -> IssuerResult<()> {
    let issuer_secret = private_scalar(9);
    let (issuer_public, issuer_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&issuer_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let compact = encrypt_request_for_issuer(
        br#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#,
        &issuer_public,
        "issuer-key-1",
    )?;
    let private_key =
        JoseJwePrivateKey::p256(issuer_private.to_vec(), Some("issuer-key-2".to_owned()))?;
    let decryptor = JoseJweCredentialRequestDecryptor::new(private_key);

    let result = decryptor.decrypt_request(&compact);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidRequest)
    );
    Ok(())
}

#[test]
fn jose_jwe_response_encryptor_applies_deflate_compression() -> IssuerResult<()> {
    let recipient_secret = private_scalar(11);
    let (recipient_public, _recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope::compact("credential-sd-jwt".to_owned())],
        None,
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let encryption = CredentialResponseEncryption {
        jwk: p256_public_jwk(&recipient_public, Some("wallet-key-1"))?,
        enc: "A128GCM".to_owned(),
        zip: Some("DEF".to_owned()),
    };

    let encrypted =
        JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &encryption)?;
    let protected = encrypted
        .as_str()
        .split('.')
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let protected = base64url_to_bytes(protected)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let protected: Value = serde_json::from_slice(&protected)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;

    assert_eq!(protected.get("zip").and_then(Value::as_str), Some("DEF"));
    Ok(())
}

#[test]
fn jose_jwe_response_encryptor_rejects_unsupported_zip_parameter() -> IssuerResult<()> {
    let recipient_secret = private_scalar(11);
    let (recipient_public, _recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope::compact("credential-sd-jwt".to_owned())],
        None,
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let encryption = CredentialResponseEncryption {
        jwk: p256_public_jwk(&recipient_public, Some("wallet-key-1"))?,
        enc: "A128GCM".to_owned(),
        zip: Some("GZIP".to_owned()),
    };

    let result = JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &encryption);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    Ok(())
}

#[test]
fn jose_jwe_response_encryptor_rejects_private_wallet_jwk() -> IssuerResult<()> {
    let recipient_secret = private_scalar(13);
    let (recipient_public, _recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let mut jwk = p256_public_jwk_value(&recipient_public, Some("wallet-key-1"))?;
    let object = jwk
        .as_object_mut()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    object.insert(
        "d".to_owned(),
        Value::String(bytes_to_base64url(&[7_u8; 32])),
    );
    let result = PublicJwk::new(jwk);

    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(openid4vci_types::Reason::InvalidJwk)
    );
    Ok(())
}

#[test]
fn jose_jwe_response_encryptor_rejects_oversized_plaintext() -> IssuerResult<()> {
    let recipient_secret = private_scalar(17);
    let (recipient_public, _recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let response =
        CredentialResponse::immediate(vec![CredentialEnvelope::compact("a".repeat(131_072))], None)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let encryption = CredentialResponseEncryption {
        jwk: p256_public_jwk(&recipient_public, Some("wallet-key-1"))?,
        enc: "A128GCM".to_owned(),
        zip: None,
    };

    let result = JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &encryption);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn jose_jwe_response_encryptor_rejects_oversized_wallet_jwk() -> IssuerResult<()> {
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope::compact("credential-sd-jwt".to_owned())],
        None,
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let encryption = CredentialResponseEncryption {
        jwk: PublicJwk::new(json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ECDH-ES",
            "use": "enc",
            "x": "a",
            "y": "b",
            "extension": "a".repeat(16_384)
        }))
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?,
        enc: "A128GCM".to_owned(),
        zip: None,
    };

    let result = JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &encryption);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    Ok(())
}

#[test]
fn jose_jwe_response_encryptor_rejects_off_curve_wallet_key_before_issuance() -> IssuerResult<()> {
    let encryption = CredentialResponseEncryption {
        jwk: PublicJwk::new(json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ECDH-ES",
            "use": "enc",
            "x": bytes_to_base64url(&[0_u8; 32]),
            "y": bytes_to_base64url(&[0_u8; 32])
        }))
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?,
        enc: "A128GCM".to_owned(),
        zip: None,
    };

    assert_eq!(
        JoseJweCredentialResponseEncryptor::new()
            .validate_parameters(&encryption)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    Ok(())
}

#[test]
fn jose_jwe_response_encryptor_enforces_wallet_key_operations() -> IssuerResult<()> {
    let recipient_secret = private_scalar(23);
    let (recipient_public, _) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let mut jwk = p256_public_jwk_value(&recipient_public, None)?;
    let object = jwk
        .as_object_mut()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    object.insert("key_ops".to_owned(), json!(["sign"]));
    let encryption = CredentialResponseEncryption {
        jwk: PublicJwk::new(jwk)
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidEncryptionParameters))?,
        enc: "A128GCM".to_owned(),
        zip: None,
    };

    assert_eq!(
        JoseJweCredentialResponseEncryptor::new()
            .validate_parameters(&encryption)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidEncryptionParameters)
    );
    Ok(())
}

#[test]
fn jose_jwe_request_decryptor_rejects_oversized_plaintext() -> IssuerResult<()> {
    let issuer_secret = private_scalar(19);
    let (issuer_public, issuer_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&issuer_secret)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let plaintext = vec![b'a'; 65_537];
    let compact = encrypt_request_for_issuer(&plaintext, &issuer_public, "issuer-key-1")?;
    let private_key =
        JoseJwePrivateKey::p256(issuer_private.to_vec(), Some("issuer-key-1".to_owned()))?;
    let decryptor = JoseJweCredentialRequestDecryptor::new(private_key);

    let result = decryptor.decrypt_request(&compact);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidRequest)
    );
    Ok(())
}

fn encrypt_request_for_issuer(
    plaintext: &[u8],
    issuer_public: &[u8],
    kid: &str,
) -> IssuerResult<String> {
    let mut rng = reallyme_crypto::csprng::OsSecureRandom;
    let mut encryptor = P256EcdhEsJweKeyEncryptor::new(issuer_public);
    encrypt_compact_jwe_bytes(
        &CompactJweEncryptRequest::new(plaintext, JweContentEncryptionAlgorithm::A128Gcm)
            .with_kid(kid),
        &mut encryptor,
        &mut rng,
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn p256_public_jwk(public_key_sec1: &[u8], kid: Option<&str>) -> IssuerResult<PublicJwk> {
    PublicJwk::new(p256_public_jwk_value(public_key_sec1, kid)?)
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidEncryptionParameters))
}

fn p256_public_jwk_value(public_key_sec1: &[u8], kid: Option<&str>) -> IssuerResult<Value> {
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
    let mut jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-ES",
        "use": "enc",
        "x": bytes_to_base64url(x),
        "y": bytes_to_base64url(y)
    });
    if let Some(kid) = kid {
        let object = jwk
            .as_object_mut()
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
        object.insert("kid".to_owned(), Value::String(kid.to_owned()));
    }
    Ok(jwk)
}

fn private_scalar(last_byte: u8) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar[31] = last_byte;
    scalar
}
