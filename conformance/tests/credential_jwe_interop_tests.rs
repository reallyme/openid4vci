// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-crate credential JWE interoperability tests for issuer and wallet roles.

use openid4vci_issuer::{
    CredentialRequestDecryptor, CredentialResponseEncryptor, JoseJweCredentialRequestDecryptor,
    JoseJweCredentialResponseEncryptor, JoseJwePrivateKey,
};
use openid4vci_types::{
    CredentialEnvelope, CredentialRequest, CredentialRequestEncryptionMetadata, CredentialResponse,
    CredentialResponseEncryption, DeferredCredentialRequest, Proofs, PublicJwk, PublicJwkSet,
};
use reallyme_openid4vci_wallet::{
    CredentialJwePrivateKey, JoseJweCredentialRequestEncryptor, JoseJweCredentialResponseDecryptor,
    WalletStatus,
};
use serde_json::json;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
#[error("credential JWE interoperability test setup failed")]
struct InteropTestError;

type InteropTestResult<T = ()> = Result<T, InteropTestError>;

fn test_result<T, E>(result: Result<T, E>) -> InteropTestResult<T> {
    result.map_err(|_| InteropTestError)
}

#[test]
fn request_encryption_interoperates_with_production_issuer() -> InteropTestResult {
    let (issuer_public, issuer_private) = p256_keypair(7)?;
    let metadata = request_encryption_metadata(public_jwk(&issuer_public, "issuer-key-1")?)?;
    let request = credential_request();
    let encrypted =
        test_result(JoseJweCredentialRequestEncryptor::new().encrypt_request(&request, &metadata))?;
    let issuer_key = test_result(JoseJwePrivateKey::p256(
        issuer_private,
        Some("issuer-key-1".to_owned()),
    ))?;
    let decrypted = test_result(
        JoseJweCredentialRequestDecryptor::new(issuer_key).decrypt_request(encrypted.as_str()),
    )?;
    let decoded = test_result(CredentialRequest::parse_json(decrypted.as_str()))?;

    assert_eq!(decoded, request);
    assert!(!format!("{encrypted:?}").contains("credential-nonce"));
    Ok(())
}

#[test]
fn response_decryption_interoperates_with_production_issuer() -> InteropTestResult {
    let (wallet_public, wallet_private) = p256_keypair(11)?;
    let encryption = CredentialResponseEncryption {
        jwk: public_jwk(&wallet_public, "wallet-key-1")?,
        enc: "A256GCM".to_owned(),
        zip: None,
    };
    let response = test_result(CredentialResponse::immediate(
        vec![CredentialEnvelope::compact("credential-sd-jwt".to_owned())],
        Some("notification-1".to_owned()),
    ))?;
    let encrypted = test_result(
        JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &encryption),
    )?;
    let wallet_key = wallet_private_key(&wallet_private, "wallet-key-1")?;
    let decryptor = test_result(JoseJweCredentialResponseDecryptor::new(
        wallet_key,
        &encryption,
    ))?;
    let decoded = test_result(decryptor.decrypt_response(encrypted.as_str()))?;

    assert_eq!(decoded, response);
    Ok(())
}

#[test]
fn deferred_request_encryption_interoperates_with_production_issuer() -> InteropTestResult {
    let (issuer_public, issuer_private) = p256_keypair(9)?;
    let metadata = request_encryption_metadata(public_jwk(&issuer_public, "issuer-key-deferred")?)?;
    let (wallet_public, wallet_private) = p256_keypair(10)?;
    let response_encryption = CredentialResponseEncryption {
        jwk: public_jwk(&wallet_public, "wallet-key-deferred")?,
        enc: "A256GCM".to_owned(),
        zip: None,
    };
    let request = DeferredCredentialRequest {
        transaction_id: "deferred-transaction-1".to_owned(),
        credential_response_encryption: Some(response_encryption.clone()),
    };
    let encrypted = test_result(
        JoseJweCredentialRequestEncryptor::new().encrypt_deferred_request(&request, &metadata),
    )?;
    let issuer_key = test_result(JoseJwePrivateKey::p256(
        issuer_private,
        Some("issuer-key-deferred".to_owned()),
    ))?;
    let decrypted = test_result(
        JoseJweCredentialRequestDecryptor::new(issuer_key).decrypt_request(encrypted.as_str()),
    )?;
    let decoded = test_result(DeferredCredentialRequest::parse_json(decrypted.as_str()))?;
    assert_eq!(decoded, request);

    let response = test_result(CredentialResponse::immediate(
        vec![CredentialEnvelope::compact(
            "deferred-credential-sd-jwt".to_owned(),
        )],
        None,
    ))?;
    let encrypted_response = test_result(
        JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &response_encryption),
    )?;
    let wallet_key = wallet_private_key(&wallet_private, "wallet-key-deferred")?;
    let decryptor = test_result(JoseJweCredentialResponseDecryptor::new(
        wallet_key,
        &response_encryption,
    ))?;
    let decoded_response = test_result(decryptor.decrypt_response(encrypted_response.as_str()))?;
    assert_eq!(decoded_response, response);
    Ok(())
}

#[test]
fn response_decryption_rejects_wrong_key_identifier_and_tampering() -> InteropTestResult {
    let (wallet_public, wallet_private) = p256_keypair(13)?;
    let response = test_result(CredentialResponse::immediate(
        vec![CredentialEnvelope::compact("credential-sd-jwt".to_owned())],
        None,
    ))?;
    let encryption = CredentialResponseEncryption {
        jwk: public_jwk(&wallet_public, "wallet-key-1")?,
        enc: "A128GCM".to_owned(),
        zip: None,
    };
    let encrypted = test_result(
        JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &encryption),
    )?;
    let wrong_kid = wallet_private_key(&wallet_private, "wallet-key-2")?;
    assert!(JoseJweCredentialResponseDecryptor::new(wrong_kid, &encryption).is_err());

    let mut tampered = encrypted.as_str().as_bytes().to_vec();
    let last = tampered.last_mut().ok_or(InteropTestError)?;
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = test_result(core::str::from_utf8(&tampered))?;
    let key = wallet_private_key(&wallet_private, "wallet-key-1")?;
    let decryptor = test_result(JoseJweCredentialResponseDecryptor::new(key, &encryption))?;
    assert!(decryptor.decrypt_response(tampered).is_err());
    Ok(())
}

#[test]
fn response_decryption_enforces_requested_context_and_input_bounds() -> InteropTestResult {
    assert!(CredentialJwePrivateKey::p256(
        Zeroizing::new([0_u8; 32]),
        Some("wallet-key-1".to_owned()),
    )
    .is_err());

    let (wallet_public, wallet_private) = p256_keypair(19)?;
    let encryption = CredentialResponseEncryption {
        jwk: public_jwk(&wallet_public, "wallet-key-1")?,
        enc: "A128GCM".to_owned(),
        zip: None,
    };
    let response = test_result(CredentialResponse::immediate(
        vec![CredentialEnvelope::compact("credential-sd-jwt".to_owned())],
        None,
    ))?;
    let encrypted = test_result(
        JoseJweCredentialResponseEncryptor::new().encrypt_response(&response, &encryption),
    )?;

    let wrong_algorithm = CredentialResponseEncryption {
        jwk: encryption.jwk.clone(),
        enc: "A256GCM".to_owned(),
        zip: None,
    };
    let key = wallet_private_key(&wallet_private, "wallet-key-1")?;
    let wrong_algorithm_decryptor = test_result(JoseJweCredentialResponseDecryptor::new(
        key,
        &wrong_algorithm,
    ))?;
    assert_eq!(
        wrong_algorithm_decryptor
            .decrypt_response(encrypted.as_str())
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::EncryptedResponseRejected)
    );

    let (other_public, _other_private) = p256_keypair(23)?;
    let mismatched_key = CredentialResponseEncryption {
        jwk: public_jwk(&other_public, "wallet-key-1")?,
        enc: "A128GCM".to_owned(),
        zip: None,
    };
    let key = wallet_private_key(&wallet_private, "wallet-key-1")?;
    assert!(JoseJweCredentialResponseDecryptor::new(key, &mismatched_key).is_err());

    let key = wallet_private_key(&wallet_private, "wallet-key-1")?;
    let decryptor = test_result(JoseJweCredentialResponseDecryptor::new(key, &encryption))?;
    let oversized = "a".repeat(262_145);
    assert_eq!(
        decryptor
            .decrypt_response(&oversized)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::EncryptedResponseRejected)
    );
    Ok(())
}

fn credential_request() -> CredentialRequest {
    CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    }
}

fn p256_keypair(seed: u8) -> InteropTestResult<(Vec<u8>, Vec<u8>)> {
    test_result(reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&[seed; 32]))
        .map(|(public, private)| (public, private.to_vec()))
}

fn request_encryption_metadata(
    public_jwk: PublicJwk,
) -> InteropTestResult<CredentialRequestEncryptionMetadata> {
    Ok(CredentialRequestEncryptionMetadata {
        alg_values_supported: None,
        enc_values_supported: vec!["A128GCM".to_owned(), "A256GCM".to_owned()],
        zip_values_supported: None,
        jwks: test_result(PublicJwkSet::new(vec![public_jwk]))?,
        encryption_required: true,
    })
}

fn wallet_private_key(private_key: &[u8], kid: &str) -> InteropTestResult<CredentialJwePrivateKey> {
    let scalar = test_result(<[u8; 32]>::try_from(private_key))?;
    test_result(CredentialJwePrivateKey::p256(
        Zeroizing::new(scalar),
        Some(kid.to_owned()),
    ))
}

fn public_jwk(compressed_public_key: &[u8], kid: &str) -> InteropTestResult<PublicJwk> {
    let affine = test_result(reallyme_crypto::p256::decompress_public_key(
        compressed_public_key,
    ))?;
    let x = affine.get(1..33).ok_or(InteropTestError)?;
    let y = affine.get(33..65).ok_or(InteropTestError)?;
    test_result(PublicJwk::new(json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-ES",
        "use": "enc",
        "x": reallyme_codec::base64url::bytes_to_base64url(x),
        "y": reallyme_codec::base64url::bytes_to_base64url(y),
        "kid": kid
    })))
}
