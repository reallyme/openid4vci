// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use openid4vci_types::{
    CredentialRequest, CredentialRequestEncryptionMetadata, Proofs, PublicJwkSet,
};
use reallyme_codec::base64url::bytes_to_base64url;
use serde_json::{json, Value};

use super::JoseJweCredentialRequestEncryptor;
use crate::{WalletError, WalletResult, WalletStatus};

#[test]
fn request_encryption_rejects_invalid_metadata_and_ec_points() -> WalletResult<()> {
    let (issuer_public, _issuer_private) = p256_keypair(17)?;
    let valid_jwk = public_jwk(&issuer_public, "issuer-key-1")?;
    let request = credential_request();

    let mut missing_kid = valid_jwk.clone();
    missing_kid
        .as_object_mut()
        .ok_or_else(wallet_error)?
        .remove("kid");
    assert!(request_encryption_metadata(missing_kid).is_err());

    assert!(
        PublicJwkSet::from_value(json!({"keys": [valid_jwk.clone(), valid_jwk.clone()]})).is_err()
    );

    let mut invalid_point = valid_jwk;
    invalid_point
        .as_object_mut()
        .ok_or_else(wallet_error)?
        .insert("y".to_owned(), json!(bytes_to_base64url(&[0_u8; 32])));
    assert!(JoseJweCredentialRequestEncryptor::new()
        .encrypt_request(&request, &request_encryption_metadata(invalid_point)?)
        .is_err());

    let unsupported_enc = CredentialRequestEncryptionMetadata {
        alg_values_supported: None,
        enc_values_supported: vec!["A128CBC-HS256".to_owned()],
        zip_values_supported: None,
        jwks: PublicJwkSet::from_value(
            json!({"keys": [public_jwk(&issuer_public, "issuer-key-1")?]}),
        )
        .map_err(|_| wallet_error())?,
        encryption_required: true,
    };
    assert!(JoseJweCredentialRequestEncryptor::new()
        .encrypt_request(&request, &unsupported_enc)
        .is_err());

    let mut escape_expansion = public_jwk(&issuer_public, "issuer-key-escape")?;
    escape_expansion
        .as_object_mut()
        .ok_or_else(wallet_error)?
        .insert("extension".to_owned(), json!("\"".repeat(10_000)));
    assert!(JoseJweCredentialRequestEncryptor::new()
        .encrypt_request(&request, &request_encryption_metadata(escape_expansion)?)
        .is_err());
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

fn p256_keypair(seed: u8) -> WalletResult<(Vec<u8>, Vec<u8>)> {
    reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&[seed; 32])
        .map(|(public, private)| (public, private.to_vec()))
        .map_err(|_| wallet_error())
}

fn request_encryption_metadata(
    public_jwk: Value,
) -> WalletResult<CredentialRequestEncryptionMetadata> {
    Ok(CredentialRequestEncryptionMetadata {
        alg_values_supported: None,
        enc_values_supported: vec!["A128GCM".to_owned(), "A256GCM".to_owned()],
        zip_values_supported: None,
        jwks: PublicJwkSet::from_value(json!({"keys": [public_jwk]}))
            .map_err(|_| wallet_error())?,
        encryption_required: true,
    })
}

fn public_jwk(compressed_public_key: &[u8], kid: &str) -> WalletResult<Value> {
    if compressed_public_key.len() != 33 {
        return Err(wallet_error());
    }
    let prefix = compressed_public_key
        .first()
        .copied()
        .ok_or_else(wallet_error)?;
    let x = compressed_public_key.get(1..).ok_or_else(wallet_error)?;
    let y = recover_y(prefix, x)?;
    Ok(json!({
        "alg": "ECDH-ES",
        "crv": "P-256",
        "kid": kid,
        "kty": "EC",
        "use": "enc",
        "x": bytes_to_base64url(x),
        "y": bytes_to_base64url(&y),
    }))
}

fn recover_y(prefix: u8, x: &[u8]) -> WalletResult<Vec<u8>> {
    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(x);
    let point =
        reallyme_crypto::p256::decompress_public_key(&compressed).map_err(|_| wallet_error())?;
    point
        .get(33..65)
        .map(ToOwned::to_owned)
        .ok_or_else(wallet_error)
}

const fn wallet_error() -> WalletError {
    WalletError::new(WalletStatus::InvalidRequest)
}
