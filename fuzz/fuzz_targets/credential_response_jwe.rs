// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_types::{CredentialResponseEncryption, PublicJwk};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_openid4vci_wallet::{CredentialJwePrivateKey, JoseJweCredentialResponseDecryptor};
use serde_json::json;
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let Ok(compact) = core::str::from_utf8(data) else {
        return;
    };
    let Ok((public_key, _)) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&[17; 32])
    else {
        return;
    };
    let Ok(uncompressed) = reallyme_crypto::p256::decompress_public_key(&public_key) else {
        return;
    };
    let Some(x) = uncompressed.get(1..33) else {
        return;
    };
    let Some(y) = uncompressed.get(33..65) else {
        return;
    };
    let Ok(jwk) = PublicJwk::new(json!({
        "kty": "EC", "crv": "P-256", "alg": "ECDH-ES", "use": "enc",
        "kid": "wallet-key-1", "x": bytes_to_base64url(x), "y": bytes_to_base64url(y)
    })) else {
        return;
    };
    let encryption = CredentialResponseEncryption {
        jwk,
        enc: "A256GCM".to_owned(),
        zip: None,
    };
    let Ok(key) =
        CredentialJwePrivateKey::p256(Zeroizing::new([17_u8; 32]), Some("wallet-key-1".to_owned()))
    else {
        return;
    };
    let Ok(decryptor) = JoseJweCredentialResponseDecryptor::new(key, &encryption) else {
        return;
    };
    let _ = decryptor.decrypt_response(compact);
});
