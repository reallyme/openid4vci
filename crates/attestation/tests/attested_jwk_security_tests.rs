// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attested public-key sanitization and subgroup validation tests.

use openid4vci_attestation::{
    parse_key_attestation, AttestationStatus, KeyAttestationAlgorithm, KeyAttestationJwt,
    KeyAttestationTemporalPolicy, KeyAttestationValidationContext,
};
use reallyme_codec::base64url::bytes_to_base64url;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
enum AttestedJwkTestError {
    #[error("json")]
    Json,
    #[error("attestation")]
    Attestation,
}

#[test]
fn rejects_unknown_jwk_extensions_before_credential_binding() -> Result<(), AttestedJwkTestError> {
    let mut key = valid_key();
    key["vendor_extension"] = json!({"untrusted": true});
    assert_unsupported_attested_key(key)
}

#[test]
fn rejects_small_order_ed25519_binding_key() -> Result<(), AttestedJwkTestError> {
    let mut identity_encoding = [0_u8; 32];
    identity_encoding[0] = 1;
    assert_unsupported_attested_key(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": bytes_to_base64url(&identity_encoding)
    }))
}

fn assert_unsupported_attested_key(key: Value) -> Result<(), AttestedJwkTestError> {
    let jwt = key_attestation_with_key(key)?;
    assert_eq!(
        parse_key_attestation(&jwt, &context()?)
            .err()
            .map(|error| error.status()),
        Some(AttestationStatus::UnsupportedAttestedKey)
    );
    Ok(())
}

fn key_attestation_with_key(key: Value) -> Result<KeyAttestationJwt, AttestedJwkTestError> {
    let header = serde_json::to_vec(&json!({
        "typ": "key-attestation+jwt",
        "alg": "ES256"
    }))
    .map_err(|_| AttestedJwkTestError::Json)?;
    let claims = serde_json::to_vec(&json!({
        "iat": 1_700_000_000_i64,
        "exp": 1_700_000_100_i64,
        "attested_keys": [key]
    }))
    .map_err(|_| AttestedJwkTestError::Json)?;
    let compact = [
        bytes_to_base64url(&header),
        bytes_to_base64url(&claims),
        bytes_to_base64url(b"signature"),
    ]
    .join(".");
    KeyAttestationJwt::new(compact).map_err(|_| AttestedJwkTestError::Attestation)
}

fn context() -> Result<KeyAttestationValidationContext, AttestedJwkTestError> {
    Ok(KeyAttestationValidationContext {
        nonce_required: false,
        expected_nonce: None,
        temporal_policy: KeyAttestationTemporalPolicy::new(1_700_000_000, 300, 60, false)
            .map_err(|_| AttestedJwkTestError::Attestation)?,
        accepted_algorithms: vec![KeyAttestationAlgorithm::Es256],
    })
}

fn valid_key() -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "B_zLQ0UJb5Yhcm_E5De-DPgcQxCB8yjlVJZyOaxVIu4",
        "y": "DZcUdT7G939Veqc3FCadWs_rcpS-vc_8Z8FaZREVX4A"
    })
}
