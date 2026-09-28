// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cryptographic tests for the example issuer's pinned key-attestation provider.

use openid4vci_attestation::{
    verify_key_attestation, AttestationStatus, KeyAttestationAlgorithm, KeyAttestationJwt,
    KeyAttestationTemporalPolicy, KeyAttestationValidationContext,
};
use serde_json::json;

use super::run::{CONFORMANCE_ATTESTER_PUBLIC_X, CONFORMANCE_ATTESTER_PUBLIC_Y};
use super::sign::sign_es256_jws;
use super::store_authorization_state::ExampleOAuthAuthorizationServer;
use super::verify::ExampleKeyAttestationTrustVerifier;

const TEST_NONCE: &str = "key-attestation-test-nonce";

#[test]
fn pinned_provider_verifies_the_real_attestation_signature() -> Result<(), AttestationStatus> {
    let (jwt, context) = signed_attestation()?;
    let verified = verify_key_attestation(&jwt, &context, &ExampleKeyAttestationTrustVerifier)
        .map_err(|error| error.status())?;

    assert_eq!(verified.algorithm(), KeyAttestationAlgorithm::Es256);
    assert_eq!(verified.attested_key_count(), 1);
    assert_eq!(
        verified.trust_evidence().signer_identity(),
        "oidf-key-attester"
    );
    Ok(())
}

#[test]
fn pinned_provider_rejects_a_tampered_attestation_signature() -> Result<(), AttestationStatus> {
    let (jwt, context) = signed_attestation()?;
    let mut tampered = jwt.as_str().to_owned();
    let signature_start = tampered
        .rfind('.')
        .and_then(|index| index.checked_add(1))
        .ok_or(AttestationStatus::InvalidJwt)?;
    let replacement = if tampered.as_bytes().get(signature_start) == Some(&b'A') {
        "B"
    } else {
        "A"
    };
    let signature_end = signature_start
        .checked_add(1)
        .ok_or(AttestationStatus::InvalidJwt)?;
    tampered.replace_range(signature_start..signature_end, replacement);
    let tampered = KeyAttestationJwt::new(tampered).map_err(|error| error.status())?;

    let error = verify_key_attestation(&tampered, &context, &ExampleKeyAttestationTrustVerifier)
        .err()
        .ok_or(AttestationStatus::InvalidJwt)?;
    assert_eq!(error.status(), AttestationStatus::SignatureRejected);
    Ok(())
}

fn signed_attestation(
) -> Result<(KeyAttestationJwt, KeyAttestationValidationContext), AttestationStatus> {
    let current_time = ExampleOAuthAuthorizationServer::now_unix_seconds()
        .and_then(|value| {
            i64::try_from(value).map_err(|_| {
                openid4vci_http::OAuthHttpError::new(
                    openid4vci_http::OAuthHttpErrorReason::InvalidRequest,
                )
            })
        })
        .map_err(|_| AttestationStatus::InvalidClaims)?;
    let expires_at = current_time
        .checked_add(300)
        .ok_or(AttestationStatus::InvalidClaims)?;
    let header = json!({"alg": "ES256", "typ": "key-attestation+jwt"});
    let claims = json!({
        "iat": current_time,
        "exp": expires_at,
        "nonce": TEST_NONCE,
        "attested_keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": CONFORMANCE_ATTESTER_PUBLIC_X,
            "y": CONFORMANCE_ATTESTER_PUBLIC_Y
        }]
    });
    let jwt = sign_es256_jws(&header, &claims)
        .map_err(|_| AttestationStatus::SignatureRejected)
        .and_then(|value| KeyAttestationJwt::new(value).map_err(|error| error.status()))?;
    let temporal_policy = KeyAttestationTemporalPolicy::new(current_time, 300, 60, true)
        .map_err(|error| error.status())?;
    Ok((
        jwt,
        KeyAttestationValidationContext {
            nonce_required: true,
            expected_nonce: Some(TEST_NONCE.to_owned()),
            temporal_policy,
            accepted_algorithms: vec![KeyAttestationAlgorithm::Es256],
        },
    ))
}
