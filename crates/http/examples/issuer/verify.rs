// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verifies wallet attestation JWTs used by the conformance issuer.

use openid4vci_attestation::{
    AttestationError, AttestationResult, AttestationStatus, KeyAttestationAlgorithm,
    KeyAttestationJwt, KeyAttestationStatusEvidence, KeyAttestationTrustEvidenceInput,
    KeyAttestationTrustPurpose, KeyAttestationTrustVerifier, ParsedKeyAttestation,
};
use openid4vci_http::{OAuthHttpError, OAuthHttpErrorReason, OAuthHttpResult};
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::verify;
use reallyme_crypto::jwk::Jwk;
use reallyme_crypto::p256::p256_ecdsa_jose_signature_to_der;
use serde_json::{json, Value};

use super::run::{
    CONFORMANCE_ATTESTER_PUBLIC_X, CONFORMANCE_ATTESTER_PUBLIC_Y,
    KEY_ATTESTATION_TRUST_VALIDITY_SECONDS,
};
use super::store_authorization_state::ExampleOAuthAuthorizationServer;

const KEY_ATTESTER_IDENTITY: &str = "oidf-key-attester";
const KEY_ATTESTATION_POLICY_VERSION: &str = "reallyme-oidf-key-attestation-v1";
const KEY_ATTESTATION_SOURCE_SNAPSHOT: &str = "oidf-conformance-suite-5.3.1";
const KEY_ATTESTATION_ANCHOR: &str = "oidf-conformance-p256-key-1";

/// Closed-set trust provider used by the deployable conformance issuer.
///
/// Production deployments inject their trust-registry provider through the
/// same interface. This provider is intentionally pinned to the OIDF fixture
/// key and still performs the real ES256 signature verification.
pub(super) struct ExampleKeyAttestationTrustVerifier;

impl KeyAttestationTrustVerifier for ExampleKeyAttestationTrustVerifier {
    fn verify_key_attestation(
        &self,
        _jwt: &KeyAttestationJwt,
        parsed: &ParsedKeyAttestation,
    ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
        if parsed.algorithm() != KeyAttestationAlgorithm::Es256 {
            return Err(AttestationError::new(
                AttestationStatus::AlgorithmNotAllowed,
            ));
        }
        if parsed.status().is_some() {
            // This pinned provider has no status-list resolver. A deployment
            // must not treat an unevaluated status claim as trusted evidence.
            return Err(AttestationError::new(
                AttestationStatus::StatusIndeterminate,
            ));
        }
        let jwk = conformance_attester_jwk()
            .map_err(|_| AttestationError::new(AttestationStatus::TrustRejected))?;
        let public_key = jwk
            .public_key_bytes()
            .map_err(|_| AttestationError::new(AttestationStatus::TrustRejected))?;
        let der_signature = p256_ecdsa_jose_signature_to_der(parsed.signature())
            .map_err(|_| AttestationError::new(AttestationStatus::SignatureRejected))?;
        verify(
            Algorithm::P256,
            &public_key,
            parsed.signing_input().as_bytes(),
            &der_signature,
        )
        .map_err(|_| AttestationError::new(AttestationStatus::SignatureRejected))?;

        let now = ExampleOAuthAuthorizationServer::now_unix_seconds()
            .and_then(|value| {
                i64::try_from(value)
                    .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
            })
            .map_err(|_| AttestationError::new(AttestationStatus::TrustIndeterminate))?;
        let valid_until = now
            .checked_add(KEY_ATTESTATION_TRUST_VALIDITY_SECONDS)
            .ok_or_else(|| AttestationError::new(AttestationStatus::TrustIndeterminate))?;
        Ok(KeyAttestationTrustEvidenceInput {
            verified_signing_input: parsed.signing_input().to_owned(),
            signer_identity: KEY_ATTESTER_IDENTITY.to_owned(),
            policy_version: KEY_ATTESTATION_POLICY_VERSION.to_owned(),
            source_snapshot: KEY_ATTESTATION_SOURCE_SNAPSHOT.to_owned(),
            anchor: KEY_ATTESTATION_ANCHOR.to_owned(),
            evaluated_at: now,
            valid_until,
            purpose: KeyAttestationTrustPurpose::CredentialBinding,
            status: KeyAttestationStatusEvidence::NotPresent,
        })
    }
}

pub(super) fn conformance_attester_jwk() -> OAuthHttpResult<Jwk> {
    serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "x": CONFORMANCE_ATTESTER_PUBLIC_X,
        "y": CONFORMANCE_ATTESTER_PUBLIC_Y
    }))
    .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))
}

pub(super) fn verify_compact_es256_jwt(jwt: &str, jwk: &Jwk) -> OAuthHttpResult<(Value, Value)> {
    let (protected, payload, signature) = split_compact_jwt(jwt)?;
    let header_bytes = base64url_to_bytes(protected)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let payload_bytes = base64url_to_bytes(payload)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let signature_bytes = base64url_to_bytes(signature)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let protected_header = serde_json::from_slice::<Value>(&header_bytes)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    if protected_header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
    }
    let claims = serde_json::from_slice::<Value>(&payload_bytes)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let public_key = jwk
        .public_key_bytes()
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let der_signature = p256_ecdsa_jose_signature_to_der(&signature_bytes)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let mut signing_input = protected.to_owned();
    signing_input.push('.');
    signing_input.push_str(payload);
    verify(
        Algorithm::P256,
        &public_key,
        signing_input.as_bytes(),
        &der_signature,
    )
    .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    Ok((protected_header, claims))
}

fn split_compact_jwt(jwt: &str) -> OAuthHttpResult<(&str, &str, &str)> {
    let mut parts = jwt.split('.');
    let protected = parts
        .next()
        .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let payload = parts
        .next()
        .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let signature = parts
        .next()
        .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    if parts.next().is_some() || protected.is_empty() || payload.is_empty() || signature.is_empty()
    {
        return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
    }
    Ok((protected, payload, signature))
}

pub(super) fn validate_temporal_claims(claims: &Value) -> OAuthHttpResult<()> {
    let now = ExampleOAuthAuthorizationServer::now_unix_seconds()?;
    let now_i64 =
        i64::try_from(now).map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let earliest_iat = now_i64
        .checked_sub(300)
        .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let latest_iat = now_i64
        .checked_add(60)
        .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
    let iat = integer_claim(claims, "iat")?;
    if iat < earliest_iat || iat > latest_iat {
        return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
    }
    if let Some(exp) = optional_integer_claim(claims, "exp")? {
        if exp <= now_i64 {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
    }
    if let Some(nbf) = optional_integer_claim(claims, "nbf")? {
        if nbf > latest_iat {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
    }
    Ok(())
}

pub(super) fn require_string_claim<'a>(
    claims: &'a Value,
    name: &'static str,
) -> OAuthHttpResult<&'a str> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))
}

fn integer_claim(claims: &Value, name: &'static str) -> OAuthHttpResult<i64> {
    optional_integer_claim(claims, name)?
        .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))
}

fn optional_integer_claim(claims: &Value, name: &'static str) -> OAuthHttpResult<Option<i64>> {
    match claims.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient)),
    }
}
