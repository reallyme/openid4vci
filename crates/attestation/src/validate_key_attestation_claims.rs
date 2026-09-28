// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validation for key-attestation JWT claims and public JWK values.

use core::fmt;

use ed25519_dalek::VerifyingKey;
use reallyme_codec::{base64url::base64url_to_bytes, jcs::canonicalize_trusted_json_value};
use reallyme_crypto::jwk::Jwk;
use serde::{
    de::{Error as SerdeError, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{AttestationError, AttestationResult, AttestationStatus};
use crate::model::{BindingKeyAlgorithm, BindingKeyMaterial, VerifiedBindingKey};
use crate::verify_key_attestation::KeyAttestationValidationContext;

const MAX_ATTESTED_JWK_JSON_BYTES: usize = 8_192;
const MAX_ATTESTED_KEYS: usize = 64;
const MAX_ATTESTED_JWK_MEMBERS: usize = 32;
const MAX_RESISTANCE_VALUES: usize = 16;
const MAX_RESISTANCE_VALUE_BYTES: usize = 128;
const MAX_CERTIFICATION_URI_BYTES: usize = 2_048;

/// JWK members that carry private or symmetric key material.
///
/// Key attestations assert public keys. Rejecting member names, regardless of
/// their values, prevents secret material from crossing this JSON boundary or
/// being retained as an ignored extension by a downstream key parser.
const PRIVATE_JWK_MEMBERS: &[&str] = &[
    "d",
    "p",
    "q",
    "dp",
    "dq",
    "qi",
    "oth",
    "k",
    "priv",
    "privateKey",
    "secretKey",
];

#[derive(Deserialize)]
pub(crate) struct KeyAttestationClaims {
    pub(crate) iat: i64,
    #[serde(default)]
    pub(crate) exp: Option<i64>,
    pub(crate) attested_keys: Vec<PublicJwkValue>,
    #[serde(default)]
    pub(crate) key_storage: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) user_authentication: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) certification: Option<String>,
    #[serde(default)]
    pub(crate) nonce: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<Value>,
}

/// Public JWK parsed without ever materializing forbidden private values.
pub(crate) struct PublicJwkValue(Value);

impl PublicJwkValue {
    fn as_value(&self) -> &Value {
        &self.0
    }
}

struct PublicJwkVisitor;

impl<'de> Visitor<'de> for PublicJwkVisitor {
    type Value = PublicJwkValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a public JWK object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut members = serde_json::Map::new();
        let mut member_count = 0_usize;
        while let Some(name) = map.next_key::<String>()? {
            member_count = member_count
                .checked_add(1)
                .ok_or_else(|| A::Error::custom("invalid public JWK"))?;
            if member_count > MAX_ATTESTED_JWK_MEMBERS
                || PRIVATE_JWK_MEMBERS.contains(&name.as_str())
                || members.contains_key(&name)
            {
                return Err(A::Error::custom("invalid public JWK"));
            }
            let value = map.next_value::<Value>()?;
            members.insert(name, value);
        }
        Ok(PublicJwkValue(Value::Object(members)))
    }
}

impl<'de> Deserialize<'de> for PublicJwkValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PublicJwkVisitor)
    }
}

pub(crate) fn validate_key_attestation_claims(
    claims: &KeyAttestationClaims,
    context: &KeyAttestationValidationContext,
) -> AttestationResult<Vec<VerifiedBindingKey>> {
    validate_temporal_claims(claims.iat, claims.exp, context)?;
    if claims.attested_keys.is_empty() || claims.attested_keys.len() > MAX_ATTESTED_KEYS {
        return Err(AttestationError::new(AttestationStatus::InvalidClaims));
    }
    let mut verified_keys = Vec::with_capacity(claims.attested_keys.len());
    for key in &claims.attested_keys {
        let verified_key = validate_public_jwk(key)?;
        if verified_keys
            .iter()
            .any(|existing: &VerifiedBindingKey| existing.same_public_key(&verified_key))
        {
            return Err(AttestationError::new(
                AttestationStatus::DuplicateAttestedKey,
            ));
        }
        verified_keys.push(verified_key);
    }
    validate_optional_non_empty_strings(&claims.key_storage)?;
    validate_optional_non_empty_strings(&claims.user_authentication)?;
    validate_certification(claims.certification.as_deref())?;
    if claims
        .status
        .as_ref()
        .is_some_and(|status| status.as_object().is_none_or(serde_json::Map::is_empty))
    {
        return Err(AttestationError::new(AttestationStatus::InvalidClaims));
    }
    validate_nonce(claims.nonce.as_deref(), context)?;
    Ok(verified_keys)
}

fn validate_temporal_claims(
    issued_at: i64,
    expires_at: Option<i64>,
    context: &KeyAttestationValidationContext,
) -> AttestationResult<()> {
    // OpenID4VCI 1.0 Appendix D.1 requires `iat` and, for a JWT proof,
    // `exp`. RFC 7519 Sections 4.1.4 and 4.1.6 permit bounded clock skew;
    // this issuer policy also places an explicit maximum age on `iat`.
    if issued_at <= 0 {
        return Err(AttestationError::new(AttestationStatus::InvalidClaims));
    }
    let (earliest, latest) = context.temporal_policy.accepted_iat_bounds()?;
    if issued_at < earliest {
        return Err(AttestationError::new(AttestationStatus::Stale));
    }
    if issued_at > latest {
        return Err(AttestationError::new(AttestationStatus::FutureIssued));
    }
    if context.temporal_policy.expiration_required() && expires_at.is_none() {
        return Err(AttestationError::new(AttestationStatus::InvalidClaims));
    }
    if let Some(expires_at) = expires_at {
        if expires_at <= issued_at {
            return Err(AttestationError::new(AttestationStatus::InvalidClaims));
        }
        if expires_at <= context.temporal_policy.expiration_cutoff()? {
            return Err(AttestationError::new(AttestationStatus::Expired));
        }
    }
    Ok(())
}

fn validate_public_jwk(key: &PublicJwkValue) -> AttestationResult<VerifiedBindingKey> {
    let public_jwk = key.as_value();
    let canonical = Zeroizing::new(
        canonicalize_trusted_json_value(public_jwk)
            .map_err(|_| AttestationError::new(AttestationStatus::InvalidClaims))?,
    );
    if canonical.len() > MAX_ATTESTED_JWK_JSON_BYTES {
        return Err(AttestationError::new(AttestationStatus::InvalidClaims));
    }
    let object = public_jwk
        .as_object()
        .ok_or_else(|| AttestationError::new(AttestationStatus::InvalidClaims))?;
    if PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err(AttestationError::new(
            AttestationStatus::UnsupportedAttestedKey,
        ));
    }
    validate_optional_key_metadata(object)?;

    // RFC 7517 Section 4 defines the common JWK members. RFC 7518 Sections
    // 6.2 and 6.3 define the EC/OKP public parameters used here. Decode and
    // length-check coordinates now so downstream issuance never binds to an
    // opaque or partially interpreted JSON object.
    let key_type = required_string(object, "kty")?;
    let curve = required_string(object, "crv")?;
    let key_id = optional_non_empty_string(object, "kid")?.map(str::to_owned);
    let (algorithm, material) = match (key_type, curve) {
        ("EC", "P-256") => (
            BindingKeyAlgorithm::P256,
            BindingKeyMaterial::Ec {
                x: coordinate(object, "x")?,
                y: coordinate(object, "y")?,
            },
        ),
        ("EC", "secp256k1") => (
            BindingKeyAlgorithm::Secp256K1,
            BindingKeyMaterial::Ec {
                x: coordinate(object, "x")?,
                y: coordinate(object, "y")?,
            },
        ),
        ("OKP", "Ed25519") => {
            if object.contains_key("y") {
                return Err(AttestationError::new(
                    AttestationStatus::UnsupportedAttestedKey,
                ));
            }
            (
                BindingKeyAlgorithm::Ed25519,
                BindingKeyMaterial::Okp {
                    x: coordinate(object, "x")?,
                },
            )
        }
        _ => {
            return Err(AttestationError::new(
                AttestationStatus::UnsupportedAttestedKey,
            ));
        }
    };
    validate_declared_algorithm(object, algorithm)?;
    let typed_jwk = serde_json::from_value::<Jwk>(public_jwk.clone())
        .map_err(|_| AttestationError::new(AttestationStatus::UnsupportedAttestedKey))?;
    let validated_public_key = Zeroizing::new(
        typed_jwk
            .public_key_bytes()
            .map_err(|_| AttestationError::new(AttestationStatus::UnsupportedAttestedKey))?,
    );
    if validated_public_key.is_empty() {
        return Err(AttestationError::new(
            AttestationStatus::UnsupportedAttestedKey,
        ));
    }
    if algorithm == BindingKeyAlgorithm::Ed25519 {
        let bytes = <[u8; 32]>::try_from(validated_public_key.as_slice())
            .map_err(|_| AttestationError::new(AttestationStatus::UnsupportedAttestedKey))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| AttestationError::new(AttestationStatus::UnsupportedAttestedKey))?;
        if verifying_key.is_weak() {
            return Err(AttestationError::new(
                AttestationStatus::UnsupportedAttestedKey,
            ));
        }
    }
    let sanitized_public_jwk = sanitize_public_jwk(object);
    Ok(VerifiedBindingKey::new(
        algorithm,
        sanitized_public_jwk,
        key_id,
        material,
    ))
}

fn sanitize_public_jwk(object: &serde_json::Map<String, Value>) -> Value {
    // Credential `cnf.jwk` receives only members that identify and type the
    // verified public key. Attestation-specific or unknown extension members
    // must not cross into an issued credential as trusted claims.
    const RETAINED_MEMBERS: &[&str] = &["kty", "crv", "x", "y", "kid", "alg"];
    let mut sanitized = serde_json::Map::new();
    for member in RETAINED_MEMBERS {
        if let Some(value) = object.get(*member) {
            sanitized.insert((*member).to_owned(), value.clone());
        }
    }
    Value::Object(sanitized)
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    member: &str,
) -> AttestationResult<&'a str> {
    object
        .get(member)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AttestationError::new(AttestationStatus::UnsupportedAttestedKey))
}

fn optional_non_empty_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    member: &str,
) -> AttestationResult<Option<&'a str>> {
    match object.get(member) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        Some(_) => Err(AttestationError::new(
            AttestationStatus::UnsupportedAttestedKey,
        )),
    }
}

fn coordinate(
    object: &serde_json::Map<String, Value>,
    member: &str,
) -> AttestationResult<[u8; 32]> {
    let encoded = required_string(object, member)?;
    let decoded = Zeroizing::new(
        base64url_to_bytes(encoded)
            .map_err(|_| AttestationError::new(AttestationStatus::UnsupportedAttestedKey))?,
    );
    <[u8; 32]>::try_from(decoded.as_slice())
        .map_err(|_| AttestationError::new(AttestationStatus::UnsupportedAttestedKey))
}

fn validate_optional_key_metadata(
    object: &serde_json::Map<String, Value>,
) -> AttestationResult<()> {
    if optional_non_empty_string(object, "use")?.is_some_and(|value| value != "sig") {
        return Err(AttestationError::new(
            AttestationStatus::UnsupportedAttestedKey,
        ));
    }
    if let Some(operations) = object.get("key_ops") {
        let operations = operations
            .as_array()
            .ok_or_else(|| AttestationError::new(AttestationStatus::UnsupportedAttestedKey))?;
        if operations.len() != 1 || operations[0].as_str() != Some("verify") {
            return Err(AttestationError::new(
                AttestationStatus::UnsupportedAttestedKey,
            ));
        }
    }
    Ok(())
}

fn validate_declared_algorithm(
    object: &serde_json::Map<String, Value>,
    algorithm: BindingKeyAlgorithm,
) -> AttestationResult<()> {
    let expected = match algorithm {
        BindingKeyAlgorithm::P256 => "ES256",
        BindingKeyAlgorithm::Secp256K1 => "ES256K",
        BindingKeyAlgorithm::Ed25519 => "EdDSA",
    };
    if optional_non_empty_string(object, "alg")?.is_some_and(|value| value != expected) {
        return Err(AttestationError::new(
            AttestationStatus::UnsupportedAttestedKey,
        ));
    }
    Ok(())
}

fn validate_certification(certification: Option<&str>) -> AttestationResult<()> {
    let Some(certification) = certification else {
        return Ok(());
    };
    if certification.is_empty()
        || certification.len() > MAX_CERTIFICATION_URI_BYTES
        || certification.contains('\r')
        || certification.contains('\n')
        || Url::parse(certification).is_err()
    {
        return Err(AttestationError::new(AttestationStatus::InvalidClaims));
    }
    Ok(())
}

fn validate_optional_non_empty_strings(values: &Option<Vec<String>>) -> AttestationResult<()> {
    if values.as_ref().is_some_and(|values| {
        values.is_empty()
            || values.len() > MAX_RESISTANCE_VALUES
            || values.iter().any(|value| {
                value.is_empty()
                    || value.len() > MAX_RESISTANCE_VALUE_BYTES
                    || value.contains('\r')
                    || value.contains('\n')
            })
    }) {
        return Err(AttestationError::new(AttestationStatus::InvalidClaims));
    }
    Ok(())
}

fn validate_nonce(
    nonce: Option<&str>,
    context: &KeyAttestationValidationContext,
) -> AttestationResult<()> {
    if (context.nonce_required && nonce.is_none())
        || context
            .expected_nonce
            .as_ref()
            .is_some_and(|expected| nonce != Some(expected.as_str()))
        || matches!(nonce, Some(""))
    {
        return Err(AttestationError::new(AttestationStatus::InvalidNonce));
    }
    Ok(())
}
