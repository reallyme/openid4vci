// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof verification interfaces.

use core::fmt;

use reallyme_codec::{base64url::base64url_to_bytes, jcs::canonicalize_json_text};
use serde::{
    de::{DeserializeOwned, Error as SerdeError, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

/// Maximum accepted compact proof JWT size.
///
/// The cap keeps memory use predictable before an adapter or crypto backend sees
/// attacker-controlled proof material.
pub const DEFAULT_MAX_PROOF_JWT_BYTES: usize = 64 * 1024;

/// Maximum decoded JOSE header size accepted from a proof JWT.
const MAX_DECODED_PROOF_HEADER_BYTES: usize = 8_192;

/// Maximum decoded claims size accepted from a proof JWT.
const MAX_DECODED_PROOF_PAYLOAD_BYTES: usize = 32_768;

/// JWK members that carry private or symmetric key material.
///
/// The proof parser handles untrusted JSON before the JOSE backend sees it, so
/// it must reject these names itself rather than relying on a downstream JWK
/// deserializer. The aliases cover private-key forms accepted by some generic
/// key tooling and prevent them from being retained as ignored extensions.
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

/// Bound on JWK members before an untrusted proof reaches a JOSE provider.
const MAX_PROOF_JWK_MEMBERS: usize = 32;

/// Required JOSE `typ` for an OpenID4VCI key proof JWT (Appendix F.1).
pub const PROOF_JWT_TYP: &str = "openid4vci-proof+jwt";
/// Maximum accepted age of a JWT key proof.
pub const MAX_PROOF_AGE_SECONDS: i64 = 300;
/// Maximum accepted proof timestamp skew into the future.
pub const MAX_PROOF_FUTURE_SKEW_SECONDS: i64 = 60;

use super::verify::{ConfirmationJwk, ProofAlgorithm, ProofVerificationContext};

/// Parsed, untrusted compact JWT claims used for deterministic verifier routing.
pub struct UnverifiedProofClaims {
    /// Required issued-at timestamp.
    pub issued_at: i64,
    /// Optional OAuth client identifier asserted by the proof JWT.
    pub issuer: Option<String>,
    /// Optional nonce claim.
    pub nonce: Option<String>,
    /// Optional audience claim. Array audiences are rejected by this parser.
    pub audience: Option<String>,
    /// Optional key-binding identifier.
    pub key_binding_id: Option<String>,
    /// Optional key identifier from the JWT header.
    pub key_id: Option<String>,
    /// JWT algorithm from the header.
    pub algorithm: String,
    /// Public confirmation key carried by protected-header `jwk`, when present.
    pub confirmation_jwk: Option<ConfirmationJwk>,
    /// Optional key attestation JWT from the proof header.
    pub key_attestation: Option<String>,
    /// Validated proof-key binding retained for the JOSE adapter.
    // Keep the base parser's validation and output shape identical across
    // provider features; only the JOSE adapter consumes this internal field.
    #[cfg_attr(not(feature = "identity-jose"), allow(dead_code))]
    pub(crate) proof_key_binding: Option<UnverifiedProofKeyBinding>,
}

impl Drop for UnverifiedProofClaims {
    fn drop(&mut self) {
        self.issuer.zeroize();
        self.nonce.zeroize();
        self.audience.zeroize();
        self.key_binding_id.zeroize();
        self.key_id.zeroize();
        self.algorithm.zeroize();
        self.key_attestation.zeroize();
    }
}

/// Proof-key binding parsed at the single reviewed JWT JSON boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnverifiedProofKeyBinding {
    Jwk(Value),
    Kid(String),
    X5c(Vec<String>),
}

/// Public JWK parsed without ever materializing forbidden private values.
struct PublicJwkValue(Value);

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
            if member_count > MAX_PROOF_JWK_MEMBERS
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

#[derive(Deserialize)]
struct ProofJwtHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    jwk: Option<PublicJwkValue>,
    #[serde(default)]
    x5c: Option<Vec<String>>,
    #[serde(default)]
    key_attestation: Option<String>,
    #[serde(default)]
    trust_chain: Option<Value>,
    #[serde(default)]
    crit: Option<Value>,
    #[serde(default)]
    b64: Option<bool>,
}

/// Bounded compact-JWT parser for issuer proof verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactProofJwtParser {
    max_jwt_bytes: usize,
}

impl Default for CompactProofJwtParser {
    fn default() -> Self {
        Self {
            max_jwt_bytes: DEFAULT_MAX_PROOF_JWT_BYTES,
        }
    }
}

impl CompactProofJwtParser {
    /// Creates a parser using an explicit maximum accepted compact JWT size.
    #[must_use]
    pub const fn new(max_jwt_bytes: usize) -> Self {
        Self { max_jwt_bytes }
    }

    /// Parses selected header and payload claims without trusting the signature.
    pub fn parse_unverified(&self, jwt: &str) -> IssuerResult<UnverifiedProofClaims> {
        if jwt.is_empty() || jwt.len() > self.max_jwt_bytes || jwt.trim() != jwt {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }

        let (header_segment, payload_segment) = split_compact_jwt(jwt)?;
        let header: ProofJwtHeader =
            parse_strict_jwt_json(header_segment, MAX_DECODED_PROOF_HEADER_BYTES)?;
        validate_header(&header)?;
        let payload: Value =
            parse_strict_jwt_json(payload_segment, MAX_DECODED_PROOF_PAYLOAD_BYTES)?;
        let issued_at = require_iat(&payload)?;
        let algorithm = ProofAlgorithm::from_jws_alg(&header.alg)?;
        let confirmation_jwk = extract_confirmation_jwk(&header, algorithm)?;
        let proof_key_binding = extract_proof_key_binding(&header);
        Ok(UnverifiedProofClaims {
            issued_at,
            issuer: optional_string_claim(&payload, "iss")?,
            nonce: optional_string_claim(&payload, "nonce")?,
            audience: optional_audience_claim(&payload)?,
            key_binding_id: optional_string_claim(&payload, "key_binding_id")?,
            key_id: header.kid,
            algorithm: header.alg,
            confirmation_jwk,
            key_attestation: header.key_attestation,
            proof_key_binding,
        })
    }
}

fn parse_strict_jwt_json<T: DeserializeOwned>(segment: &str, max_bytes: usize) -> IssuerResult<T> {
    let decoded = Zeroizing::new(
        base64url_to_bytes(segment).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?,
    );
    if decoded.len() > max_bytes {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    let text = core::str::from_utf8(decoded.as_slice())
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
    // The shared codec parser rejects duplicate members, trailing data, and
    // excessive nesting before Serde can discard that security provenance.
    let canonical = Zeroizing::new(
        canonicalize_json_text(text).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?,
    );
    serde_json::from_str(canonical.as_str())
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))
}

fn split_compact_jwt(jwt: &str) -> IssuerResult<(&str, &str)> {
    let mut parts = jwt.split('.');
    let header = parts
        .next()
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    let payload = parts
        .next()
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    let signature = parts
        .next()
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    Ok((header, payload))
}

fn validate_header(header: &ProofJwtHeader) -> IssuerResult<()> {
    match header.alg.as_str() {
        "ES256" | "ES256K" | "EdDSA" => {}
        "none" => return Err(IssuerError::new(IssuerStatus::InvalidProof)),
        _ => return Err(IssuerError::new(IssuerStatus::InvalidProof)),
    }
    // OpenID4VCI 1.0 Appendix F.1: `typ` is REQUIRED and MUST be
    // `openid4vci-proof+jwt`. The draft-era `JWT` and absent-typ forms are
    // rejected to prevent token confusion.
    if header.typ.as_deref() != Some(PROOF_JWT_TYP) {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    if matches!(header.kid.as_deref(), Some("")) {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    let binding_header_count = usize::from(header.kid.is_some())
        .saturating_add(usize::from(header.jwk.is_some()))
        .saturating_add(usize::from(header.x5c.is_some()));
    // Appendix F.1 makes the three mechanisms mutually exclusive and requires
    // signature validation through one of them. Enforce that invariant at the
    // parser boundary so no parser-only consumer can observe an unbound proof.
    if binding_header_count != 1 {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    if let Some(x5c) = &header.x5c {
        if x5c.is_empty() || x5c.iter().any(String::is_empty) {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
    }
    if let Some(key_attestation) = &header.key_attestation {
        validate_compact_header_jwt(key_attestation)?;
    }
    // RFC 7515 Section 4.1.11 requires a verifier to understand every
    // protected critical extension. RFC 7797 changes the JWS signing input
    // when `b64` is used, so this compact-JWT boundary rejects both forms
    // until a dedicated implementation can verify those semantics.
    if header.crit.is_some() || header.b64.is_some() {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    // OpenID4VCI Appendix F.1 permits `trust_chain`, but this verifier does not
    // yet expose the chain to a trust resolver. Silently discarding a known
    // trust-bearing header would make its nested algorithms and policies
    // unverifiable, so unsupported chains fail closed.
    if header.trust_chain.is_some() {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    Ok(())
}

fn optional_string_claim(payload: &Value, name: &'static str) -> IssuerResult<Option<String>> {
    match payload.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(_) => Err(IssuerError::new(IssuerStatus::InvalidProof)),
    }
}

fn optional_audience_claim(payload: &Value) -> IssuerResult<Option<String>> {
    match payload.get("aud") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(_) => Err(IssuerError::new(IssuerStatus::InvalidProof)),
    }
}

fn extract_confirmation_jwk(
    header: &ProofJwtHeader,
    algorithm: ProofAlgorithm,
) -> IssuerResult<Option<ConfirmationJwk>> {
    // OpenID4VCI 1.0 Appendix F.1: the proof key MUST be identified in the JOSE
    // header via `jwk`, `kid`, or `x5c`. The draft-era payload `cnf.jwk` binding
    // is not accepted. A `kid`/`x5c` binding carries no inline key here and is
    // resolved by the verifier backend.
    match &header.jwk {
        Some(jwk) => jwk_value_to_confirmation(&jwk.0, algorithm),
        None => Ok(None),
    }
}

fn extract_proof_key_binding(header: &ProofJwtHeader) -> Option<UnverifiedProofKeyBinding> {
    if let Some(jwk) = &header.jwk {
        Some(UnverifiedProofKeyBinding::Jwk(jwk.0.clone()))
    } else if let Some(kid) = &header.kid {
        Some(UnverifiedProofKeyBinding::Kid(kid.clone()))
    } else {
        header
            .x5c
            .as_ref()
            .map(|chain| UnverifiedProofKeyBinding::X5c(chain.clone()))
    }
}

/// OpenID4VCI 1.0 Appendix F.1: the key proof `iat` claim is REQUIRED and must
/// be a positive integer (issued-at time in seconds).
fn require_iat(payload: &Value) -> IssuerResult<i64> {
    let issued_at = payload
        .get("iat")
        .and_then(Value::as_i64)
        .filter(|iat| *iat > 0)
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    Ok(issued_at)
}

fn jwk_value_to_confirmation(
    jwk: &Value,
    algorithm: ProofAlgorithm,
) -> IssuerResult<Option<ConfirmationJwk>> {
    let jwk = jwk
        .as_object()
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    if contains_private_jwk_material(jwk) {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    let key_id = jwk.get("kid").and_then(Value::as_str).map(str::to_owned);
    let public_key = match (kty, algorithm) {
        ("OKP", ProofAlgorithm::EdDsa) => {
            let crv = required_jwk_string(jwk, "crv")?;
            if crv != "Ed25519" {
                return Err(IssuerError::new(IssuerStatus::InvalidProof));
            }
            let x = decode_jwk_coordinate(jwk, "x")?;
            if x.len() != 32 {
                return Err(IssuerError::new(IssuerStatus::InvalidProof));
            }
            x
        }
        ("EC", ProofAlgorithm::Es256) => {
            let crv = required_jwk_string(jwk, "crv")?;
            if crv != "P-256" {
                return Err(IssuerError::new(IssuerStatus::InvalidProof));
            }
            sec1_public_key(jwk)?
        }
        ("EC", ProofAlgorithm::Es256k) => {
            let crv = required_jwk_string(jwk, "crv")?;
            if crv != "secp256k1" {
                return Err(IssuerError::new(IssuerStatus::InvalidProof));
            }
            sec1_public_key(jwk)?
        }
        _ => return Err(IssuerError::new(IssuerStatus::InvalidProof)),
    };
    Ok(Some(ConfirmationJwk {
        algorithm,
        public_key,
        key_id,
    }))
}

fn contains_private_jwk_material(jwk: &serde_json::Map<String, Value>) -> bool {
    PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| jwk.contains_key(*member))
}

fn validate_compact_header_jwt(jwt: &str) -> IssuerResult<()> {
    let mut parts = jwt.split('.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    let extra = parts.next();
    match (header, payload, signature, extra) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok(())
        }
        _ => Err(IssuerError::new(IssuerStatus::InvalidProof)),
    }
}

fn required_jwk_string<'a>(
    jwk: &'a serde_json::Map<String, Value>,
    name: &'static str,
) -> IssuerResult<&'a str> {
    jwk.get(name)
        .and_then(Value::as_str)
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))
}

fn decode_jwk_coordinate(
    jwk: &serde_json::Map<String, Value>,
    name: &'static str,
) -> IssuerResult<Vec<u8>> {
    let value = required_jwk_string(jwk, name)?;
    base64url_to_bytes(value).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))
}

fn sec1_public_key(jwk: &serde_json::Map<String, Value>) -> IssuerResult<Vec<u8>> {
    let x = decode_jwk_coordinate(jwk, "x")?;
    let y = decode_jwk_coordinate(jwk, "y")?;
    if x.len() != 32 || y.len() != 32 {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Ok(out)
}

/// Validates nonce and audience claims common to final-spec proof types.
pub fn validate_common_proof_claims(
    claims: &UnverifiedProofClaims,
    context: &ProofVerificationContext,
) -> IssuerResult<()> {
    let earliest = context
        .current_time
        .checked_sub(MAX_PROOF_AGE_SECONDS)
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    let latest = context
        .current_time
        .checked_add(MAX_PROOF_FUTURE_SKEW_SECONDS)
        .ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    if claims.issued_at < earliest || claims.issued_at > latest {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    if context.nonce_required && claims.nonce.is_none() {
        return Err(IssuerError::new(IssuerStatus::InvalidNonce));
    }
    if claims.audience.as_deref() != Some(context.credential_issuer.as_str()) {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    if let Some(issuer) = claims.issuer.as_deref() {
        if context.client_id.as_deref() != Some(issuer) {
            return Err(IssuerError::new(IssuerStatus::InvalidProof));
        }
    }
    Ok(())
}
