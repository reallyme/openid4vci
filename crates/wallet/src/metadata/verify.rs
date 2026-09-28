// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict parsing and verification engine for signed Credential Issuer Metadata.

use reallyme_codec::{base64url::base64url_to_bytes, jcs::canonicalize_json_text};
use serde::Deserialize;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use openid4vci_types::IssuerMetadata;

use super::{
    ParsedSignedIssuerMetadata, SignedIssuerMetadataJwt, SignedIssuerMetadataTrustVerifier,
    SignedIssuerMetadataValidationContext, SignedMetadataAlgorithm, SignedMetadataTrustEvidence,
    SignedMetadataTrustPurpose, VerifiedSignedIssuerMetadata,
};
use crate::error::{WalletError, WalletResult, WalletStatus};

const SIGNED_METADATA_TYP: &str = "openidvci-issuer-metadata+jwt";
const MAX_SIGNED_METADATA_HEADER_BYTES: usize = 8 * 1024;
const MAX_SIGNED_METADATA_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_SIGNED_METADATA_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_SIGNED_METADATA_CERTIFICATE_CHAIN_LENGTH: usize = 8;
const MAX_SIGNED_METADATA_CERTIFICATE_BYTES: usize = 6 * 1024;

/// Verifies signed Credential Issuer Metadata before returning typed metadata.
pub fn verify_signed_issuer_metadata(
    jwt: &SignedIssuerMetadataJwt,
    context: &SignedIssuerMetadataValidationContext,
    verifier: &dyn SignedIssuerMetadataTrustVerifier,
) -> WalletResult<VerifiedSignedIssuerMetadata> {
    let parsed = parse_signed_issuer_metadata(jwt, context)?;
    let trust_evidence =
        SignedMetadataTrustEvidence::new(verifier.verify_signed_issuer_metadata(jwt, &parsed)?)?;
    if trust_evidence.purpose() != SignedMetadataTrustPurpose::CredentialIssuerMetadata
        || trust_evidence.signer_trust_purpose() != context.required_signer_trust_purpose
        || parsed.issuer() != trust_evidence.asserted_issuer()
        || parsed.signing_input() != trust_evidence.verified_signing_input()
    {
        return Err(WalletError::new(
            WalletStatus::InvalidSignedMetadataTrustEvidence,
        ));
    }
    validate_signed_metadata_trust_freshness(&trust_evidence, context)?;

    // OpenID4VCI 1.0 Final §12.2.3 requires signer trust and signature
    // verification before the wallet processes any metadata parameters.
    let metadata = IssuerMetadata::parse_json(parsed.payload.as_str())
        .map_err(|_| WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    if metadata.credential_issuer != context.expected_credential_issuer {
        return Err(WalletError::new(WalletStatus::InvalidSignedMetadata));
    }
    Ok(VerifiedSignedIssuerMetadata {
        metadata,
        algorithm: parsed.algorithm,
        issued_at: parsed.issued_at,
        expires_at: parsed.expires_at,
        trust_evidence,
    })
}

fn validate_signed_metadata_trust_freshness(
    evidence: &SignedMetadataTrustEvidence,
    context: &SignedIssuerMetadataValidationContext,
) -> WalletResult<()> {
    let skew = i64::try_from(context.allowed_clock_skew_seconds)
        .map_err(|_| WalletError::new(WalletStatus::InvalidSignedMetadataTrustEvidence))?;
    let latest_evaluation = context
        .current_time
        .checked_add(skew)
        .ok_or(WalletError::new(
            WalletStatus::InvalidSignedMetadataTrustEvidence,
        ))?;
    let earliest_validity = context
        .current_time
        .checked_sub(skew)
        .ok_or(WalletError::new(
            WalletStatus::InvalidSignedMetadataTrustEvidence,
        ))?;
    if evidence.evaluated_at() > latest_evaluation {
        return Err(WalletError::new(
            WalletStatus::SignedMetadataTrustEvidenceFutureIssued,
        ));
    }
    if evidence.valid_until() < earliest_validity {
        return Err(WalletError::new(
            WalletStatus::SignedMetadataTrustEvidenceStale,
        ));
    }
    Ok(())
}

fn parse_signed_issuer_metadata(
    jwt: &SignedIssuerMetadataJwt,
    context: &SignedIssuerMetadataValidationContext,
) -> WalletResult<ParsedSignedIssuerMetadata> {
    let parts = split_compact_jws(jwt.as_str())?;
    let header = decode_strict_segment(
        parts.header,
        MAX_SIGNED_METADATA_HEADER_BYTES,
        WalletStatus::InvalidSignedMetadata,
    )?;
    let payload = decode_strict_segment(
        parts.payload,
        MAX_SIGNED_METADATA_PAYLOAD_BYTES,
        WalletStatus::InvalidSignedMetadata,
    )?;
    let signature = base64url_to_bytes(parts.signature)
        .map_err(|_| WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    if signature.len() > MAX_SIGNED_METADATA_SIGNATURE_BYTES {
        return Err(WalletError::new(WalletStatus::InvalidSignedMetadata));
    }

    let protected_header: Value = serde_json::from_str(header.as_str())
        .map_err(|_| WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    let typed_header: SignedMetadataHeader = serde_json::from_str(header.as_str())
        .map_err(|_| WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    let algorithm = validate_header(&typed_header, &context.accepted_algorithms)?;
    let claims: SignedMetadataClaims = serde_json::from_str(payload.as_str())
        .map_err(|_| WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    validate_claims(&claims, context)?;

    Ok(ParsedSignedIssuerMetadata {
        protected_header,
        signing_input: [parts.header, ".", parts.payload].concat(),
        signature,
        payload,
        issuer: claims.iss,
        subject: claims.sub,
        issued_at: claims.iat,
        expires_at: claims.exp,
        algorithm,
    })
}

struct CompactJwsParts<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}

fn split_compact_jws(jwt: &str) -> WalletResult<CompactJwsParts<'_>> {
    let mut parts = jwt.split('.');
    let header = parts
        .next()
        .ok_or(WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    let payload = parts
        .next()
        .ok_or(WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    let signature = parts
        .next()
        .ok_or(WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(WalletError::new(WalletStatus::InvalidSignedMetadata));
    }
    Ok(CompactJwsParts {
        header,
        payload,
        signature,
    })
}

fn decode_strict_segment(
    segment: &str,
    max_bytes: usize,
    status: WalletStatus,
) -> WalletResult<Zeroizing<String>> {
    let decoded =
        Zeroizing::new(base64url_to_bytes(segment).map_err(|_| WalletError::new(status))?);
    if decoded.len() > max_bytes {
        return Err(WalletError::new(status));
    }
    let text = core::str::from_utf8(decoded.as_slice()).map_err(|_| WalletError::new(status))?;
    let canonical = canonicalize_json_text(text).map_err(|_| WalletError::new(status))?;
    Ok(Zeroizing::new(canonical))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedMetadataHeader {
    alg: String,
    typ: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crit: Option<Value>,
    #[serde(default)]
    b64: Option<bool>,
    #[serde(default)]
    x5c: Option<Vec<String>>,
    #[serde(default)]
    trust_chain: Option<Vec<String>>,
}

fn validate_header(
    header: &SignedMetadataHeader,
    accepted_algorithms: &[SignedMetadataAlgorithm],
) -> WalletResult<SignedMetadataAlgorithm> {
    // OpenID4VCI 1.0 Final §12.2.3 fixes `typ` and requires asymmetric JWS.
    // RFC 7515 §4.1.1 and RFC 8725 §3.1 require an application allow-list.
    // RFC 7515 §4.1.11 requires rejection of unsupported critical headers;
    // RFC 7797 `b64` changes the signing input and is not implemented here.
    if header.typ != SIGNED_METADATA_TYP
        || header.kid.as_ref().is_some_and(String::is_empty)
        || header.crit.is_some()
        || header.b64.is_some()
        || !valid_untrusted_chain(header.x5c.as_deref())
        || !valid_untrusted_chain(header.trust_chain.as_deref())
    {
        return Err(WalletError::new(WalletStatus::InvalidSignedMetadata));
    }
    let algorithm = SignedMetadataAlgorithm::from_jose_name(&header.alg)?;
    if accepted_algorithms.is_empty() || !accepted_algorithms.contains(&algorithm) {
        return Err(WalletError::new(
            WalletStatus::SignedMetadataAlgorithmNotAllowed,
        ));
    }
    Ok(algorithm)
}

fn valid_untrusted_chain(chain: Option<&[String]>) -> bool {
    let Some(chain) = chain else {
        return true;
    };
    !chain.is_empty()
        && chain.len() <= MAX_SIGNED_METADATA_CERTIFICATE_CHAIN_LENGTH
        && chain.iter().all(|entry| {
            !entry.is_empty()
                && entry.len() <= MAX_SIGNED_METADATA_CERTIFICATE_BYTES
                && entry.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
                })
        })
}

#[derive(Deserialize)]
struct SignedMetadataClaims {
    #[serde(default)]
    iss: Option<String>,
    sub: String,
    iat: i64,
    #[serde(default)]
    exp: Option<i64>,
}

fn validate_claims(
    claims: &SignedMetadataClaims,
    context: &SignedIssuerMetadataValidationContext,
) -> WalletResult<()> {
    if claims.sub != context.expected_credential_issuer
        || claims.iat <= 0
        || claims.iss.as_ref().is_some_and(String::is_empty)
        || claims
            .exp
            .is_some_and(|expires_at| expires_at <= claims.iat)
    {
        return Err(WalletError::new(WalletStatus::InvalidSignedMetadata));
    }
    let max_age = i64::try_from(context.max_age_seconds)
        .map_err(|_| WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    let skew = i64::try_from(context.allowed_clock_skew_seconds)
        .map_err(|_| WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    let earliest = context
        .current_time
        .checked_sub(max_age)
        .and_then(|value| value.checked_sub(skew))
        .ok_or(WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    let latest = context
        .current_time
        .checked_add(skew)
        .ok_or(WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    if claims.iat < earliest {
        return Err(WalletError::new(WalletStatus::StaleSignedMetadata));
    }
    if claims.iat > latest {
        return Err(WalletError::new(WalletStatus::FutureSignedMetadata));
    }
    let expiration_cutoff = context
        .current_time
        .checked_sub(skew)
        .ok_or(WalletError::new(WalletStatus::InvalidSignedMetadata))?;
    // RFC 7519 §§4.1.4 and 4.1.6 permit only explicitly bounded leeway.
    if claims
        .exp
        .is_some_and(|expires_at| expires_at <= expiration_cutoff)
    {
        return Err(WalletError::new(WalletStatus::ExpiredSignedMetadata));
    }
    Ok(())
}

pub(super) fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => {
            for nested in values {
                zeroize_json_strings(nested);
            }
        }
        Value::Object(values) => {
            for nested in values.values_mut() {
                zeroize_json_strings(nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
