// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key-attestation JWT structural validation and trust-verifier boundary.

use reallyme_codec::{base64url::base64url_to_bytes, jcs::canonicalize_json_text};
use serde::Deserialize;
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{AttestationError, AttestationResult, AttestationStatus};
use crate::model::{
    zeroize_json_strings, AttackPotentialResistance, CertificationReference,
    KeyAttestationAlgorithm, KeyAttestationStatusEvidence, KeyAttestationStatusReference,
    KeyAttestationTemporalPolicy, KeyAttestationTrustEvidence, KeyAttestationTrustEvidenceInput,
    KeyAttestationTrustPurpose, VerifiedBindingKey,
};
use crate::validate_key_attestation_claims::{
    validate_key_attestation_claims, KeyAttestationClaims,
};
use crate::wrap::KeyAttestationJwt;

const KEY_ATTESTATION_TYP: &str = "key-attestation+jwt";
const MAX_DECODED_ATTESTATION_HEADER_BYTES: usize = 8_192;
const MAX_DECODED_ATTESTATION_CLAIMS_BYTES: usize = 32_768;
const MAX_DECODED_ATTESTATION_SIGNATURE_BYTES: usize = 16_384;

/// Validation context supplied by an issuer profile.
#[derive(ZeroizeOnDrop)]
pub struct KeyAttestationValidationContext {
    /// Whether the issuer requires a server-provided nonce.
    pub nonce_required: bool,
    /// Exact nonce value when storage can bind to a specific nonce.
    pub expected_nonce: Option<String>,
    /// Mandatory trusted-clock and freshness policy.
    #[zeroize(skip)]
    pub temporal_policy: KeyAttestationTemporalPolicy,
    /// Algorithms permitted by both issuer metadata and local policy.
    #[zeroize(skip)]
    pub accepted_algorithms: Vec<KeyAttestationAlgorithm>,
}

/// Verified key-attestation evidence returned to issuer proof policy.
pub struct VerifiedKeyAttestation {
    algorithm: KeyAttestationAlgorithm,
    key_id: Option<String>,
    attested_keys: Vec<VerifiedBindingKey>,
    attested_key_count: u32,
    issued_at: i64,
    expires_at: Option<i64>,
    key_storage: Option<Vec<AttackPotentialResistance>>,
    user_authentication: Option<Vec<AttackPotentialResistance>>,
    certification: Option<CertificationReference>,
    status: Option<KeyAttestationStatusReference>,
    nonce: Option<String>,
    trust_evidence: KeyAttestationTrustEvidence,
}

impl VerifiedKeyAttestation {
    /// Returns the accepted protected-header algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> KeyAttestationAlgorithm {
        self.algorithm
    }

    /// Returns the optional protected-header key identifier.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Returns the checked number of unique attested keys.
    #[must_use]
    pub const fn attested_key_count(&self) -> u32 {
        self.attested_key_count
    }

    /// Returns the validated credential-binding keys.
    #[must_use]
    pub fn attested_keys(&self) -> &[VerifiedBindingKey] {
        &self.attested_keys
    }

    /// Returns the accepted `iat` timestamp.
    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Returns the accepted optional `exp` timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    /// Returns the asserted key-storage resistance levels.
    #[must_use]
    pub fn key_storage(&self) -> Option<&[AttackPotentialResistance]> {
        self.key_storage.as_deref()
    }

    /// Returns the asserted user-authentication resistance levels.
    #[must_use]
    pub fn user_authentication(&self) -> Option<&[AttackPotentialResistance]> {
        self.user_authentication.as_deref()
    }

    /// Returns the asserted certification URL.
    #[must_use]
    pub const fn certification(&self) -> Option<&CertificationReference> {
        self.certification.as_ref()
    }

    /// Returns the retained status reference.
    #[must_use]
    pub const fn status(&self) -> Option<&KeyAttestationStatusReference> {
        self.status.as_ref()
    }

    /// Returns the validated nonce.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Returns signer trust and status provenance.
    #[must_use]
    pub const fn trust_evidence(&self) -> &KeyAttestationTrustEvidence {
        &self.trust_evidence
    }

    /// Transfers the nonce to another sensitive owner.
    pub fn take_nonce(&mut self) -> Option<String> {
        self.nonce.take()
    }

    /// Transfers the protected-header key identifier.
    pub fn take_key_id(&mut self) -> Option<String> {
        self.key_id.take()
    }
}

impl Drop for VerifiedKeyAttestation {
    fn drop(&mut self) {
        self.key_id.zeroize();
        self.nonce.zeroize();
    }
}

/// Structurally validated data supplied to the trust verifier.
pub struct ParsedKeyAttestation {
    protected_header: Value,
    signing_input: String,
    signature: Vec<u8>,
    algorithm: KeyAttestationAlgorithm,
    key_id: Option<String>,
    attested_keys: Vec<VerifiedBindingKey>,
    attested_key_count: u32,
    issued_at: i64,
    expires_at: Option<i64>,
    key_storage: Option<Vec<AttackPotentialResistance>>,
    user_authentication: Option<Vec<AttackPotentialResistance>>,
    certification: Option<CertificationReference>,
    status: Option<KeyAttestationStatusReference>,
    nonce: Option<String>,
}

impl ParsedKeyAttestation {
    /// Returns the strictly parsed protected header.
    #[must_use]
    pub const fn protected_header(&self) -> &Value {
        &self.protected_header
    }

    /// Returns the exact JWS signing input.
    #[must_use]
    pub fn signing_input(&self) -> &str {
        &self.signing_input
    }

    /// Returns the decoded JWS signature.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the locally accepted signing algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> KeyAttestationAlgorithm {
        self.algorithm
    }

    /// Returns the structurally validated binding keys.
    #[must_use]
    pub fn attested_keys(&self) -> &[VerifiedBindingKey] {
        &self.attested_keys
    }

    /// Returns asserted key-storage resistance levels.
    #[must_use]
    pub fn key_storage(&self) -> Option<&[AttackPotentialResistance]> {
        self.key_storage.as_deref()
    }

    /// Returns asserted user-authentication resistance levels.
    #[must_use]
    pub fn user_authentication(&self) -> Option<&[AttackPotentialResistance]> {
        self.user_authentication.as_deref()
    }

    /// Returns the asserted certification URL.
    #[must_use]
    pub const fn certification(&self) -> Option<&CertificationReference> {
        self.certification.as_ref()
    }

    /// Returns the retained status reference.
    #[must_use]
    pub const fn status(&self) -> Option<&KeyAttestationStatusReference> {
        self.status.as_ref()
    }

    /// Returns the structurally accepted `iat` timestamp.
    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Returns the structurally accepted optional `exp` timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    fn into_verified(self, trust_evidence: KeyAttestationTrustEvidence) -> VerifiedKeyAttestation {
        let mut owned = self;
        VerifiedKeyAttestation {
            algorithm: owned.algorithm,
            key_id: owned.key_id.take(),
            attested_keys: core::mem::take(&mut owned.attested_keys),
            attested_key_count: owned.attested_key_count,
            issued_at: owned.issued_at,
            expires_at: owned.expires_at,
            key_storage: owned.key_storage.take(),
            user_authentication: owned.user_authentication.take(),
            certification: owned.certification.take(),
            status: owned.status.take(),
            nonce: owned.nonce.take(),
            trust_evidence,
        }
    }
}

impl Drop for ParsedKeyAttestation {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.protected_header);
        self.signing_input.zeroize();
        self.signature.zeroize();
        self.key_id.zeroize();
        self.nonce.zeroize();
    }
}

/// Trust verifier injected by issuer adapters or services.
pub trait KeyAttestationTrustVerifier: Send + Sync {
    /// Verifies signature, signer trust, certification, and status, returning
    /// the exact provenance used for the credential-binding decision.
    fn verify_key_attestation(
        &self,
        jwt: &KeyAttestationJwt,
        parsed: &ParsedKeyAttestation,
    ) -> AttestationResult<KeyAttestationTrustEvidenceInput>;
}

/// Validates a key-attestation JWT and returns complete trusted evidence.
pub fn verify_key_attestation(
    jwt: &KeyAttestationJwt,
    context: &KeyAttestationValidationContext,
    verifier: &dyn KeyAttestationTrustVerifier,
) -> AttestationResult<VerifiedKeyAttestation> {
    let parsed = parse_key_attestation(jwt, context)?;
    let trust_evidence =
        KeyAttestationTrustEvidence::new(verifier.verify_key_attestation(jwt, &parsed)?)?;
    validate_trust_evidence(&parsed, &trust_evidence, &context.temporal_policy)?;
    Ok(parsed.into_verified(trust_evidence))
}

fn validate_trust_evidence(
    parsed: &ParsedKeyAttestation,
    evidence: &KeyAttestationTrustEvidence,
    temporal_policy: &KeyAttestationTemporalPolicy,
) -> AttestationResult<()> {
    if evidence.purpose() != KeyAttestationTrustPurpose::CredentialBinding
        || evidence.verified_signing_input() != parsed.signing_input()
    {
        return Err(AttestationError::new(
            AttestationStatus::InvalidTrustEvidence,
        ));
    }
    let current_time = temporal_policy.current_time();
    let skew = i64::try_from(temporal_policy.allowed_clock_skew_seconds())
        .map_err(|_| AttestationError::new(AttestationStatus::InvalidTrustEvidence))?;
    let latest_evaluation = current_time
        .checked_add(skew)
        .ok_or_else(|| AttestationError::new(AttestationStatus::InvalidTrustEvidence))?;
    let earliest_validity = current_time
        .checked_sub(skew)
        .ok_or_else(|| AttestationError::new(AttestationStatus::InvalidTrustEvidence))?;
    if evidence.evaluated_at() > latest_evaluation {
        return Err(AttestationError::new(
            AttestationStatus::TrustEvidenceFutureIssued,
        ));
    }
    if evidence.valid_until() < earliest_validity {
        return Err(AttestationError::new(AttestationStatus::TrustEvidenceStale));
    }
    match (parsed.status().is_some(), evidence.status()) {
        (true, KeyAttestationStatusEvidence::Valid { evaluated_at }) => {
            // A retained status claim is useful only if the adapter evaluated
            // it for this verification event. Bind the receipt timestamp to
            // the same trusted clock (and explicit skew) as the JWT so stale
            // cached status evidence cannot silently authorize issuance.
            let (earliest, latest) = temporal_policy.status_evaluation_bounds()?;
            if evaluated_at < earliest || evaluated_at > latest {
                return Err(AttestationError::new(
                    AttestationStatus::StatusIndeterminate,
                ));
            }
            Ok(())
        }
        (false, KeyAttestationStatusEvidence::NotPresent) => Ok(()),
        (true, KeyAttestationStatusEvidence::NotPresent) => Err(AttestationError::new(
            AttestationStatus::StatusIndeterminate,
        )),
        (false, KeyAttestationStatusEvidence::Valid { .. }) => Err(AttestationError::new(
            AttestationStatus::InvalidTrustEvidence,
        )),
    }
}

/// Parses and validates key-attestation JWT structure without trusting it.
pub fn parse_key_attestation(
    jwt: &KeyAttestationJwt,
    context: &KeyAttestationValidationContext,
) -> AttestationResult<ParsedKeyAttestation> {
    let parts = split_compact_jwt(jwt.as_str())?;
    let header_json = decode_strict_json_segment(
        parts.header,
        MAX_DECODED_ATTESTATION_HEADER_BYTES,
        AttestationStatus::InvalidHeader,
    )?;
    let claims_json = decode_strict_json_segment(
        parts.payload,
        MAX_DECODED_ATTESTATION_CLAIMS_BYTES,
        AttestationStatus::InvalidClaims,
    )?;
    let signature = base64url_to_bytes(parts.signature)
        .map_err(|_| AttestationError::new(AttestationStatus::InvalidJwt))?;
    if signature.len() > MAX_DECODED_ATTESTATION_SIGNATURE_BYTES {
        return Err(AttestationError::new(AttestationStatus::InvalidJwt));
    }
    let header: KeyAttestationHeader = serde_json::from_str(header_json.as_str())
        .map_err(|_| AttestationError::new(AttestationStatus::InvalidHeader))?;
    let algorithm = validate_header(&header, &context.accepted_algorithms)?;
    let claims: KeyAttestationClaims = serde_json::from_str(claims_json.as_str())
        .map_err(|_| AttestationError::new(AttestationStatus::InvalidClaims))?;
    let attested_keys = validate_key_attestation_claims(&claims, context)?;
    let protected_header = serde_json::from_str(header_json.as_str())
        .map_err(|_| AttestationError::new(AttestationStatus::InvalidHeader))?;
    let attested_key_count = u32::try_from(attested_keys.len())
        .map_err(|_| AttestationError::new(AttestationStatus::InvalidClaims))?;
    Ok(ParsedKeyAttestation {
        protected_header,
        signing_input: [parts.header, ".", parts.payload].concat(),
        signature,
        algorithm,
        key_id: header.kid,
        attested_keys,
        attested_key_count,
        issued_at: claims.iat,
        expires_at: claims.exp,
        key_storage: parse_resistance_values(claims.key_storage)?,
        user_authentication: parse_resistance_values(claims.user_authentication)?,
        certification: claims.certification.map(CertificationReference::new),
        status: claims.status.map(KeyAttestationStatusReference::new),
        nonce: claims.nonce,
    })
}

fn parse_resistance_values(
    values: Option<Vec<String>>,
) -> AttestationResult<Option<Vec<AttackPotentialResistance>>> {
    let Some(values) = values else {
        return Ok(None);
    };
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        parsed.push(AttackPotentialResistance::parse(value)?);
    }
    Ok(Some(parsed))
}

fn decode_strict_json_segment(
    segment: &str,
    max_bytes: usize,
    invalid_status: AttestationStatus,
) -> AttestationResult<Zeroizing<String>> {
    let decoded = Zeroizing::new(
        base64url_to_bytes(segment)
            .map_err(|_| AttestationError::new(AttestationStatus::InvalidJwt))?,
    );
    if decoded.len() > max_bytes {
        return Err(AttestationError::new(invalid_status));
    }
    let text = core::str::from_utf8(decoded.as_slice())
        .map_err(|_| AttestationError::new(invalid_status))?;
    let canonical =
        canonicalize_json_text(text).map_err(|_| AttestationError::new(invalid_status))?;
    Ok(Zeroizing::new(canonical))
}

struct CompactJwtParts<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}

#[derive(Deserialize)]
struct KeyAttestationHeader {
    alg: String,
    typ: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crit: Option<Value>,
    #[serde(default)]
    b64: Option<bool>,
}

fn split_compact_jwt(jwt: &str) -> AttestationResult<CompactJwtParts<'_>> {
    let mut parts = jwt.split('.');
    let header = parts
        .next()
        .ok_or(AttestationError::new(AttestationStatus::InvalidJwt))?;
    let payload = parts
        .next()
        .ok_or(AttestationError::new(AttestationStatus::InvalidJwt))?;
    let signature = parts
        .next()
        .ok_or(AttestationError::new(AttestationStatus::InvalidJwt))?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(AttestationError::new(AttestationStatus::InvalidJwt));
    }
    Ok(CompactJwtParts {
        header,
        payload,
        signature,
    })
}

fn validate_header(
    header: &KeyAttestationHeader,
    accepted_algorithms: &[KeyAttestationAlgorithm],
) -> AttestationResult<KeyAttestationAlgorithm> {
    // RFC 7515 Section 4.1.9 and OpenID4VCI Appendix D.1 require explicit
    // type separation. RFC 8725 Sections 3.1 and 3.11 require an allow-listed
    // algorithm and mutually exclusive validation rules.
    // RFC 7515 Section 4.1.11 requires rejection when a critical extension is
    // not understood. This profile implements no critical JOSE extensions.
    // In particular, RFC 7797 changes the signing-input construction when
    // `b64` is false, so accepting it under the ordinary compact-JWS parser
    // would create different bytes for structural and signature validation.
    if header.typ != KEY_ATTESTATION_TYP || header.crit.is_some() || header.b64.is_some() {
        return Err(AttestationError::new(AttestationStatus::InvalidHeader));
    }
    let algorithm = KeyAttestationAlgorithm::from_jose_name(&header.alg)?;
    if accepted_algorithms.is_empty() || !accepted_algorithms.contains(&algorithm) {
        return Err(AttestationError::new(
            AttestationStatus::AlgorithmNotAllowed,
        ));
    }
    if header.kid.as_ref().is_some_and(String::is_empty) {
        return Err(AttestationError::new(AttestationStatus::InvalidHeader));
    }
    Ok(algorithm)
}
