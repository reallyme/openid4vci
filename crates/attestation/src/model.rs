// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed key-attestation algorithms, binding keys, time policy, and trust evidence.

use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AttestationError, AttestationResult, AttestationStatus};

const MAX_TRUST_EVIDENCE_IDENTIFIER_BYTES: usize = 512;
const MAX_RESISTANCE_VALUE_BYTES: usize = 128;
const SEC1_UNCOMPRESSED_P256_PUBLIC_KEY_BYTES: usize = 65;
const SEC1_UNCOMPRESSED_POINT_PREFIX: u8 = 0x04;

/// JOSE algorithms supported by the ReallyMe key-attestation verification profile.
///
/// RFC 7518 algorithm identifiers are case-sensitive. Keeping this as an enum
/// prevents a syntactically plausible but unsupported `alg` string from being
/// represented as a verified algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAttestationAlgorithm {
    /// ECDSA using P-256 and SHA-256 (`ES256`).
    Es256,
    /// ECDSA using secp256k1 and SHA-256 (`ES256K`).
    Es256K,
    /// Edwards-curve signatures using Ed25519 (`EdDSA`).
    EdDsa,
}

impl KeyAttestationAlgorithm {
    /// Parses an algorithm supported by the local JOSE provider profile.
    pub(crate) fn from_jose_name(value: &str) -> AttestationResult<Self> {
        match value {
            "ES256" => Ok(Self::Es256),
            "ES256K" => Ok(Self::Es256K),
            "EdDSA" => Ok(Self::EdDsa),
            _ => Err(AttestationError::new(
                AttestationStatus::UnsupportedAlgorithm,
            )),
        }
    }

    /// Returns the RFC 7518 / JOSE registry identifier.
    #[must_use]
    pub const fn jose_name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es256K => "ES256K",
            Self::EdDsa => "EdDSA",
        }
    }
}

/// Supported cryptographic key identities for credential holder binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKeyAlgorithm {
    /// NIST P-256 public key.
    P256,
    /// secp256k1 public key.
    Secp256K1,
    /// Ed25519 public key.
    Ed25519,
}

/// Attack-potential resistance asserted for key storage or user authentication.
///
/// OpenID4VCI Appendix D.1 defines known ISO 18045 values but permits future
/// registered values. `Unregistered` keeps a bounded unknown value distinct
/// from malformed input and from a known value rejected by issuer policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackPotentialResistance {
    /// ISO/IEC 18045 basic resistance.
    Iso18045Basic,
    /// ISO/IEC 18045 enhanced-basic resistance.
    Iso18045EnhancedBasic,
    /// ISO/IEC 18045 moderate resistance.
    Iso18045Moderate,
    /// ISO/IEC 18045 high resistance.
    Iso18045High,
    /// Syntactically valid value not known to this library revision.
    Unregistered(String),
}

impl AttackPotentialResistance {
    /// Parses a bounded resistance identifier without erasing unknown values.
    pub fn parse(value: String) -> AttestationResult<Self> {
        if value.is_empty()
            || value.len() > MAX_RESISTANCE_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(AttestationError::new(AttestationStatus::InvalidClaims));
        }
        Ok(match value.as_str() {
            "iso_18045_basic" => Self::Iso18045Basic,
            "iso_18045_enhanced-basic" => Self::Iso18045EnhancedBasic,
            "iso_18045_moderate" => Self::Iso18045Moderate,
            "iso_18045_high" => Self::Iso18045High,
            _ => Self::Unregistered(value),
        })
    }

    /// Returns the exact protocol identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Iso18045Basic => "iso_18045_basic",
            Self::Iso18045EnhancedBasic => "iso_18045_enhanced-basic",
            Self::Iso18045Moderate => "iso_18045_moderate",
            Self::Iso18045High => "iso_18045_high",
            Self::Unregistered(value) => value,
        }
    }

    /// Returns whether this library revision recognizes the value.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        !matches!(self, Self::Unregistered(_))
    }
}

impl Drop for AttackPotentialResistance {
    fn drop(&mut self) {
        if let Self::Unregistered(value) = self {
            value.zeroize();
        }
    }
}

/// Bounded, syntactically valid certification URI.
#[derive(ZeroizeOnDrop)]
pub struct CertificationReference(String);

impl CertificationReference {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the exact certification URI.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque bounded status reference whose semantics are evaluated by trust policy.
pub struct KeyAttestationStatusReference(Value);

impl KeyAttestationStatusReference {
    pub(crate) fn new(value: Value) -> Self {
        Self(value)
    }

    /// Returns the retained status object for a status adapter.
    #[must_use]
    pub const fn as_json(&self) -> &Value {
        &self.0
    }
}

impl Drop for KeyAttestationStatusReference {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

#[derive(PartialEq, Eq)]
pub(crate) enum BindingKeyMaterial {
    Ec { x: [u8; 32], y: [u8; 32] },
    Okp { x: [u8; 32] },
}

/// A validated public JWK that can be used as a credential binding key.
///
/// Construction is crate-private so issuer code cannot manufacture a
/// "verified" key from unvalidated JSON. Coordinates are decoded and checked
/// according to RFC 7517 and RFC 7518 before this type is created.
pub struct VerifiedBindingKey {
    algorithm: BindingKeyAlgorithm,
    public_jwk: Value,
    key_id: Option<String>,
    pub(crate) material: BindingKeyMaterial,
}

impl VerifiedBindingKey {
    pub(crate) fn new(
        algorithm: BindingKeyAlgorithm,
        public_jwk: Value,
        key_id: Option<String>,
        material: BindingKeyMaterial,
    ) -> Self {
        Self {
            algorithm,
            public_jwk,
            key_id,
            material,
        }
    }

    /// Returns the validated key algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> BindingKeyAlgorithm {
        self.algorithm
    }

    /// Returns the sanitized public JWK.
    #[must_use]
    pub const fn public_jwk(&self) -> &Value {
        &self.public_jwk
    }

    /// Returns the optional non-empty JWK key identifier.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Returns normalized public key bytes for credential holder binding.
    ///
    /// Edwards keys are returned as the raw 32-byte public key. EC keys are
    /// returned in SEC1 uncompressed form (`0x04 || x || y`).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match &self.material {
            BindingKeyMaterial::Ec { x, y } => {
                let mut bytes = Vec::with_capacity(SEC1_UNCOMPRESSED_P256_PUBLIC_KEY_BYTES);
                bytes.push(SEC1_UNCOMPRESSED_POINT_PREFIX);
                bytes.extend_from_slice(x);
                bytes.extend_from_slice(y);
                bytes
            }
            BindingKeyMaterial::Okp { x } => x.to_vec(),
        }
    }

    pub(crate) fn same_public_key(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.material == other.material
    }
}

impl Drop for VerifiedBindingKey {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.public_jwk);
        self.key_id.zeroize();
    }
}

/// Mandatory time and freshness policy for key-attestation validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAttestationTemporalPolicy {
    current_time: i64,
    max_age_seconds: u64,
    allowed_clock_skew_seconds: u64,
    expiration_required: bool,
}

impl KeyAttestationTemporalPolicy {
    /// Creates a checked temporal policy.
    pub fn new(
        current_time: i64,
        max_age_seconds: u64,
        allowed_clock_skew_seconds: u64,
        expiration_required: bool,
    ) -> AttestationResult<Self> {
        let policy = Self {
            current_time,
            max_age_seconds,
            allowed_clock_skew_seconds,
            expiration_required,
        };
        policy.accepted_iat_bounds()?;
        Ok(policy)
    }

    /// Returns the trusted Unix timestamp used for validation.
    #[must_use]
    pub const fn current_time(&self) -> i64 {
        self.current_time
    }

    /// Returns whether `exp` is mandatory in the selected proof mode.
    #[must_use]
    pub const fn expiration_required(&self) -> bool {
        self.expiration_required
    }

    /// Returns the configured symmetric clock-skew allowance.
    #[must_use]
    pub const fn allowed_clock_skew_seconds(&self) -> u64 {
        self.allowed_clock_skew_seconds
    }

    pub(crate) fn accepted_iat_bounds(&self) -> AttestationResult<(i64, i64)> {
        if self.current_time <= 0 {
            return Err(AttestationError::new(AttestationStatus::InvalidClaims));
        }
        let max_age = i64::try_from(self.max_age_seconds)
            .map_err(|_| AttestationError::new(AttestationStatus::InvalidClaims))?;
        let skew = i64::try_from(self.allowed_clock_skew_seconds)
            .map_err(|_| AttestationError::new(AttestationStatus::InvalidClaims))?;
        let earliest = self
            .current_time
            .checked_sub(max_age)
            .and_then(|value| value.checked_sub(skew))
            .ok_or_else(|| AttestationError::new(AttestationStatus::InvalidClaims))?;
        let latest = self
            .current_time
            .checked_add(skew)
            .ok_or_else(|| AttestationError::new(AttestationStatus::InvalidClaims))?;
        Ok((earliest, latest))
    }

    pub(crate) fn expiration_cutoff(&self) -> AttestationResult<i64> {
        let skew = i64::try_from(self.allowed_clock_skew_seconds)
            .map_err(|_| AttestationError::new(AttestationStatus::InvalidClaims))?;
        self.current_time
            .checked_sub(skew)
            .ok_or_else(|| AttestationError::new(AttestationStatus::InvalidClaims))
    }

    pub(crate) fn status_evaluation_bounds(&self) -> AttestationResult<(i64, i64)> {
        let skew = i64::try_from(self.allowed_clock_skew_seconds)
            .map_err(|_| AttestationError::new(AttestationStatus::InvalidClaims))?;
        let earliest = self
            .current_time
            .checked_sub(skew)
            .ok_or_else(|| AttestationError::new(AttestationStatus::InvalidClaims))?;
        let latest = self
            .current_time
            .checked_add(skew)
            .ok_or_else(|| AttestationError::new(AttestationStatus::InvalidClaims))?;
        Ok((earliest, latest))
    }
}

/// Trust purpose attached to a successful key-attestation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAttestationTrustPurpose {
    /// Trust was evaluated for binding an issued credential to attested keys.
    CredentialBinding,
}

/// Status evidence returned by the attestation trust adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAttestationStatusEvidence {
    /// The attestation contained no status reference.
    NotPresent,
    /// The present status mechanism was checked and accepted at this Unix time.
    Valid {
        /// Unix time at which the referenced status was accepted.
        evaluated_at: i64,
    },
}

/// Provenance for a successful signature, signer-trust, and status decision.
/// Identifiers remain opaque so external trust profiles retain their semantics.
#[derive(ZeroizeOnDrop)]
pub struct KeyAttestationTrustEvidenceInput {
    /// Exact compact-JWS signing input authenticated by the verifier.
    /// Retaining these bytes prevents evidence substitution across JWTs.
    pub verified_signing_input: String,
    /// Authenticated key-attestation signer identity.
    pub signer_identity: String,
    /// Applied trust-policy revision.
    pub policy_version: String,
    /// Immutable trust-source snapshot identifier.
    pub source_snapshot: String,
    /// Selected trust-anchor evidence identifier.
    pub anchor: String,
    /// Unix time at which signer trust was evaluated.
    pub evaluated_at: i64,
    /// Last Unix time at which this trust decision may be consumed.
    pub valid_until: i64,
    /// Purpose for which signer trust was accepted.
    #[zeroize(skip)]
    pub purpose: KeyAttestationTrustPurpose,
    /// Evaluated status evidence for the attestation.
    #[zeroize(skip)]
    pub status: KeyAttestationStatusEvidence,
}

/// Validated provenance for a successful signature, signer-trust, and status decision.
#[derive(ZeroizeOnDrop)]
pub struct KeyAttestationTrustEvidence {
    input: KeyAttestationTrustEvidenceInput,
}

impl KeyAttestationTrustEvidence {
    /// Validates and accepts a complete trust-evidence input.
    pub(crate) fn new(input: KeyAttestationTrustEvidenceInput) -> AttestationResult<Self> {
        if input.verified_signing_input.is_empty() {
            return Err(AttestationError::new(
                AttestationStatus::InvalidTrustEvidence,
            ));
        }
        for identifier in [
            &input.signer_identity,
            &input.policy_version,
            &input.source_snapshot,
            &input.anchor,
        ] {
            validate_evidence_identifier(identifier)?;
        }
        if matches!(input.status, KeyAttestationStatusEvidence::Valid { evaluated_at } if evaluated_at <= 0)
        {
            return Err(AttestationError::new(
                AttestationStatus::InvalidTrustEvidence,
            ));
        }
        if input.evaluated_at <= 0 || input.valid_until < input.evaluated_at {
            return Err(AttestationError::new(
                AttestationStatus::InvalidTrustEvidence,
            ));
        }
        Ok(Self { input })
    }

    /// Returns the trusted signer identity.
    #[must_use]
    pub fn signer_identity(&self) -> &str {
        &self.input.signer_identity
    }
    /// Returns the exact JWS signing input covered by this trust decision.
    #[must_use]
    pub fn verified_signing_input(&self) -> &str {
        &self.input.verified_signing_input
    }
    /// Returns the applied policy version.
    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.input.policy_version
    }
    /// Returns the immutable trust-source snapshot identifier.
    #[must_use]
    pub fn source_snapshot(&self) -> &str {
        &self.input.source_snapshot
    }
    /// Returns the selected trust-anchor evidence identifier.
    #[must_use]
    pub fn anchor(&self) -> &str {
        &self.input.anchor
    }

    /// Returns the Unix time at which signer trust was evaluated.
    #[must_use]
    pub const fn evaluated_at(&self) -> i64 {
        self.input.evaluated_at
    }

    /// Returns the last Unix time at which this decision may be consumed.
    #[must_use]
    pub const fn valid_until(&self) -> i64 {
        self.input.valid_until
    }

    /// Returns the purpose for which trust was accepted.
    #[must_use]
    pub const fn purpose(&self) -> KeyAttestationTrustPurpose {
        self.input.purpose
    }

    /// Returns the evaluated status evidence.
    #[must_use]
    pub const fn status(&self) -> KeyAttestationStatusEvidence {
        self.input.status
    }
}

fn validate_evidence_identifier(value: &str) -> AttestationResult<()> {
    if value.is_empty()
        || value.len() > MAX_TRUST_EVIDENCE_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(AttestationError::new(
            AttestationStatus::InvalidTrustEvidence,
        ));
    }
    Ok(())
}

pub(crate) fn zeroize_json_strings(value: &mut Value) {
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
