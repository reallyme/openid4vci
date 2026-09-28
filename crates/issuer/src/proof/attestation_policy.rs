// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed issuer policy for verified key-attestation evidence.

use openid4vci_attestation::{
    AttackPotentialResistance, KeyAttestationAlgorithm, KeyAttestationTemporalPolicy,
    VerifiedKeyAttestation,
};
use openid4vci_types::ProofTypeMetadata;

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

/// Issuer policy for security properties asserted by a trusted key attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAttestationPolicy {
    accepted_algorithms: Vec<KeyAttestationAlgorithm>,
    max_age_seconds: u64,
    allowed_clock_skew_seconds: u64,
    accepted_key_storage: Option<Vec<AttackPotentialResistance>>,
    accepted_user_authentication: Option<Vec<AttackPotentialResistance>>,
    certification_required: bool,
    status_required: bool,
}

/// Deployment-local key-attestation controls not expressed in issuer metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAttestationLocalPolicy {
    max_age_seconds: u64,
    allowed_clock_skew_seconds: u64,
    certification_required: bool,
    status_required: bool,
}

impl KeyAttestationLocalPolicy {
    /// Creates bounded freshness controls for verified key attestations.
    pub fn new(max_age_seconds: u64, allowed_clock_skew_seconds: u64) -> IssuerResult<Self> {
        if max_age_seconds == 0 {
            return Err(IssuerError::new(IssuerStatus::InvalidProofPolicy));
        }
        Ok(Self {
            max_age_seconds,
            allowed_clock_skew_seconds,
            certification_required: false,
            status_required: false,
        })
    }

    /// Requires a validated certification reference.
    #[must_use]
    pub const fn require_certification(mut self) -> Self {
        self.certification_required = true;
        self
    }

    /// Requires a conclusively validated status mechanism.
    #[must_use]
    pub const fn require_status(mut self) -> Self {
        self.status_required = true;
        self
    }
}

impl KeyAttestationPolicy {
    /// Creates policy from proof metadata and local freshness limits.
    pub fn from_proof_metadata(
        metadata: &ProofTypeMetadata,
        max_age_seconds: u64,
        allowed_clock_skew_seconds: u64,
    ) -> IssuerResult<Self> {
        let mut accepted_algorithms =
            Vec::with_capacity(metadata.proof_signing_alg_values_supported.len());
        for name in &metadata.proof_signing_alg_values_supported {
            let algorithm = match name.as_str() {
                "ES256" => KeyAttestationAlgorithm::Es256,
                "ES256K" => KeyAttestationAlgorithm::Es256K,
                "EdDSA" => KeyAttestationAlgorithm::EdDsa,
                _ => return Err(IssuerError::new(IssuerStatus::InvalidProofPolicy)),
            };
            if !accepted_algorithms.contains(&algorithm) {
                accepted_algorithms.push(algorithm);
            }
        }
        if accepted_algorithms.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidProofPolicy));
        }
        let requirements = metadata
            .key_attestations_required
            .as_ref()
            .ok_or(IssuerError::new(IssuerStatus::InvalidProofPolicy))?;
        let policy = Self {
            accepted_algorithms,
            max_age_seconds,
            allowed_clock_skew_seconds,
            accepted_key_storage: parse_resistance_policy(requirements.key_storage.as_deref())?,
            accepted_user_authentication: parse_resistance_policy(
                requirements.user_authentication.as_deref(),
            )?,
            certification_required: false,
            status_required: false,
        };
        policy.temporal_policy(1, false)?;
        Ok(policy)
    }

    /// Combines advertised requirements with deployment-local controls.
    pub fn from_metadata_and_local_policy(
        metadata: &ProofTypeMetadata,
        local: KeyAttestationLocalPolicy,
    ) -> IssuerResult<Self> {
        let mut policy = Self::from_proof_metadata(
            metadata,
            local.max_age_seconds,
            local.allowed_clock_skew_seconds,
        )?;
        policy.certification_required = local.certification_required;
        policy.status_required = local.status_required;
        Ok(policy)
    }

    /// Returns algorithms derived from the selected proof metadata.
    #[must_use]
    pub fn accepted_algorithms(&self) -> &[KeyAttestationAlgorithm] {
        &self.accepted_algorithms
    }

    /// Returns accepted key-storage resistance assertions, when constrained.
    #[must_use]
    pub fn accepted_key_storage(&self) -> Option<&[AttackPotentialResistance]> {
        self.accepted_key_storage.as_deref()
    }

    /// Returns accepted user-authentication resistance assertions, when constrained.
    #[must_use]
    pub fn accepted_user_authentication(&self) -> Option<&[AttackPotentialResistance]> {
        self.accepted_user_authentication.as_deref()
    }

    pub(crate) fn temporal_policy(
        &self,
        current_time: i64,
        expiration_required: bool,
    ) -> IssuerResult<KeyAttestationTemporalPolicy> {
        if self.accepted_algorithms.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidProofPolicy));
        }
        KeyAttestationTemporalPolicy::new(
            current_time,
            self.max_age_seconds,
            self.allowed_clock_skew_seconds,
            expiration_required,
        )
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidProofPolicy))
    }

    /// Evaluates trusted claims without interpreting unknown resistance levels.
    pub fn validate(&self, attestation: &VerifiedKeyAttestation) -> IssuerResult<()> {
        if !accepted_values_match(
            self.accepted_key_storage.as_deref(),
            attestation.key_storage(),
        ) || !accepted_values_match(
            self.accepted_user_authentication.as_deref(),
            attestation.user_authentication(),
        ) || (self.certification_required && attestation.certification().is_none())
            || (self.status_required && attestation.status().is_none())
        {
            return Err(IssuerError::new(
                IssuerStatus::AttestationSecurityPropertiesRejected,
            ));
        }
        Ok(())
    }
}

fn parse_resistance_policy(
    values: Option<&[String]>,
) -> IssuerResult<Option<Vec<AttackPotentialResistance>>> {
    let Some(values) = values else {
        return Ok(None);
    };
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        parsed.push(
            AttackPotentialResistance::parse(value.clone())
                .map_err(|_| IssuerError::new(IssuerStatus::InvalidProofPolicy))?,
        );
    }
    Ok(Some(parsed))
}

fn accepted_values_match(
    accepted: Option<&[AttackPotentialResistance]>,
    asserted: Option<&[AttackPotentialResistance]>,
) -> bool {
    match accepted {
        None => true,
        Some(accepted) => asserted.is_some_and(|asserted| {
            asserted
                .iter()
                .any(|value| accepted.iter().any(|candidate| candidate == value))
        }),
    }
}
