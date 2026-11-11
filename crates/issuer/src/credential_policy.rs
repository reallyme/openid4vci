// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Endpoint policy derived from public issuer metadata.

use std::collections::BTreeMap;

use openid4vci_types::{CredentialResponseEncryptionMetadata, IssuerMetadata, ProofTypeMetadata};

use crate::error::{IssuerError, IssuerResult, IssuerStatus};
use crate::proof::{
    CredentialRequestProfile, KeyAttestationLocalPolicy, KeyAttestationPolicy, ProofAlgorithm,
    ProofKind,
};

/// Runtime proof policy selected by the proof type actually submitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofTypeEndpointPolicy {
    /// Algorithms advertised for this exact proof type.
    pub accepted_algorithms: Vec<ProofAlgorithm>,
    /// Key-attestation constraints derived from this exact proof type.
    pub key_attestation_policy: Option<KeyAttestationPolicy>,
}

/// Runtime policy for one advertised credential configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEndpointConfig {
    /// Credential Issuer Identifier used as proof audience/domain.
    pub credential_issuer: String,
    /// Whether the selected credential requires a key proof.
    pub proof_required: bool,
    /// JWT proof algorithms advertised for this credential configuration.
    pub accepted_proof_algorithms: Vec<ProofAlgorithm>,
    /// Attestation proof algorithms advertised for this credential configuration.
    pub accepted_attestation_proof_algorithms: Vec<ProofAlgorithm>,
    /// Whether the selected credential requires a verified key attestation.
    pub key_attestation_required: bool,
    /// Security properties required from each trusted key attestation.
    pub key_attestation_policy: Option<KeyAttestationPolicy>,
    /// Deployment-local freshness and trust requirements used during derivation.
    pub key_attestation_local_policy: Option<KeyAttestationLocalPolicy>,
    /// Exact per-proof policies derived from the selected credential configuration.
    pub proof_type_policies: BTreeMap<ProofKind, ProofTypeEndpointPolicy>,
    /// Maximum number of key proofs accepted in one Credential Request.
    pub max_batch_size: Option<u64>,
    /// Whether response encryption is mandatory for the selected credential.
    pub response_encryption_required: bool,
    /// Advertised response encryption algorithms for the selected credential.
    pub response_encryption_metadata: Option<CredentialResponseEncryptionMetadata>,
    /// Whether the issuer publishes a Nonce Endpoint for this credential.
    pub nonce_required: bool,
    /// Whether encrypted Credential Request transport is mandatory.
    pub request_encryption_required: bool,
    /// Additional Credential Request semantics selected by deployment policy.
    pub credential_request_profile: CredentialRequestProfile,
}

impl CredentialEndpointConfig {
    /// Derives runtime policy from one advertised credential configuration.
    /// Local attestation freshness/trust controls remain injected because they
    /// cannot be expressed completely in Credential Issuer Metadata.
    pub fn from_metadata(
        metadata: &IssuerMetadata,
        configuration_id: &str,
        key_attestation_local_policy: Option<KeyAttestationLocalPolicy>,
    ) -> IssuerResult<Self> {
        let configuration = metadata
            .credential_configurations_supported
            .get(configuration_id)
            .ok_or(IssuerError::new(IssuerStatus::InvalidProofPolicy))?;
        let mut accepted_proof_algorithms = Vec::new();
        let mut accepted_attestation_proof_algorithms = Vec::new();
        let mut key_attestation_required = false;
        let mut proof_type_policies = BTreeMap::new();
        if let Some(proof_types) = &configuration.proof_types_supported {
            accepted_proof_algorithms = proof_algorithms_for_type(proof_types, "jwt")?;
            accepted_attestation_proof_algorithms =
                proof_algorithms_for_type(proof_types, "attestation")?;
            for (name, proof_metadata) in proof_types {
                let kind = match name.as_str() {
                    "jwt" => ProofKind::Jwt,
                    "attestation" => ProofKind::Attestation,
                    "di_vp" => ProofKind::DiVp,
                    _ => continue,
                };
                let key_attestation_policy = match (
                    proof_metadata.key_attestations_required.as_ref(),
                    key_attestation_local_policy,
                ) {
                    (Some(_), Some(local)) => {
                        Some(KeyAttestationPolicy::from_metadata_and_local_policy(
                            proof_metadata,
                            local,
                        )?)
                    }
                    (Some(_), None) => {
                        return Err(IssuerError::new(IssuerStatus::InvalidProofPolicy));
                    }
                    (None, _) => None,
                };
                proof_type_policies.insert(
                    kind,
                    ProofTypeEndpointPolicy {
                        accepted_algorithms: proof_algorithms(proof_metadata)?,
                        key_attestation_policy,
                    },
                );
            }
            key_attestation_required = proof_type_policies
                .values()
                .all(|policy| policy.key_attestation_policy.is_some());
        }
        let key_attestation_policy = if proof_type_policies.len() == 1 {
            proof_type_policies
                .values()
                .next()
                .and_then(|policy| policy.key_attestation_policy.clone())
        } else {
            None
        };
        Ok(Self {
            credential_issuer: metadata.credential_issuer.clone(),
            proof_required: configuration.supports_proofs(),
            accepted_proof_algorithms,
            accepted_attestation_proof_algorithms,
            key_attestation_required,
            key_attestation_policy,
            key_attestation_local_policy,
            proof_type_policies,
            max_batch_size: metadata
                .batch_credential_issuance
                .as_ref()
                .map(|batch| batch.batch_size),
            response_encryption_required: metadata
                .credential_response_encryption
                .as_ref()
                .is_some_and(|encryption| encryption.encryption_required),
            response_encryption_metadata: metadata.credential_response_encryption.clone(),
            nonce_required: metadata.nonce_endpoint.is_some(),
            request_encryption_required: metadata
                .credential_request_encryption
                .as_ref()
                .is_some_and(|encryption| encryption.encryption_required),
            credential_request_profile: CredentialRequestProfile::OpenId4Vci,
        })
    }

    /// Enables ETSI TS 119 472-3 Credential Request semantics.
    ///
    /// The profile requires a Nonce Endpoint and at least one of the JWT or
    /// direct-attestation proof mechanisms with an enforceable Wallet Unit
    /// Attestation trust policy. This method fails closed instead of silently
    /// weakening a partially configured issuer.
    pub fn with_etsi_ts119472_part3_profile(mut self) -> IssuerResult<Self> {
        if !self.nonce_required {
            return Err(IssuerError::new(IssuerStatus::InvalidProofPolicy));
        }
        let jwt_policy = self.proof_type_policies.get(&ProofKind::Jwt);
        let attestation_policy = self.proof_type_policies.get(&ProofKind::Attestation);
        if (jwt_policy.is_some_and(|policy| policy.key_attestation_policy.is_none()))
            || (attestation_policy.is_some_and(|policy| policy.key_attestation_policy.is_none()))
            || (jwt_policy.is_none() && attestation_policy.is_none())
            || self.proof_type_policies.contains_key(&ProofKind::DiVp)
        {
            return Err(IssuerError::new(IssuerStatus::InvalidProofPolicy));
        }
        self.credential_request_profile = CredentialRequestProfile::EtsiTs119472Part3;
        Ok(self)
    }

    pub(crate) fn proof_policy(
        &self,
        proof_kind: ProofKind,
    ) -> IssuerResult<ProofTypeEndpointPolicy> {
        if let Some(policy) = self.proof_type_policies.get(&proof_kind) {
            return Ok(policy.clone());
        }
        let accepted_algorithms = match proof_kind {
            ProofKind::Jwt => self.accepted_proof_algorithms.clone(),
            ProofKind::Attestation => self.accepted_attestation_proof_algorithms.clone(),
            ProofKind::DiVp => Vec::new(),
        };
        if accepted_algorithms.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidProofPolicy));
        }
        Ok(ProofTypeEndpointPolicy {
            accepted_algorithms,
            key_attestation_policy: self.key_attestation_policy.clone(),
        })
    }
}

fn proof_algorithms(metadata: &ProofTypeMetadata) -> IssuerResult<Vec<ProofAlgorithm>> {
    metadata
        .proof_signing_alg_values_supported
        .iter()
        .map(|algorithm| ProofAlgorithm::from_jose_name(algorithm))
        .collect()
}

fn proof_algorithms_for_type(
    proof_types: &BTreeMap<String, ProofTypeMetadata>,
    proof_type: &str,
) -> IssuerResult<Vec<ProofAlgorithm>> {
    let Some(metadata) = proof_types.get(proof_type) else {
        return Ok(Vec::new());
    };
    proof_algorithms(metadata)
}
