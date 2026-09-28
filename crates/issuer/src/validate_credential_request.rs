// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential request validation and proof-policy selection.

use openid4vci_types::{CredentialRequest, CredentialSelector, Proofs};

use crate::authorization::IssuanceAuthorization;
use crate::credential_policy::CredentialEndpointConfig;
use crate::encode::expected_credential_count;
use crate::encrypt::validate_response_encryption_parameters;
use crate::error::{IssuerError, IssuerResult, IssuerStatus};
use crate::proof::{ProofKind, ProofVerificationContext, ProofVerifier, VerifiedProofSet};

/// Refines a generic unknown-credential error into its selector-specific code.
pub(crate) fn specialize_unknown_credential(
    error: IssuerError,
    selector: &CredentialSelector,
) -> IssuerError {
    if error.status() == IssuerStatus::UnsupportedCredential
        && matches!(selector, CredentialSelector::CredentialIdentifier(_))
    {
        return IssuerError::new(IssuerStatus::UnknownCredentialIdentifier);
    }
    error
}

/// Bounds proof entries before signature work using the advertised batch size.
fn enforce_batch_size(
    request: &CredentialRequest,
    config: &CredentialEndpointConfig,
) -> IssuerResult<()> {
    let proof_count = u64::try_from(expected_credential_count(request))
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
    if proof_count > config.max_batch_size.unwrap_or(1) {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    Ok(())
}

/// Enforces the batch ceiling after direct attestation reveals all bound keys.
fn enforce_verified_binding_count(
    verified: &VerifiedProofSet,
    config: &CredentialEndpointConfig,
) -> IssuerResult<()> {
    if u64::from(verified.binding_key_count()) > config.max_batch_size.unwrap_or(1) {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    Ok(())
}

fn submitted_proof_kind(proofs: &Proofs) -> ProofKind {
    if !proofs.jwt.is_empty() {
        ProofKind::Jwt
    } else if !proofs.attestation.is_empty() {
        ProofKind::Attestation
    } else {
        // Data Integrity algorithm identifiers are not JOSE values. A DI-VP
        // request must not inherit another proof family's advertised policy.
        ProofKind::DiVp
    }
}

fn requires_key_attestation(
    request: &CredentialRequest,
    config: &CredentialEndpointConfig,
) -> bool {
    request.proofs.as_ref().is_some_and(|proofs| {
        let kind = submitted_proof_kind(proofs);
        config
            .proof_type_policies
            .get(&kind)
            .is_some_and(|policy| policy.key_attestation_policy.is_some())
            || (config.proof_type_policies.is_empty()
                && (config.key_attestation_required || config.key_attestation_policy.is_some()))
    })
}

pub(crate) fn validate_and_verify_credential_request(
    authorization: &IssuanceAuthorization,
    request: &CredentialRequest,
    config: &CredentialEndpointConfig,
    proof_verifier: &dyn ProofVerifier,
    now_unix: u64,
) -> IssuerResult<(CredentialSelector, Option<VerifiedProofSet>)> {
    request
        .validate()
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
    if config.response_encryption_required && request.credential_response_encryption.is_none() {
        return Err(IssuerError::new(IssuerStatus::EncryptionRequired));
    }
    if let Some(encryption) = &request.credential_response_encryption {
        validate_response_encryption_parameters(
            encryption,
            config.response_encryption_metadata.as_ref(),
        )?;
    }
    let selector = request
        .selector()
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
    let verified = match &request.proofs {
        Some(proofs) => {
            enforce_batch_size(request, config)?;
            let current_time = i64::try_from(now_unix)
                .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
            let proof_kind = submitted_proof_kind(proofs);
            let proof_policy = config.proof_policy(proof_kind)?;
            let context = ProofVerificationContext {
                credential_issuer: config.credential_issuer.clone(),
                selector: selector.clone(),
                client_id: authorization.client_id().map(str::to_owned),
                accepted_proof_algorithms: proof_policy.accepted_algorithms,
                nonce_required: config.nonce_required,
                current_time,
                key_attestation_policy: proof_policy.key_attestation_policy.clone(),
            };
            let verified = proof_verifier.verify(proofs, &context)?;
            if verified
                .proofs()
                .iter()
                .any(|proof| proof.kind() != proof_kind)
                || (proof_kind == ProofKind::Jwt && verified.proofs().len() != proofs.jwt.len())
            {
                return Err(IssuerError::new(IssuerStatus::InvalidProof));
            }
            enforce_verified_binding_count(&verified, config)?;
            Some(verified)
        }
        None if config.proof_required => return Err(IssuerError::new(IssuerStatus::ProofRequired)),
        None => None,
    };
    if requires_key_attestation(request, config)
        && !verified
            .as_ref()
            .is_some_and(VerifiedProofSet::includes_key_attestation)
    {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    Ok((selector, verified))
}
