// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential-endpoint checks that depend on verified attestation cardinality.

use std::collections::BTreeMap;

use openid4vci_issuer::{
    handle_credential_request, AuthenticatedNonceManager, ConfirmationJwk,
    CredentialEndpointConfig, CredentialIssuer, IssuanceAuthorization, IssuanceOutcome,
    IssuerError, IssuerResult, IssuerStatus, ProofAlgorithm, ProofKind, ProofVerificationContext,
    ProofVerifier, VerifiedProof, VerifiedProofSet,
};
use openid4vci_types::{CredentialRequest, CredentialSelector, Proofs};
use serde_json::json;

struct TwoKeyProofVerifier;

#[allow(clippy::panic)]
fn authorization() -> IssuanceAuthorization {
    IssuanceAuthorization::new("pid".to_owned(), "subject-1".to_owned(), [7_u8; 32])
        .unwrap_or_else(|error| panic!("test authorization must be valid: {error}"))
}

impl ProofVerifier for TwoKeyProofVerifier {
    fn verify(
        &self,
        _proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        VerifiedProofSet::new(vec![test_proof(1)?, test_proof(2)?], Vec::new())
    }
}

fn test_proof(index: u8) -> IssuerResult<VerifiedProof> {
    VerifiedProof::new(
        ProofKind::Jwt,
        None,
        None,
        None,
        None,
        Some(json!({"kty": "EC", "x": index})),
        Some(ConfirmationJwk {
            algorithm: ProofAlgorithm::Es256,
            public_key: vec![index; 65],
            key_id: None,
        }),
    )
}

struct RejectIfCalledIssuer;

impl CredentialIssuer for RejectIfCalledIssuer {
    fn issue(
        &self,
        _authorization: &IssuanceAuthorization,
        _request: &CredentialRequest,
        _selector: &CredentialSelector,
        _verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome> {
        Err(IssuerError::new(IssuerStatus::EncodingFailed))
    }
}

#[test]
fn endpoint_enforces_batch_ceiling_after_verified_key_expansion() -> IssuerResult<()> {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["a.b.c".to_owned(), "d.e.f".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let config = CredentialEndpointConfig {
        credential_issuer: "https://issuer.example".to_owned(),
        proof_required: true,
        accepted_proof_algorithms: vec![
            openid4vci_issuer::ProofAlgorithm::EdDsa,
            openid4vci_issuer::ProofAlgorithm::Es256,
            openid4vci_issuer::ProofAlgorithm::Es256k,
        ],
        accepted_attestation_proof_algorithms: vec![
            openid4vci_issuer::ProofAlgorithm::EdDsa,
            openid4vci_issuer::ProofAlgorithm::Es256,
            openid4vci_issuer::ProofAlgorithm::Es256k,
        ],
        key_attestation_required: false,
        key_attestation_policy: None,
        key_attestation_local_policy: None,
        proof_type_policies: BTreeMap::new(),
        nonce_required: false,
        request_encryption_required: false,
        max_batch_size: None,
        response_encryption_required: false,
        response_encryption_metadata: None,
    };

    let result = handle_credential_request(
        &authorization(),
        &request,
        &config,
        &TwoKeyProofVerifier,
        &RejectIfCalledIssuer,
        &AuthenticatedNonceManager::with_generated_key()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?,
        1_700_000_000,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}
