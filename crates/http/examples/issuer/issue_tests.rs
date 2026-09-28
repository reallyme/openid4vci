// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batch credential binding tests for the deployable issuer example.

use openid4vci_issuer::{
    CredentialIssuer, IssuanceAuthorization, IssuanceOutcome, IssuerError, IssuerResult,
    IssuerStatus, ProofKind, VerifiedProof, VerifiedProofSet,
};
use openid4vci_types::{CredentialPayload, CredentialRequest, Proofs};
use reallyme_codec::base64url::base64url_to_bytes;
use serde_json::{json, Value};

use super::issue::ExampleCredentialIssuer;

#[test]
fn batch_credentials_bind_to_the_corresponding_distinct_proof_keys() -> IssuerResult<()> {
    let first_jwk = json!({"kty": "EC", "crv": "P-256", "x": "first-x", "y": "first-y"});
    let second_jwk = json!({"kty": "EC", "crv": "P-256", "x": "second-x", "y": "second-y"});
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["first-proof".to_owned(), "second-proof".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let verified = VerifiedProofSet {
        binding_key_count: 2,
        includes_key_attestation: false,
        key_attestations: Vec::new(),
        proofs: vec![
            verified_proof(first_jwk.clone()),
            verified_proof(second_jwk.clone()),
        ],
    };

    let authorization =
        IssuanceAuthorization::new("pid".to_owned(), "subject-1".to_owned(), [7_u8; 32])?;
    let outcome = ExampleCredentialIssuer::new("https://issuer.example/".to_owned()).issue(
        &authorization,
        &request,
        &openid4vci_types::CredentialSelector::ConfigurationId("pid".to_owned()),
        Some(&verified),
    )?;
    let response = match outcome {
        IssuanceOutcome::Immediate(response) => response,
        IssuanceOutcome::Deferred(_) => {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
    };
    let credentials = response
        .credentials
        .as_ref()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    assert_eq!(credentials.len(), 2);
    assert_eq!(
        credential_binding_key(&credentials[0].credential)?,
        first_jwk
    );
    assert_eq!(
        credential_binding_key(&credentials[1].credential)?,
        second_jwk
    );
    Ok(())
}

fn verified_proof(public_jwk: Value) -> VerifiedProof {
    VerifiedProof {
        kind: ProofKind::Jwt,
        nonce: Some("nonce".to_owned()),
        audience: Some("https://issuer.example/".to_owned()),
        key_binding_id: None,
        key_id: None,
        public_jwk: Some(public_jwk),
        confirmation_key: None,
    }
}

fn credential_binding_key(credential: &CredentialPayload) -> IssuerResult<Value> {
    let CredentialPayload::Compact(compact) = credential else {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    };
    let signed = compact
        .strip_suffix('~')
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let mut segments = signed.split('.');
    let _protected = segments
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let payload = segments
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let _signature = segments
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    if segments.next().is_some() {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let payload =
        base64url_to_bytes(payload).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let claims = serde_json::from_slice::<Value>(&payload)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .cloned()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))
}
