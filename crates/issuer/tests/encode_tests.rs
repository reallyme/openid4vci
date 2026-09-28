// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encoder boundary tests for credential response envelopes.

use openid4vci_issuer::{
    encode_immediate_response, encode_immediate_response_with_verified_proofs,
    expected_credential_count, ConfirmationJwk, IssuedCredential, IssuerResult, IssuerStatus,
    PassThroughCredentialEncoder, ProofAlgorithm, ProofKind, VerifiedProof, VerifiedProofSet,
};
use openid4vci_types::{CredentialFormat, CredentialPayload, CredentialRequest, Proofs};
use serde_json::{json, Value};

fn request() -> CredentialRequest {
    CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: None,
        credential_response_encryption: None,
    }
}

fn request_with_jwt_proofs(count: usize) -> CredentialRequest {
    CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: (0..count)
                .map(|index| ["proof-", &index.to_string()].concat())
                .collect(),
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    }
}

#[test]
fn pass_through_encoder_returns_prebuilt_sd_jwt_vc() -> IssuerResult<()> {
    let encoder = PassThroughCredentialEncoder::new(CredentialFormat::SdJwtVc);
    let issued = [IssuedCredential::new(
        CredentialFormat::SdJwtVc,
        Value::String("sd-jwt-vc".to_owned()),
    )?];
    let response = encode_immediate_response(&request(), &encoder, &issued, None)?;
    let credentials = response
        .credentials
        .as_ref()
        .ok_or(openid4vci_issuer::IssuerError::new(
            openid4vci_issuer::IssuerStatus::EncodingFailed,
        ))?;
    assert_eq!(credentials.len(), 1);
    assert_eq!(
        credentials.first().map(|entry| &entry.credential),
        Some(&CredentialPayload::Compact("sd-jwt-vc".to_owned()))
    );
    Ok(())
}

#[test]
fn issued_credential_debug_redacts_payload() -> IssuerResult<()> {
    let issued = IssuedCredential::new(
        CredentialFormat::SdJwtVc,
        json!({"credential": "sensitive-issued-credential"}),
    )?;

    let debug = format!("{issued:?}");
    assert!(!debug.contains("sensitive-issued-credential"));
    assert!(debug.contains("<redacted>"));
    Ok(())
}

#[test]
fn pass_through_encoder_rejects_wrong_format() -> IssuerResult<()> {
    let encoder = PassThroughCredentialEncoder::new(CredentialFormat::MsoMdoc);
    let issued = [IssuedCredential::new(
        CredentialFormat::SdJwtVc,
        Value::String("sd-jwt-vc".to_owned()),
    )?];
    let result = encode_immediate_response(&request(), &encoder, &issued, None);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::UnsupportedCredential)
    );
    Ok(())
}

#[test]
fn multiple_proofs_require_matching_number_of_issued_credentials() -> IssuerResult<()> {
    let encoder = PassThroughCredentialEncoder::new(CredentialFormat::SdJwtVc);
    let request = request_with_jwt_proofs(2);
    let issued = [IssuedCredential::new(
        CredentialFormat::SdJwtVc,
        Value::String("sd-jwt-vc".to_owned()),
    )?];

    let result = encode_immediate_response(&request, &encoder, &issued, None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn expected_credential_count_follows_final_proofs_array() {
    assert_eq!(expected_credential_count(&request()), 1);
    assert_eq!(expected_credential_count(&request_with_jwt_proofs(2)), 2);
}

#[test]
fn issuance_emits_one_credential_per_verified_binding_key() -> IssuerResult<()> {
    let encoder = PassThroughCredentialEncoder::new(CredentialFormat::SdJwtVc);
    let request = request_with_jwt_proofs(2);
    let verified = VerifiedProofSet::new(
        vec![
            binding_proof(json!({"kty": "EC", "x": "first"}))?,
            binding_proof(json!({"kty": "EC", "x": "second"}))?,
        ],
        Vec::new(),
    )?;
    let issued = [
        IssuedCredential::new(
            CredentialFormat::SdJwtVc,
            Value::String("sd-jwt-vc-1".to_owned()),
        )?,
        IssuedCredential::new(
            CredentialFormat::SdJwtVc,
            Value::String("sd-jwt-vc-2".to_owned()),
        )?,
    ];

    let response = encode_immediate_response_with_verified_proofs(
        &request,
        Some(&verified),
        &encoder,
        &issued,
        None,
    )?;

    assert_eq!(response.credentials.as_ref().map(Vec::len), Some(2));
    Ok(())
}

#[test]
fn verified_proof_set_exposes_binding_keys_in_proof_order() -> IssuerResult<()> {
    let first = json!({"kty": "EC", "x": "first"});
    let second = json!({"kty": "EC", "x": "second"});
    let verified = VerifiedProofSet::new(
        vec![
            binding_proof(first.clone())?,
            binding_proof(second.clone())?,
        ],
        Vec::new(),
    )?;

    assert_eq!(verified.ordered_public_jwks()?, vec![&first, &second]);
    Ok(())
}

#[test]
fn verified_proof_set_rejects_inconsistent_binding_records() -> IssuerResult<()> {
    let missing_key = VerifiedProof::new(ProofKind::Jwt, None, None, None, None, None, None);
    assert_eq!(
        missing_key.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    let verified = VerifiedProofSet::new(
        vec![binding_proof(json!({"kty": "EC", "x": "first"}))?],
        Vec::new(),
    )?;
    assert_eq!(verified.binding_key_count(), 1);
    Ok(())
}

fn binding_proof(public_jwk: Value) -> IssuerResult<VerifiedProof> {
    VerifiedProof::new(
        ProofKind::Jwt,
        None,
        None,
        None,
        None,
        Some(public_jwk),
        Some(ConfirmationJwk {
            algorithm: ProofAlgorithm::Es256,
            public_key: vec![0x04; 65],
            key_id: None,
        }),
    )
}
