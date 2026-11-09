// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pass-through encoding and proof-count boundary tests.

use openid4vci_issuer::{
    encode_immediate_response, encode_immediate_response_with_verified_proofs,
    expected_credential_count, IssuedCredential, IssuerResult, IssuerStatus,
    PassThroughCredentialEncoder, ProofKind, VerifiedProof, VerifiedProofSet,
};
use openid4vci_types::{CredentialFormat, CredentialPayload};
use serde_json::{json, Value};

use crate::support::{binding_proof, request, request_with_jwt_proofs};

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
fn public_issued_credential_constructor_rejects_reallyme_zk_v1() {
    assert_eq!(
        IssuedCredential::new(
            CredentialFormat::ReallyMeZkV1,
            Value::String("compact-zk".to_owned()),
        )
        .err()
        .map(|error| error.status()),
        Some(IssuerStatus::UnsupportedCredential)
    );
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
