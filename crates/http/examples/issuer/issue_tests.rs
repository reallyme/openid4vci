// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batch credential binding tests for the synthetic conformance issuer.

use openid4vci_issuer::{
    ConfirmationJwk, CredentialIssuer, IssuanceAuthorization, IssuanceOutcome, IssuerError,
    IssuerResult, IssuerStatus, ProofAlgorithm, ProofKind, VerifiedProof, VerifiedProofSet,
};
use openid4vci_types::{CredentialPayload, CredentialRequest, Proofs};
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::verify;
use reallyme_crypto::p256::{
    generate_p256_keypair_from_secret_key, p256_ecdsa_jose_signature_to_der,
};
use reallyme_sd_jwt::{digest_disclosure, SdJwtHashAlgorithm};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

use super::issue::ExampleCredentialIssuer;
use super::run::{CONFORMANCE_ISSUER_PRIVATE_KEY_D, CONFORMANCE_ISSUER_X5C_LEAF};

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
        reallyme_zk_v1_issuance: None,
    };
    let verified = VerifiedProofSet::new(
        vec![
            verified_proof(first_jwk.clone())?,
            verified_proof(second_jwk.clone())?,
        ],
        Vec::new(),
    )?;

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

fn verified_proof(public_jwk: Value) -> IssuerResult<VerifiedProof> {
    VerifiedProof::new(
        ProofKind::Jwt,
        Some("nonce".to_owned()),
        Some("https://issuer.example/".to_owned()),
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

fn credential_binding_key(credential: &CredentialPayload) -> IssuerResult<Value> {
    let CredentialPayload::Compact(compact) = credential else {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    };
    let mut parts = compact.split('~');
    let signed = parts
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let mut segments = signed.split('.');
    let protected = segments
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let payload = segments
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let signature = segments
        .next()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    if segments.next().is_some() {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let header = base64url_to_bytes(protected)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let header = serde_json::from_slice::<Value>(&header)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256")
        || header.get("typ").and_then(Value::as_str) != Some("dc+sd-jwt")
        || header
            .get("x5c")
            .and_then(Value::as_array)
            .and_then(|certificates| certificates.first())
            .and_then(Value::as_str)
            != Some(CONFORMANCE_ISSUER_X5C_LEAF)
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let signing_input = format!("{protected}.{payload}");
    let signature = base64url_to_bytes(signature)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let signature = p256_ecdsa_jose_signature_to_der(&signature)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let private_key = Zeroizing::new(
        base64url_to_bytes(CONFORMANCE_ISSUER_PRIVATE_KEY_D)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
    );
    let secret = Zeroizing::new(
        <[u8; 32]>::try_from(private_key.as_slice())
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
    );
    let (public_key, _derived_secret) = generate_p256_keypair_from_secret_key(&secret)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    verify(
        Algorithm::P256,
        &public_key,
        signing_input.as_bytes(),
        &signature,
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let payload =
        base64url_to_bytes(payload).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let claims = serde_json::from_slice::<Value>(&payload)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let committed_digests = claims
        .get("_sd")
        .and_then(Value::as_array)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    if claims.get("_sd_alg").and_then(Value::as_str) != Some("sha-256")
        || committed_digests.len() != 3
        || !committed_digests.windows(2).all(|pair| {
            pair[0]
                .as_str()
                .zip(pair[1].as_str())
                .is_some_and(|(left, right)| left < right)
        })
        || ["given_name", "family_name", "birthdate"]
            .iter()
            .any(|name| claims.get(*name).is_some())
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let disclosures = parts.filter(|part| !part.is_empty()).collect::<Vec<_>>();
    if disclosures.len() != committed_digests.len() {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let mut names = BTreeSet::new();
    for disclosure in disclosures {
        let digest = digest_disclosure(disclosure, SdJwtHashAlgorithm::Sha256)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        if !committed_digests
            .iter()
            .any(|committed| committed.as_str() == Some(digest.as_str()))
        {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        let encoded = base64url_to_bytes(disclosure)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        let decoded = serde_json::from_slice::<Value>(&encoded)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        let fields = decoded
            .as_array()
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
        let (Some(name), Some(value)) = (
            fields.get(1).and_then(Value::as_str),
            fields.get(2).and_then(Value::as_str),
        ) else {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        };
        if fields.len() != 3
            || fields.first().and_then(Value::as_str).is_none()
            || !names.insert(name.to_owned())
            || !matches!(
                (name, value),
                ("given_name", "Erika")
                    | ("family_name", "Mustermann")
                    | ("birthdate", "1970-01-01")
            )
        {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
    }
    if names.len() != 3 {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .cloned()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))
}
