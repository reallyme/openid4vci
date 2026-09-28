// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance vector runner.
//!
//! Each vector names a `target` parser and an `input_json` payload with an
//! `expected` accept/reject outcome. The runner dispatches the payload to the
//! concrete parser for that target and checks the real behavior against the
//! expectation, so the negative vectors actually exercise the implementation.

use openid4vci_attestation::{
    parse_key_attestation, KeyAttestationAlgorithm, KeyAttestationJwt,
    KeyAttestationTemporalPolicy, KeyAttestationValidationContext,
};
use openid4vci_issuer::CompactProofJwtParser;
use openid4vci_types::{
    CredentialOffer, CredentialRequest, CredentialResponse, IssuerMetadata, NotificationRequest,
};
use reallyme_openid4vci_wallet::{
    verify_signed_issuer_metadata, ParsedSignedIssuerMetadata, SignedIssuerMetadataJwt,
    SignedIssuerMetadataTrustVerifier, SignedIssuerMetadataValidationContext,
    SignedMetadataAlgorithm, SignedMetadataSignerTrustPurpose, SignedMetadataTrustEvidenceInput,
    SignedMetadataTrustPurpose, WalletError, WalletResult, WalletStatus,
};

use crate::error::{ConformanceError, ConformanceResult};
use crate::vector::{ConformanceVector, ExpectedResult};

/// Outcome of running one conformance vector against the implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorOutcome {
    /// The parser's accept/reject behavior matched the expectation.
    Passed,
    /// The parser accepted a payload the vector expected it to reject.
    UnexpectedAccept,
    /// The parser rejected a payload the vector expected it to accept.
    UnexpectedReject,
}

impl VectorOutcome {
    /// Returns true when the vector behaved as expected.
    #[must_use]
    pub const fn passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Runs one vector, dispatching its `input_json` to the parser named by
/// `target`. Returns [`ConformanceError::UnknownTarget`] for an unknown target
/// so a stale or mistyped vector fails loudly rather than being silently skipped.
pub fn run_vector(vector: &ConformanceVector) -> ConformanceResult<VectorOutcome> {
    let accepted = dispatch(&vector.target, &vector.input_json)?;
    let expected_accept = matches!(vector.expected, ExpectedResult::Accept);
    Ok(match (accepted, expected_accept) {
        (true, true) | (false, false) => VectorOutcome::Passed,
        (true, false) => VectorOutcome::UnexpectedAccept,
        (false, true) => VectorOutcome::UnexpectedReject,
    })
}

/// Runs every vector, returning each vector's id paired with its outcome.
pub fn run_vectors(
    vectors: &[ConformanceVector],
) -> ConformanceResult<Vec<(String, VectorOutcome)>> {
    let mut results = Vec::with_capacity(vectors.len());
    for vector in vectors {
        results.push((vector.id.clone(), run_vector(vector)?));
    }
    Ok(results)
}

/// Parses the vector payload with the parser for `target`, returning whether it was
/// accepted (`Ok(true)`) or rejected (`Ok(false)`); errors on unknown targets.
fn dispatch(target: &str, input_json: &str) -> ConformanceResult<bool> {
    let accepted = match target {
        // A Proofs vector is expressed as a full Credential Request payload, so
        // it is validated through the Credential Request parser.
        "types::CredentialRequest" | "types::Proofs" => {
            CredentialRequest::parse_json(input_json).is_ok()
        }
        "types::CredentialResponse" => CredentialResponse::parse_json(input_json).is_ok(),
        "types::NotificationRequest" => NotificationRequest::parse_json(input_json).is_ok(),
        "types::IssuerMetadata" => IssuerMetadata::parse_json(input_json).is_ok(),
        "types::CredentialOffer" => CredentialOffer::parse_json(input_json).is_ok(),
        "issuer::CompactProofJwtParser" => CompactProofJwtParser::default()
            .parse_unverified(input_json)
            .is_ok(),
        "attestation::KeyAttestationPolicy" => run_key_attestation_vector(input_json)?,
        "wallet::SignedIssuerMetadataPolicy" => run_signed_metadata_vector(input_json)?,
        _ => return Err(ConformanceError::UnknownTarget),
    };
    Ok(accepted)
}

fn run_key_attestation_vector(input: &str) -> ConformanceResult<bool> {
    let jwt = match KeyAttestationJwt::new(input.to_owned()) {
        Ok(jwt) => jwt,
        Err(_) => return Ok(false),
    };
    let temporal_policy = KeyAttestationTemporalPolicy::new(1_700_000_000, 300, 60, false)
        .map_err(|_| ConformanceError::InvalidHarnessConfiguration)?;
    let context = KeyAttestationValidationContext {
        nonce_required: false,
        expected_nonce: None,
        temporal_policy,
        accepted_algorithms: vec![KeyAttestationAlgorithm::Es256],
    };
    Ok(parse_key_attestation(&jwt, &context).is_ok())
}

struct VectorSignedMetadataTrustVerifier;

impl SignedIssuerMetadataTrustVerifier for VectorSignedMetadataTrustVerifier {
    fn verify_signed_issuer_metadata(
        &self,
        _jwt: &SignedIssuerMetadataJwt,
        parsed: &ParsedSignedIssuerMetadata,
    ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
        if parsed.signature() == [0_u8] {
            return Err(WalletError::new(
                WalletStatus::SignedMetadataSignatureRejected,
            ));
        }
        Ok(SignedMetadataTrustEvidenceInput {
            verified_signing_input: parsed.signing_input().to_owned(),
            signer_identity: "https://signer.example".to_owned(),
            asserted_issuer: Some("https://signer.example".to_owned()),
            policy_version: "conformance-policy-v1".to_owned(),
            source_snapshot: "conformance-snapshot-1".to_owned(),
            anchor: "conformance-anchor-1".to_owned(),
            evaluated_at: 1_700_000_000,
            valid_until: 1_700_000_600,
            purpose: SignedMetadataTrustPurpose::CredentialIssuerMetadata,
            signer_trust_purpose: SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
        })
    }
}

fn run_signed_metadata_vector(input: &str) -> ConformanceResult<bool> {
    let jwt = match SignedIssuerMetadataJwt::new(input.to_owned()) {
        Ok(jwt) => jwt,
        Err(_) => return Ok(false),
    };
    let context = SignedIssuerMetadataValidationContext {
        expected_credential_issuer: "https://issuer.example".to_owned(),
        current_time: 1_700_000_000,
        max_age_seconds: 300,
        allowed_clock_skew_seconds: 60,
        accepted_algorithms: vec![SignedMetadataAlgorithm::Es256],
        required_signer_trust_purpose:
            SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
    };
    Ok(verify_signed_issuer_metadata(&jwt, &context, &VectorSignedMetadataTrustVerifier).is_ok())
}
