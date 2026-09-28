// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed Credential Issuer Metadata verification tests.

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_openid4vci_wallet::{
    verify_signed_issuer_metadata, ParsedSignedIssuerMetadata, SignedIssuerMetadataJwt,
    SignedIssuerMetadataTrustVerifier, SignedIssuerMetadataValidationContext,
    SignedMetadataAlgorithm, SignedMetadataSignerTrustPurpose, SignedMetadataTrustEvidenceInput,
    SignedMetadataTrustPurpose, WalletError, WalletResult, WalletStatus,
};
use serde_json::{json, Value};
use thiserror::Error;

const ISSUER: &str = "https://issuer.example";
const NOW: i64 = 1_700_000_000;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
enum SignedMetadataTestError {
    #[error("json")]
    Json,
    #[error("metadata")]
    Metadata,
}

struct AcceptingTrustVerifier;

impl SignedIssuerMetadataTrustVerifier for AcceptingTrustVerifier {
    fn verify_signed_issuer_metadata(
        &self,
        _jwt: &SignedIssuerMetadataJwt,
        parsed: &ParsedSignedIssuerMetadata,
    ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
        if parsed.signature() != b"trusted-signature"
            || parsed.protected_header().get("kid").and_then(Value::as_str)
                != Some("issuer-metadata-key-1")
        {
            return Err(WalletError::new(WalletStatus::UntrustedSignedMetadata));
        }
        trust_evidence(parsed)
    }
}

struct RejectingTrustVerifier;

impl SignedIssuerMetadataTrustVerifier for RejectingTrustVerifier {
    fn verify_signed_issuer_metadata(
        &self,
        _jwt: &SignedIssuerMetadataJwt,
        _parsed: &ParsedSignedIssuerMetadata,
    ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
        Err(WalletError::new(WalletStatus::UntrustedSignedMetadata))
    }
}

struct X5cTrustVerifier;

impl SignedIssuerMetadataTrustVerifier for X5cTrustVerifier {
    fn verify_signed_issuer_metadata(
        &self,
        _jwt: &SignedIssuerMetadataJwt,
        parsed: &ParsedSignedIssuerMetadata,
    ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
        let certificates = parsed
            .protected_header()
            .get("x5c")
            .and_then(Value::as_array)
            .ok_or_else(|| WalletError::new(WalletStatus::UntrustedSignedMetadata))?;
        if certificates.len() != 2
            || certificates.first().and_then(Value::as_str) != Some("bGVhZi1jZXJ0")
            || certificates.get(1).and_then(Value::as_str) != Some("aW50ZXJtZWRpYXRl")
        {
            return Err(WalletError::new(WalletStatus::UntrustedSignedMetadata));
        }
        trust_evidence(parsed)
    }
}

#[test]
fn signed_metadata_is_processed_only_after_trust_verification(
) -> Result<(), SignedMetadataTestError> {
    let jwt = signed_metadata_jwt(valid_metadata_claims())?;
    let metadata = verify_signed_issuer_metadata(&jwt, &context(), &AcceptingTrustVerifier)
        .map_err(|_| SignedMetadataTestError::Metadata)?;

    assert_eq!(metadata.metadata().credential_issuer, ISSUER);
    assert_eq!(
        metadata.metadata().credential_endpoint,
        "https://issuer.example/credential"
    );
    assert_eq!(metadata.algorithm(), SignedMetadataAlgorithm::Es256);
    assert_eq!(metadata.issued_at(), NOW - 60);
    assert_eq!(metadata.expires_at(), Some(NOW + 600));
    assert_eq!(metadata.trust_evidence().policy_version(), "policy-v1");
    assert_eq!(metadata.trust_evidence().source_snapshot(), "snapshot-1");
    assert_eq!(metadata.trust_evidence().evaluated_at(), NOW);
    assert_eq!(metadata.trust_evidence().valid_until(), NOW + 600);
    Ok(())
}

#[test]
fn signed_metadata_rejects_untrusted_signature_before_metadata_processing(
) -> Result<(), SignedMetadataTestError> {
    let mut claims = valid_metadata_claims();
    claims["credential_endpoint"] = Value::Null;
    let jwt = signed_metadata_jwt(claims)?;

    let result = verify_signed_issuer_metadata(&jwt, &context(), &RejectingTrustVerifier);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::UntrustedSignedMetadata)
    );
    Ok(())
}

#[test]
fn signed_metadata_rejects_expired_jws() -> Result<(), SignedMetadataTestError> {
    let mut claims = valid_metadata_claims();
    claims["exp"] = json!(NOW);
    let jwt = signed_metadata_jwt(claims)?;

    let result = verify_signed_issuer_metadata(&jwt, &context(), &AcceptingTrustVerifier);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::ExpiredSignedMetadata)
    );
    Ok(())
}

#[test]
fn signed_metadata_rejects_subject_or_metadata_issuer_mismatch(
) -> Result<(), SignedMetadataTestError> {
    let mut wrong_subject = valid_metadata_claims();
    wrong_subject["sub"] = json!("https://attacker.example");
    let wrong_subject_jwt = signed_metadata_jwt(wrong_subject)?;
    assert_eq!(
        verify_signed_issuer_metadata(&wrong_subject_jwt, &context(), &AcceptingTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidSignedMetadata)
    );

    let mut wrong_metadata_issuer = valid_metadata_claims();
    wrong_metadata_issuer["credential_issuer"] = json!("https://attacker.example");
    let wrong_metadata_issuer_jwt = signed_metadata_jwt(wrong_metadata_issuer)?;
    assert_eq!(
        verify_signed_issuer_metadata(
            &wrong_metadata_issuer_jwt,
            &context(),
            &AcceptingTrustVerifier,
        )
        .err()
        .map(|error| error.status()),
        Some(WalletStatus::InvalidSignedMetadata)
    );
    Ok(())
}

#[test]
fn signed_metadata_requires_trust_evidence_to_bind_optional_issuer(
) -> Result<(), SignedMetadataTestError> {
    struct IssuerIgnoringTrustVerifier;

    impl SignedIssuerMetadataTrustVerifier for IssuerIgnoringTrustVerifier {
        fn verify_signed_issuer_metadata(
            &self,
            _jwt: &SignedIssuerMetadataJwt,
            parsed: &ParsedSignedIssuerMetadata,
        ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
            Ok(SignedMetadataTrustEvidenceInput {
                verified_signing_input: parsed.signing_input().to_owned(),
                signer_identity: "sha256:trusted-signer-certificate".to_owned(),
                asserted_issuer: None,
                policy_version: "policy-v1".to_owned(),
                source_snapshot: "snapshot-1".to_owned(),
                anchor: "anchor-1".to_owned(),
                evaluated_at: NOW,
                valid_until: NOW + 600,
                purpose: SignedMetadataTrustPurpose::CredentialIssuerMetadata,
                signer_trust_purpose:
                    SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
            })
        }
    }

    let jwt = signed_metadata_jwt(valid_metadata_claims())?;
    assert_eq!(
        verify_signed_issuer_metadata(&jwt, &context(), &IssuerIgnoringTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidSignedMetadataTrustEvidence)
    );
    Ok(())
}

#[test]
fn signed_metadata_rejects_trust_evidence_for_another_jws() -> Result<(), SignedMetadataTestError> {
    struct SubstitutedEvidenceVerifier;

    impl SignedIssuerMetadataTrustVerifier for SubstitutedEvidenceVerifier {
        fn verify_signed_issuer_metadata(
            &self,
            _jwt: &SignedIssuerMetadataJwt,
            _parsed: &ParsedSignedIssuerMetadata,
        ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
            Ok(SignedMetadataTrustEvidenceInput {
                verified_signing_input: "different.protected-payload".to_owned(),
                signer_identity: "sha256:trusted-signer-certificate".to_owned(),
                asserted_issuer: Some("https://trust-list.example".to_owned()),
                policy_version: "policy-v1".to_owned(),
                source_snapshot: "snapshot-1".to_owned(),
                anchor: "anchor-1".to_owned(),
                evaluated_at: NOW,
                valid_until: NOW + 600,
                purpose: SignedMetadataTrustPurpose::CredentialIssuerMetadata,
                signer_trust_purpose:
                    SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
            })
        }
    }

    let jwt = signed_metadata_jwt(valid_metadata_claims())?;
    assert_eq!(
        verify_signed_issuer_metadata(&jwt, &context(), &SubstitutedEvidenceVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidSignedMetadataTrustEvidence)
    );
    Ok(())
}

#[test]
fn signed_metadata_rejects_stale_or_future_trust_evidence() -> Result<(), SignedMetadataTestError> {
    struct NonCurrentTrustVerifier {
        evaluated_at: i64,
        valid_until: i64,
    }

    impl SignedIssuerMetadataTrustVerifier for NonCurrentTrustVerifier {
        fn verify_signed_issuer_metadata(
            &self,
            _jwt: &SignedIssuerMetadataJwt,
            parsed: &ParsedSignedIssuerMetadata,
        ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
            Ok(SignedMetadataTrustEvidenceInput {
                verified_signing_input: parsed.signing_input().to_owned(),
                signer_identity: "sha256:trusted-signer-certificate".to_owned(),
                asserted_issuer: Some("https://trust-list.example".to_owned()),
                policy_version: "policy-v1".to_owned(),
                source_snapshot: "snapshot-1".to_owned(),
                anchor: "anchor-1".to_owned(),
                evaluated_at: self.evaluated_at,
                valid_until: self.valid_until,
                purpose: SignedMetadataTrustPurpose::CredentialIssuerMetadata,
                signer_trust_purpose:
                    SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
            })
        }
    }

    let jwt = signed_metadata_jwt(valid_metadata_claims())?;
    for (verifier, expected) in [
        (
            NonCurrentTrustVerifier {
                evaluated_at: NOW - 120,
                valid_until: NOW - 1,
            },
            WalletStatus::SignedMetadataTrustEvidenceStale,
        ),
        (
            NonCurrentTrustVerifier {
                evaluated_at: NOW + 1,
                valid_until: NOW + 600,
            },
            WalletStatus::SignedMetadataTrustEvidenceFutureIssued,
        ),
    ] {
        assert_eq!(
            verify_signed_issuer_metadata(&jwt, &context(), &verifier)
                .err()
                .map(|error| error.status()),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn signed_metadata_binds_the_profile_required_signer_trust_purpose(
) -> Result<(), SignedMetadataTestError> {
    struct WrpacTrustVerifier;

    impl SignedIssuerMetadataTrustVerifier for WrpacTrustVerifier {
        fn verify_signed_issuer_metadata(
            &self,
            _jwt: &SignedIssuerMetadataJwt,
            parsed: &ParsedSignedIssuerMetadata,
        ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
            Ok(SignedMetadataTrustEvidenceInput {
                verified_signing_input: parsed.signing_input().to_owned(),
                signer_identity: "sha256:trusted-signer-certificate".to_owned(),
                asserted_issuer: Some("https://trust-list.example".to_owned()),
                policy_version: "wrpac-policy-v1".to_owned(),
                source_snapshot: "wrpac-snapshot-1".to_owned(),
                anchor: "wrpac-anchor-1".to_owned(),
                evaluated_at: NOW,
                valid_until: NOW + 600,
                purpose: SignedMetadataTrustPurpose::CredentialIssuerMetadata,
                signer_trust_purpose:
                    SignedMetadataSignerTrustPurpose::WalletRelyingPartyAccessCertificate,
            })
        }
    }

    let jwt = signed_metadata_jwt(valid_metadata_claims())?;
    assert_eq!(
        verify_signed_issuer_metadata(&jwt, &context(), &WrpacTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidSignedMetadataTrustEvidence)
    );

    let mut wrpac_context = context();
    wrpac_context.required_signer_trust_purpose =
        SignedMetadataSignerTrustPurpose::WalletRelyingPartyAccessCertificate;
    let verified = verify_signed_issuer_metadata(&jwt, &wrpac_context, &WrpacTrustVerifier)
        .map_err(|_| SignedMetadataTestError::Metadata)?;
    assert_eq!(
        verified.trust_evidence().signer_trust_purpose(),
        SignedMetadataSignerTrustPurpose::WalletRelyingPartyAccessCertificate
    );
    Ok(())
}

#[test]
fn signed_metadata_rejects_wrong_type_and_symmetric_algorithm(
) -> Result<(), SignedMetadataTestError> {
    for header in [
        json!({"typ": "JWT", "alg": "ES256", "kid": "issuer-metadata-key-1"}),
        json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg": "HS256",
            "kid": "issuer-metadata-key-1"
        }),
    ] {
        let jwt = compact_jws(&header, &valid_metadata_claims())?;
        let result = verify_signed_issuer_metadata(&jwt, &context(), &AcceptingTrustVerifier);
        assert_eq!(
            result.err().map(|error| error.status()),
            Some(if header["alg"] == "HS256" {
                WalletStatus::SignedMetadataUnsupportedAlgorithm
            } else {
                WalletStatus::InvalidSignedMetadata
            })
        );
    }
    Ok(())
}

#[test]
fn signed_metadata_rejects_unimplemented_critical_or_unencoded_payload_headers(
) -> Result<(), SignedMetadataTestError> {
    for header in [
        json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg": "ES256",
            "kid": "issuer-metadata-key-1",
            "crit": ["future-extension"]
        }),
        json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg": "ES256",
            "kid": "issuer-metadata-key-1",
            "b64": false,
            "crit": ["b64"]
        }),
        json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg": "ES256",
            "kid": "issuer-metadata-key-1",
            "b64": true
        }),
    ] {
        let jwt = compact_jws(&header, &valid_metadata_claims())?;
        assert_eq!(
            verify_signed_issuer_metadata(&jwt, &context(), &AcceptingTrustVerifier)
                .err()
                .map(|error| error.status()),
            Some(WalletStatus::InvalidSignedMetadata)
        );
    }
    Ok(())
}

#[test]
fn signed_metadata_rejects_embedded_or_remote_key_headers() -> Result<(), SignedMetadataTestError> {
    for extension in [
        json!({"jwk": {"kty": "EC"}}),
        json!({"jku": "https://attacker.example/jwks"}),
        json!({"x5u": "https://attacker.example/certificate"}),
    ] {
        let mut header = json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg": "ES256",
            "kid": "issuer-metadata-key-1"
        });
        let object = header
            .as_object_mut()
            .ok_or(SignedMetadataTestError::Json)?;
        let extension = extension.as_object().ok_or(SignedMetadataTestError::Json)?;
        object.extend(extension.clone());
        let jwt = compact_jws(&header, &valid_metadata_claims())?;
        assert_eq!(
            verify_signed_issuer_metadata(&jwt, &context(), &AcceptingTrustVerifier)
                .err()
                .map(|error| error.status()),
            Some(WalletStatus::InvalidSignedMetadata)
        );
    }
    Ok(())
}

#[test]
fn signed_metadata_passes_bounded_x5c_evidence_to_trust_verifier(
) -> Result<(), SignedMetadataTestError> {
    let jwt = compact_jws(
        &json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg": "ES256",
            "x5c": ["bGVhZi1jZXJ0", "aW50ZXJtZWRpYXRl"]
        }),
        &valid_metadata_claims(),
    )?;

    let verified = verify_signed_issuer_metadata(&jwt, &context(), &X5cTrustVerifier)
        .map_err(|_| SignedMetadataTestError::Metadata)?;
    assert_eq!(verified.metadata().credential_issuer, ISSUER);
    Ok(())
}

#[test]
fn signed_metadata_rejects_empty_oversized_or_malformed_certificate_chains_before_trust(
) -> Result<(), SignedMetadataTestError> {
    for chain in [
        json!([]),
        json!(["a", "b", "c", "d", "e", "f", "g", "h", "i"]),
        json!(["a".repeat((6 * 1024) + 1)]),
        json!(["not base64 certificate!"]),
    ] {
        let jwt = compact_jws(
            &json!({
                "typ": "openidvci-issuer-metadata+jwt",
                "alg": "ES256",
                "x5c": chain
            }),
            &valid_metadata_claims(),
        )?;
        assert_eq!(
            verify_signed_issuer_metadata(&jwt, &context(), &X5cTrustVerifier)
                .err()
                .map(|error| error.status()),
            Some(WalletStatus::InvalidSignedMetadata)
        );
    }
    Ok(())
}

#[test]
fn certificate_chain_trust_failures_remain_provider_decisions(
) -> Result<(), SignedMetadataTestError> {
    let jwt = compact_jws(
        &json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg": "ES256",
            "x5c": ["c2VsZi1zaWduZWQtbGVhZg=="]
        }),
        &valid_metadata_claims(),
    )?;

    assert_eq!(
        verify_signed_issuer_metadata(&jwt, &context(), &RejectingTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::UntrustedSignedMetadata)
    );
    Ok(())
}

#[test]
fn signed_metadata_enforces_algorithm_and_iat_policy() -> Result<(), SignedMetadataTestError> {
    let mut wrong_algorithm_context = context();
    wrong_algorithm_context.accepted_algorithms = vec![SignedMetadataAlgorithm::EdDsa];
    let jwt = signed_metadata_jwt(valid_metadata_claims())?;
    assert_eq!(
        verify_signed_issuer_metadata(&jwt, &wrong_algorithm_context, &AcceptingTrustVerifier,)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::SignedMetadataAlgorithmNotAllowed)
    );

    let mut stale = valid_metadata_claims();
    stale["iat"] = json!(NOW - 301);
    let stale_jwt = signed_metadata_jwt(stale)?;
    assert_eq!(
        verify_signed_issuer_metadata(&stale_jwt, &context(), &AcceptingTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::StaleSignedMetadata)
    );

    let mut future = valid_metadata_claims();
    future["iat"] = json!(NOW + 1);
    let future_jwt = signed_metadata_jwt(future)?;
    assert_eq!(
        verify_signed_issuer_metadata(&future_jwt, &context(), &AcceptingTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::FutureSignedMetadata)
    );
    Ok(())
}

#[test]
fn signed_metadata_rejects_duplicate_json_members_before_trust(
) -> Result<(), SignedMetadataTestError> {
    let header = br#"{"typ":"openidvci-issuer-metadata+jwt","alg":"ES256","alg":"ES256","kid":"issuer-metadata-key-1"}"#;
    let claims =
        serde_json::to_vec(&valid_metadata_claims()).map_err(|_| SignedMetadataTestError::Json)?;
    let jwt = compact_jws_bytes(header, &claims)?;

    assert_eq!(
        verify_signed_issuer_metadata(&jwt, &context(), &AcceptingTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidSignedMetadata)
    );
    Ok(())
}

#[test]
fn signed_metadata_rejects_oversized_and_excessively_nested_payloads(
) -> Result<(), SignedMetadataTestError> {
    let header = serde_json::to_vec(&json!({
        "typ": "openidvci-issuer-metadata+jwt",
        "alg": "ES256",
        "kid": "issuer-metadata-key-1"
    }))
    .map_err(|_| SignedMetadataTestError::Json)?;
    let oversized_payload = vec![b' '; (256 * 1024) + 1];
    let oversized_jwt = compact_jws_bytes(&header, &oversized_payload)?;
    assert_eq!(
        verify_signed_issuer_metadata(&oversized_jwt, &context(), &AcceptingTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidSignedMetadata)
    );

    let mut claims = valid_metadata_claims();
    let mut nested = Value::Null;
    for _ in 0..140 {
        nested = Value::Array(vec![nested]);
    }
    claims["malicious_extension"] = nested;
    let nested_jwt = compact_jws_bytes(
        &header,
        &serde_json::to_vec(&claims).map_err(|_| SignedMetadataTestError::Json)?,
    )?;
    assert_eq!(
        verify_signed_issuer_metadata(&nested_jwt, &context(), &AcceptingTrustVerifier)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidSignedMetadata)
    );
    Ok(())
}

fn context() -> SignedIssuerMetadataValidationContext {
    SignedIssuerMetadataValidationContext {
        expected_credential_issuer: ISSUER.to_owned(),
        current_time: NOW,
        max_age_seconds: 300,
        allowed_clock_skew_seconds: 0,
        accepted_algorithms: vec![SignedMetadataAlgorithm::Es256],
        required_signer_trust_purpose:
            SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
    }
}

fn trust_evidence(
    parsed: &ParsedSignedIssuerMetadata,
) -> WalletResult<SignedMetadataTrustEvidenceInput> {
    Ok(SignedMetadataTrustEvidenceInput {
        verified_signing_input: parsed.signing_input().to_owned(),
        signer_identity: "sha256:trusted-signer-certificate".to_owned(),
        asserted_issuer: Some("https://trust-list.example".to_owned()),
        policy_version: "policy-v1".to_owned(),
        source_snapshot: "snapshot-1".to_owned(),
        anchor: "anchor-1".to_owned(),
        evaluated_at: NOW,
        valid_until: NOW + 600,
        purpose: SignedMetadataTrustPurpose::CredentialIssuerMetadata,
        signer_trust_purpose: SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
    })
}

fn valid_metadata_claims() -> Value {
    json!({
        "iss": "https://trust-list.example",
        "sub": ISSUER,
        "iat": NOW - 60,
        "exp": NOW + 600,
        "credential_issuer": ISSUER,
        "credential_endpoint": "https://issuer.example/credential",
        "credential_configurations_supported": {
            "pid": { "format": "dc+sd-jwt", "vct": "urn:example:pid" }
        }
    })
}

fn signed_metadata_jwt(claims: Value) -> Result<SignedIssuerMetadataJwt, SignedMetadataTestError> {
    compact_jws(
        &json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg": "ES256",
            "kid": "issuer-metadata-key-1"
        }),
        &claims,
    )
}

fn compact_jws(
    header: &Value,
    claims: &Value,
) -> Result<SignedIssuerMetadataJwt, SignedMetadataTestError> {
    let header = serde_json::to_vec(header).map_err(|_| SignedMetadataTestError::Json)?;
    let claims = serde_json::to_vec(claims).map_err(|_| SignedMetadataTestError::Json)?;
    compact_jws_bytes(&header, &claims)
}

fn compact_jws_bytes(
    header: &[u8],
    claims: &[u8],
) -> Result<SignedIssuerMetadataJwt, SignedMetadataTestError> {
    let compact = [
        bytes_to_base64url(header),
        bytes_to_base64url(claims),
        bytes_to_base64url(b"trusted-signature"),
    ]
    .join(".");
    SignedIssuerMetadataJwt::new(compact).map_err(|_| SignedMetadataTestError::Metadata)
}
