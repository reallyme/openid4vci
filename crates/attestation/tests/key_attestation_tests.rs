// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key attestation profile validation tests.

use openid4vci_attestation::{
    parse_key_attestation, verify_key_attestation, AttackPotentialResistance, AttestationError,
    AttestationResult, AttestationStatus, KeyAttestationAlgorithm, KeyAttestationJwt,
    KeyAttestationStatusEvidence, KeyAttestationTemporalPolicy, KeyAttestationTrustEvidenceInput,
    KeyAttestationTrustPurpose, KeyAttestationTrustVerifier, KeyAttestationValidationContext,
    ParsedKeyAttestation,
};
use reallyme_codec::base64url::bytes_to_base64url;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
enum KeyAttestationTestError {
    #[error("json")]
    Json,
    #[error("attestation")]
    Attestation,
}

struct AcceptingTrustVerifier;

impl KeyAttestationTrustVerifier for AcceptingTrustVerifier {
    fn verify_key_attestation(
        &self,
        _jwt: &KeyAttestationJwt,
        _parsed: &ParsedKeyAttestation,
    ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
        accepted_trust_evidence(_parsed)
    }
}

#[test]
fn key_attestation_recognizes_every_final_spec_resistance_value() {
    let cases = [
        ("iso_18045_basic", AttackPotentialResistance::Iso18045Basic),
        (
            "iso_18045_enhanced-basic",
            AttackPotentialResistance::Iso18045EnhancedBasic,
        ),
        (
            "iso_18045_moderate",
            AttackPotentialResistance::Iso18045Moderate,
        ),
        ("iso_18045_high", AttackPotentialResistance::Iso18045High),
    ];

    for (wire_value, expected) in cases {
        let parsed = AttackPotentialResistance::parse(wire_value.to_owned());
        assert_eq!(parsed, Ok(expected));
    }
}

#[test]
fn key_attestation_accepts_final_spec_shape() -> Result<(), KeyAttestationTestError> {
    let jwt = key_attestation_jwt(Some("nonce-1"), "key-attestation+jwt")?;
    let verified = verify_key_attestation(&jwt, &context(true)?, &AcceptingTrustVerifier)
        .map_err(|_| KeyAttestationTestError::Attestation)?;

    assert_eq!(verified.algorithm(), KeyAttestationAlgorithm::Es256);
    assert_eq!(verified.attested_key_count(), 1);
    assert_eq!(verified.nonce(), Some("nonce-1"));
    assert_eq!(
        verified.key_storage(),
        Some([AttackPotentialResistance::Iso18045Moderate].as_slice())
    );
    assert_eq!(
        verified.user_authentication(),
        Some([AttackPotentialResistance::Iso18045High].as_slice())
    );
    assert_eq!(
        verified.certification().map(|value| value.as_str()),
        Some("https://certification.example/key-storage")
    );
    assert_eq!(
        verified.status().map(|value| value.as_json()),
        Some(&json!({"status_list": {"idx": 7}}))
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_trust_evidence_for_another_jws() -> Result<(), KeyAttestationTestError> {
    struct SubstitutedEvidenceVerifier;

    impl KeyAttestationTrustVerifier for SubstitutedEvidenceVerifier {
        fn verify_key_attestation(
            &self,
            _jwt: &KeyAttestationJwt,
            _parsed: &ParsedKeyAttestation,
        ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
            Ok(KeyAttestationTrustEvidenceInput {
                verified_signing_input: "different.protected-payload".to_owned(),
                signer_identity: "attester.example".to_owned(),
                policy_version: "policy-v1".to_owned(),
                source_snapshot: "snapshot-1".to_owned(),
                anchor: "anchor-1".to_owned(),
                evaluated_at: 1_700_000_000,
                valid_until: 1_700_000_600,
                purpose: KeyAttestationTrustPurpose::CredentialBinding,
                status: KeyAttestationStatusEvidence::Valid {
                    evaluated_at: 1_700_000_000,
                },
            })
        }
    }

    let jwt = key_attestation_jwt(Some("nonce-1"), "key-attestation+jwt")?;
    assert_eq!(
        verify_key_attestation(&jwt, &context(true)?, &SubstitutedEvidenceVerifier)
            .err()
            .map(|error| error.status()),
        Some(AttestationStatus::InvalidTrustEvidence)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_expired_claim_even_when_exp_is_optional(
) -> Result<(), KeyAttestationTestError> {
    let claims = json!({
        "iat": 1_699_999_900_i64,
        "exp": 1_699_999_940_i64,
        "attested_keys": [valid_key()]
    });
    let compact = compact_jwt(
        &json!({"typ": "key-attestation+jwt", "alg": "ES256"}),
        &claims,
    )?;
    let jwt = KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;

    assert_eq!(
        parse_key_attestation(&jwt, &context(false)?)
            .err()
            .map(|error| error.status()),
        Some(AttestationStatus::Expired)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_malformed_certification_and_status_claims(
) -> Result<(), KeyAttestationTestError> {
    for (name, value) in [
        ("certification", json!("not a URL")),
        ("status", json!("not-an-object")),
    ] {
        let mut claims = json!({
            "iat": 1_699_999_999_i64,
            "exp": 1_700_000_100_i64,
            "attested_keys": [valid_key()]
        });
        claims[name] = value;
        let compact = compact_jwt(
            &json!({"typ": "key-attestation+jwt", "alg": "ES256"}),
            &claims,
        )?;
        let jwt =
            KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;
        assert_eq!(
            parse_key_attestation(&jwt, &context(false)?)
                .err()
                .map(|error| error.status()),
            Some(AttestationStatus::InvalidClaims),
            "malformed {name} was accepted"
        );
    }
    Ok(())
}

#[test]
fn key_attestation_rejects_missing_required_nonce() -> Result<(), KeyAttestationTestError> {
    let jwt = key_attestation_jwt(None, "key-attestation+jwt")?;
    let result = parse_key_attestation(&jwt, &context(true)?);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_wrong_typ() -> Result<(), KeyAttestationTestError> {
    let jwt = key_attestation_jwt(Some("nonce-1"), "JWT")?;
    let result = parse_key_attestation(&jwt, &context(true)?);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::InvalidHeader)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_unimplemented_critical_or_unencoded_payload_headers(
) -> Result<(), KeyAttestationTestError> {
    for extension in [
        json!({"crit": ["future-extension"]}),
        json!({"b64": false, "crit": ["b64"]}),
        json!({"b64": true}),
    ] {
        let mut header = json!({"typ": "key-attestation+jwt", "alg": "ES256"});
        let header_object = header
            .as_object_mut()
            .ok_or(KeyAttestationTestError::Json)?;
        let extension_object = extension.as_object().ok_or(KeyAttestationTestError::Json)?;
        header_object.extend(extension_object.clone());
        let jwt = jwt_with_header_and_claims(
            header,
            json!({
                "iat": 1_699_999_999_i64,
                "exp": 1_700_000_100_i64,
                "attested_keys": [valid_key()]
            }),
        )?;
        assert_eq!(
            parse_key_attestation(&jwt, &context(false)?)
                .err()
                .map(|error| error.status()),
            Some(AttestationStatus::InvalidHeader)
        );
    }
    Ok(())
}

#[test]
fn key_attestation_rejects_trust_failure() -> Result<(), KeyAttestationTestError> {
    struct RejectingTrustVerifier;

    impl KeyAttestationTrustVerifier for RejectingTrustVerifier {
        fn verify_key_attestation(
            &self,
            _jwt: &KeyAttestationJwt,
            _parsed: &ParsedKeyAttestation,
        ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
            Err(AttestationError::new(AttestationStatus::TrustRejected))
        }
    }

    let jwt = key_attestation_jwt(Some("nonce-1"), "key-attestation+jwt")?;
    let result = verify_key_attestation(&jwt, &context(true)?, &RejectingTrustVerifier);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::TrustRejected)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_non_object_attested_key() -> Result<(), KeyAttestationTestError> {
    // An attested key that is not a JWK object (here, a bare string) must be
    // rejected during structural validation, before any trust verifier runs.
    let claims = json!({
        "iat": 1_699_999_999_i64,
        "exp": 1_700_000_100_i64,
        "nonce": "nonce-1",
        "attested_keys": ["not-a-jwk"]
    });
    let compact = compact_jwt(
        &json!({"typ": "key-attestation+jwt", "alg": "ES256", "kid": "key-attester-1"}),
        &claims,
    )?;
    let jwt = KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;
    let result = parse_key_attestation(&jwt, &context(true)?);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::InvalidClaims)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_private_or_symmetric_attested_keys(
) -> Result<(), KeyAttestationTestError> {
    for private_member in [
        "d",
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "oth",
        "k",
        "priv",
        "privateKey",
        "secretKey",
    ] {
        let mut attested_key = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "B_zLQ0UJb5Yhcm_E5De-DPgcQxCB8yjlVJZyOaxVIu4",
            "y": "DZcUdT7G939Veqc3FCadWs_rcpS-vc_8Z8FaZREVX4A"
        });
        attested_key[private_member] = json!("must-not-cross-public-boundary");
        let compact = compact_jwt(
            &json!({"typ": "key-attestation+jwt", "alg": "ES256", "kid": "key-attester-1"}),
            &json!({
                "iat": 1_699_999_999_i64,
                "exp": 1_700_000_100_i64,
                "attested_keys": [attested_key]
            }),
        )?;
        let jwt =
            KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;
        let result = parse_key_attestation(&jwt, &context(false)?);
        assert_eq!(
            result.err().map(|error| error.status()),
            Some(AttestationStatus::InvalidClaims),
            "private JWK member {private_member} was accepted"
        );
    }

    let compact = compact_jwt(
        &json!({"typ": "key-attestation+jwt", "alg": "ES256", "kid": "key-attester-1"}),
        &json!({
            "iat": 1_699_999_999_i64,
            "exp": 1_700_000_100_i64,
            "attested_keys": [{"kty": "oct"}]
        }),
    )?;
    let jwt = KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;
    let result = parse_key_attestation(&jwt, &context(false)?);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::UnsupportedAttestedKey)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_duplicate_json_members() -> Result<(), KeyAttestationTestError> {
    let header = r#"{"typ":"key-attestation+jwt","alg":"ES256","alg":"EdDSA"}"#;
    let claims = r#"{"iat":1699999999,"exp":1700000100,"attested_keys":[{"kty":"EC"}]}"#;
    let compact = compact_jwt_text(header, claims, b"signature");
    let jwt = KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;

    let result = parse_key_attestation(&jwt, &context(false)?);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::InvalidHeader)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_excessive_claim_nesting() -> Result<(), KeyAttestationTestError> {
    let mut nested = "0".to_owned();
    for _ in 0..140 {
        nested = format!("[{nested}]");
    }
    let claims = format!(
        r#"{{"iat":1699999999,"exp":1700000100,"attested_keys":[{{"kty":"EC"}}],"extension":{nested}}}"#
    );
    let compact = compact_jwt_text(
        r#"{"typ":"key-attestation+jwt","alg":"ES256"}"#,
        &claims,
        b"signature",
    );
    let jwt = KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;

    let result = parse_key_attestation(&jwt, &context(false)?);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::InvalidClaims)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_oversized_decoded_signature() -> Result<(), KeyAttestationTestError> {
    let claims = r#"{"iat":1699999999,"exp":1700000100,"attested_keys":[{"kty":"EC"}]}"#;
    let signature = vec![7_u8; 16_385];
    let compact = compact_jwt_text(
        r#"{"typ":"key-attestation+jwt","alg":"ES256"}"#,
        claims,
        &signature,
    );
    let jwt = KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;

    let result = parse_key_attestation(&jwt, &context(false)?);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::InvalidJwt)
    );
    Ok(())
}

#[test]
fn key_attestation_rejects_oversized_attested_jwk() -> Result<(), KeyAttestationTestError> {
    let claims = format!(
        r#"{{"iat":1699999999,"exp":1700000100,"attested_keys":[{{"kty":"EC","extension":"{}"}}]}}"#,
        "a".repeat(8_192)
    );
    let compact = compact_jwt_text(
        r#"{"typ":"key-attestation+jwt","alg":"ES256"}"#,
        &claims,
        b"signature",
    );
    let jwt = KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)?;

    let result = parse_key_attestation(&jwt, &context(false)?);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(AttestationStatus::InvalidClaims)
    );
    Ok(())
}

#[test]
fn key_attestation_enforces_inclusive_time_boundaries() -> Result<(), KeyAttestationTestError> {
    let cases = [
        (1_699_999_640_i64, 1_700_000_100_i64, None),
        (
            1_699_999_639_i64,
            1_700_000_100_i64,
            Some(AttestationStatus::Stale),
        ),
        (1_700_000_060_i64, 1_700_000_100_i64, None),
        (
            1_700_000_061_i64,
            1_700_000_100_i64,
            Some(AttestationStatus::FutureIssued),
        ),
        (
            1_699_999_900_i64,
            1_699_999_940_i64,
            Some(AttestationStatus::Expired),
        ),
        (1_699_999_900_i64, 1_699_999_941_i64, None),
    ];
    for (issued_at, expires_at, expected_error) in cases {
        let jwt = jwt_with_header_and_claims(
            json!({"typ": "key-attestation+jwt", "alg": "ES256"}),
            json!({
                "iat": issued_at,
                "exp": expires_at,
                "attested_keys": [valid_key()]
            }),
        )?;
        assert_eq!(
            parse_key_attestation(&jwt, &context(false)?)
                .err()
                .map(|error| error.status()),
            expected_error
        );
    }
    Ok(())
}

#[test]
fn key_attestation_rejects_disallowed_algorithm_and_duplicate_key_material(
) -> Result<(), KeyAttestationTestError> {
    let disallowed = jwt_with_header_and_claims(
        json!({"typ": "key-attestation+jwt", "alg": "EdDSA"}),
        json!({
            "iat": 1_700_000_000_i64,
            "exp": 1_700_000_100_i64,
            "attested_keys": [valid_key()]
        }),
    )?;
    assert_eq!(
        parse_key_attestation(&disallowed, &context(false)?)
            .err()
            .map(|error| error.status()),
        Some(AttestationStatus::AlgorithmNotAllowed)
    );

    let mut first = valid_key();
    first["kid"] = json!("key-1");
    let mut second = valid_key();
    second["kid"] = json!("key-2");
    let duplicate = jwt_with_header_and_claims(
        json!({"typ": "key-attestation+jwt", "alg": "ES256"}),
        json!({
            "iat": 1_700_000_000_i64,
            "exp": 1_700_000_100_i64,
            "attested_keys": [first, second]
        }),
    )?;
    assert_eq!(
        parse_key_attestation(&duplicate, &context(false)?)
            .err()
            .map(|error| error.status()),
        Some(AttestationStatus::DuplicateAttestedKey)
    );
    Ok(())
}

#[test]
fn key_attestation_preserves_unknown_resistance_and_trust_provenance(
) -> Result<(), KeyAttestationTestError> {
    let jwt = jwt_with_header_and_claims(
        json!({"typ": "key-attestation+jwt", "alg": "ES256"}),
        json!({
            "iat": 1_700_000_000_i64,
            "exp": 1_700_000_100_i64,
            "key_storage": ["future_registry_value"],
            "attested_keys": [valid_key()]
        }),
    )?;
    let verified = verify_key_attestation(&jwt, &context(false)?, &AcceptingTrustVerifier)
        .map_err(|_| KeyAttestationTestError::Attestation)?;
    let resistance = verified
        .key_storage()
        .and_then(|values| values.first())
        .ok_or(KeyAttestationTestError::Attestation)?;
    assert!(!resistance.is_registered());
    assert_eq!(resistance.as_str(), "future_registry_value");
    assert_eq!(verified.issued_at(), 1_700_000_000);
    assert_eq!(verified.expires_at(), Some(1_700_000_100));
    assert_eq!(verified.trust_evidence().policy_version(), "policy-v1");
    assert_eq!(verified.trust_evidence().source_snapshot(), "snapshot-1");
    assert_eq!(verified.trust_evidence().anchor(), "anchor-1");
    assert_eq!(verified.trust_evidence().evaluated_at(), 1_700_000_000);
    assert_eq!(verified.trust_evidence().valid_until(), 1_700_000_600);
    Ok(())
}

#[test]
fn key_attestation_rejects_stale_or_future_signer_trust_evidence(
) -> Result<(), KeyAttestationTestError> {
    struct NonCurrentTrustVerifier {
        evaluated_at: i64,
        valid_until: i64,
    }
    impl KeyAttestationTrustVerifier for NonCurrentTrustVerifier {
        fn verify_key_attestation(
            &self,
            _jwt: &KeyAttestationJwt,
            parsed: &ParsedKeyAttestation,
        ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
            let status = if parsed.status().is_some() {
                KeyAttestationStatusEvidence::Valid {
                    evaluated_at: 1_700_000_000,
                }
            } else {
                KeyAttestationStatusEvidence::NotPresent
            };
            Ok(KeyAttestationTrustEvidenceInput {
                verified_signing_input: parsed.signing_input().to_owned(),
                signer_identity: "attester.example".to_owned(),
                policy_version: "policy-v1".to_owned(),
                source_snapshot: "snapshot-1".to_owned(),
                anchor: "anchor-1".to_owned(),
                evaluated_at: self.evaluated_at,
                valid_until: self.valid_until,
                purpose: KeyAttestationTrustPurpose::CredentialBinding,
                status,
            })
        }
    }

    let jwt = key_attestation_jwt(Some("nonce-1"), "key-attestation+jwt")?;
    for (verifier, expected) in [
        (
            NonCurrentTrustVerifier {
                evaluated_at: 1_699_999_000,
                valid_until: 1_699_999_939,
            },
            AttestationStatus::TrustEvidenceStale,
        ),
        (
            NonCurrentTrustVerifier {
                evaluated_at: 1_700_000_061,
                valid_until: 1_700_000_600,
            },
            AttestationStatus::TrustEvidenceFutureIssued,
        ),
    ] {
        assert_eq!(
            verify_key_attestation(&jwt, &context(true)?, &verifier)
                .err()
                .map(|error| error.status()),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn present_status_requires_conclusive_status_evidence() -> Result<(), KeyAttestationTestError> {
    struct StatusIgnoringVerifier;
    impl KeyAttestationTrustVerifier for StatusIgnoringVerifier {
        fn verify_key_attestation(
            &self,
            _jwt: &KeyAttestationJwt,
            parsed: &ParsedKeyAttestation,
        ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
            Ok(KeyAttestationTrustEvidenceInput {
                verified_signing_input: parsed.signing_input().to_owned(),
                signer_identity: "attester.example".to_owned(),
                policy_version: "policy-v1".to_owned(),
                source_snapshot: "snapshot-1".to_owned(),
                anchor: "anchor-1".to_owned(),
                evaluated_at: 1_700_000_000,
                valid_until: 1_700_000_600,
                purpose: KeyAttestationTrustPurpose::CredentialBinding,
                status: KeyAttestationStatusEvidence::NotPresent,
            })
        }
    }
    let jwt = key_attestation_jwt(Some("nonce-1"), "key-attestation+jwt")?;
    assert_eq!(
        verify_key_attestation(&jwt, &context(true)?, &StatusIgnoringVerifier)
            .err()
            .map(|error| error.status()),
        Some(AttestationStatus::StatusIndeterminate)
    );
    Ok(())
}

#[test]
fn present_status_requires_evidence_from_the_current_verification_window(
) -> Result<(), KeyAttestationTestError> {
    struct NonCurrentStatusVerifier {
        evaluated_at: i64,
    }
    impl KeyAttestationTrustVerifier for NonCurrentStatusVerifier {
        fn verify_key_attestation(
            &self,
            _jwt: &KeyAttestationJwt,
            parsed: &ParsedKeyAttestation,
        ) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
            Ok(KeyAttestationTrustEvidenceInput {
                verified_signing_input: parsed.signing_input().to_owned(),
                signer_identity: "attester.example".to_owned(),
                policy_version: "policy-v1".to_owned(),
                source_snapshot: "snapshot-1".to_owned(),
                anchor: "anchor-1".to_owned(),
                evaluated_at: 1_700_000_000,
                valid_until: 1_700_000_600,
                purpose: KeyAttestationTrustPurpose::CredentialBinding,
                status: KeyAttestationStatusEvidence::Valid {
                    evaluated_at: self.evaluated_at,
                },
            })
        }
    }

    let jwt = key_attestation_jwt(Some("nonce-1"), "key-attestation+jwt")?;
    for evaluated_at in [1_699_999_939_i64, 1_700_000_061_i64] {
        assert_eq!(
            verify_key_attestation(
                &jwt,
                &context(true)?,
                &NonCurrentStatusVerifier { evaluated_at },
            )
            .err()
            .map(|error| error.status()),
            Some(AttestationStatus::StatusIndeterminate)
        );
    }
    Ok(())
}

fn context(
    nonce_required: bool,
) -> Result<KeyAttestationValidationContext, KeyAttestationTestError> {
    let temporal_policy = KeyAttestationTemporalPolicy::new(1_700_000_000, 300, 60, false)
        .map_err(|_| KeyAttestationTestError::Attestation)?;
    Ok(KeyAttestationValidationContext {
        nonce_required,
        expected_nonce: None,
        temporal_policy,
        accepted_algorithms: vec![KeyAttestationAlgorithm::Es256],
    })
}

fn accepted_trust_evidence(
    parsed: &ParsedKeyAttestation,
) -> AttestationResult<KeyAttestationTrustEvidenceInput> {
    let status = if parsed.status().is_some() {
        KeyAttestationStatusEvidence::Valid {
            evaluated_at: 1_700_000_000,
        }
    } else {
        KeyAttestationStatusEvidence::NotPresent
    };
    Ok(KeyAttestationTrustEvidenceInput {
        verified_signing_input: parsed.signing_input().to_owned(),
        signer_identity: "attester.example".to_owned(),
        policy_version: "policy-v1".to_owned(),
        source_snapshot: "snapshot-1".to_owned(),
        anchor: "anchor-1".to_owned(),
        evaluated_at: 1_700_000_000,
        valid_until: 1_700_000_600,
        purpose: KeyAttestationTrustPurpose::CredentialBinding,
        status,
    })
}

fn valid_key() -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "B_zLQ0UJb5Yhcm_E5De-DPgcQxCB8yjlVJZyOaxVIu4",
        "y": "DZcUdT7G939Veqc3FCadWs_rcpS-vc_8Z8FaZREVX4A"
    })
}

fn key_attestation_jwt(
    nonce: Option<&str>,
    typ: &str,
) -> Result<KeyAttestationJwt, KeyAttestationTestError> {
    let mut claims = json!({
        "iat": 1_699_999_999_i64,
        "exp": 1_700_000_100_i64,
        "key_storage": ["iso_18045_moderate"],
        "user_authentication": ["iso_18045_high"],
        "certification": "https://certification.example/key-storage",
        "status": {"status_list": {"idx": 7}},
        "attested_keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": "B_zLQ0UJb5Yhcm_E5De-DPgcQxCB8yjlVJZyOaxVIu4",
            "y": "DZcUdT7G939Veqc3FCadWs_rcpS-vc_8Z8FaZREVX4A"
        }]
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = Value::String(nonce.to_owned());
    }
    let compact = compact_jwt(
        &json!({
            "typ": typ,
            "alg": "ES256",
            "kid": "key-attester-1"
        }),
        &claims,
    )?;
    KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)
}

fn compact_jwt(header: &Value, claims: &Value) -> Result<String, KeyAttestationTestError> {
    let header_json = serde_json::to_vec(header).map_err(|_| KeyAttestationTestError::Json)?;
    let claims_json = serde_json::to_vec(claims).map_err(|_| KeyAttestationTestError::Json)?;
    Ok([
        bytes_to_base64url(&header_json),
        bytes_to_base64url(&claims_json),
        bytes_to_base64url(b"signature"),
    ]
    .join("."))
}

fn jwt_with_header_and_claims(
    header: Value,
    claims: Value,
) -> Result<KeyAttestationJwt, KeyAttestationTestError> {
    let compact = compact_jwt(&header, &claims)?;
    KeyAttestationJwt::new(compact).map_err(|_| KeyAttestationTestError::Attestation)
}

fn compact_jwt_text(header: &str, claims: &str, signature: &[u8]) -> String {
    [
        bytes_to_base64url(header.as_bytes()),
        bytes_to_base64url(claims.as_bytes()),
        bytes_to_base64url(signature),
    ]
    .join(".")
}
