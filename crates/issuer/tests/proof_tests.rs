// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof verifier surface tests for final OpenID4VCI proof semantics.

use openid4vci_issuer::{
    validate_common_proof_claims, CompactProofJwtParser, IssuerResult, IssuerStatus,
    ProofAlgorithm, ProofVerificationContext, DEFAULT_MAX_PROOF_JWT_BYTES,
};
use openid4vci_types::CredentialSelector;
use reallyme_codec::base64url::bytes_to_base64url;
use serde_json::json;

const IAT: i64 = 1_700_000_000;

fn segment(value: &serde_json::Value) -> IssuerResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        openid4vci_issuer::IssuerError::new(openid4vci_issuer::IssuerStatus::EncodingFailed)
    })?;
    Ok(bytes_to_base64url(&bytes))
}

fn proof_jwt(header: serde_json::Value, payload: serde_json::Value) -> IssuerResult<String> {
    Ok(format!(
        "{}.{}.{}",
        segment(&header)?,
        segment(&payload)?,
        bytes_to_base64url(&[1_u8, 2_u8, 3_u8])
    ))
}

fn proof_jwt_text(header: &str, payload: &str) -> String {
    [
        bytes_to_base64url(header.as_bytes()),
        bytes_to_base64url(payload.as_bytes()),
        bytes_to_base64url(&[1_u8, 2_u8, 3_u8]),
    ]
    .join(".")
}

fn context() -> ProofVerificationContext {
    ProofVerificationContext {
        credential_issuer: "https://issuer.example".to_owned(),
        selector: CredentialSelector::ConfigurationId("pid".to_owned()),
        client_id: None,
        accepted_proof_algorithms: vec![
            ProofAlgorithm::EdDsa,
            ProofAlgorithm::Es256,
            ProofAlgorithm::Es256k,
        ],
        nonce_required: true,
        current_time: 1_700_000_000,
        key_attestation_policy: None,
    }
}

#[test]
fn parser_extracts_nonce_audience_kid_and_key_binding_id() -> IssuerResult<()> {
    let jwt = proof_jwt(
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": "proof-key-1"
        }),
        json!({
            "iat": IAT,
            "nonce": "nonce-1",
            "aud": "https://issuer.example",
            "key_binding_id": "binding-1"
        }),
    )?;
    let claims = CompactProofJwtParser::default().parse_unverified(&jwt)?;
    assert_eq!(claims.nonce.as_deref(), Some("nonce-1"));
    assert_eq!(claims.audience.as_deref(), Some("https://issuer.example"));
    assert_eq!(claims.key_binding_id.as_deref(), Some("binding-1"));
    assert_eq!(claims.key_id.as_deref(), Some("proof-key-1"));
    validate_common_proof_claims(&claims, &context())?;
    Ok(())
}

#[test]
fn parser_rejects_draft_payload_cnf_jwk_without_header_binding() -> IssuerResult<()> {
    // OpenID4VCI 1.0 Appendix F.1 binds the proof key in the JOSE header. A key
    // present only in the draft-era payload `cnf.jwk` must not be used.
    let public_key = [7_u8; 32];
    let jwt = proof_jwt(
        json!({ "alg": "EdDSA", "typ": "openid4vci-proof+jwt" }),
        json!({
            "iat": IAT,
            "nonce": "nonce-1",
            "aud": "https://issuer.example",
            "cnf": {
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": bytes_to_base64url(&public_key),
                    "kid": "cnf-key-1"
                }
            }
        }),
    )?;
    let result = CompactProofJwtParser::default().parse_unverified(&jwt);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn parser_rejects_missing_header_key_binding() -> IssuerResult<()> {
    let jwt = proof_jwt(
        json!({
            "alg": "EdDSA",
            "typ": "openid4vci-proof+jwt"
        }),
        json!({ "iat": IAT, "nonce": "nonce-1", "aud": "https://issuer.example" }),
    )?;
    let result = CompactProofJwtParser::default().parse_unverified(&jwt);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn parser_extracts_public_header_jwk() -> IssuerResult<()> {
    let public_key = [7_u8; 32];
    let jwt = proof_jwt(
        json!({
            "alg": "EdDSA",
            "typ": "openid4vci-proof+jwt",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": bytes_to_base64url(&public_key),
                "kid": "header-key-1"
            }
        }),
        json!({
            "iat": IAT,
            "nonce": "nonce-1",
            "aud": "https://issuer.example"
        }),
    )?;
    let claims = CompactProofJwtParser::default().parse_unverified(&jwt)?;
    let cnf = claims
        .confirmation_jwk
        .as_ref()
        .ok_or(openid4vci_issuer::IssuerError::new(
            IssuerStatus::InvalidProof,
        ))?;
    assert_eq!(cnf.algorithm, ProofAlgorithm::EdDsa);
    assert_eq!(cnf.public_key.as_slice(), public_key);
    assert_eq!(cnf.key_id.as_deref(), Some("header-key-1"));
    Ok(())
}

#[test]
fn parser_rejects_private_or_symmetric_header_jwk_members() -> IssuerResult<()> {
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
        let mut jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": bytes_to_base64url(&[7_u8; 32])
        });
        jwk[private_member] = json!("must-not-cross-public-boundary");
        let jwt = proof_jwt(
            json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "jwk": jwk
            }),
            json!({ "iat": IAT, "nonce": "nonce-1", "aud": "https://issuer.example" }),
        )?;
        let result = CompactProofJwtParser::default().parse_unverified(&jwt);
        assert_eq!(
            result.err().map(|error| error.status()),
            Some(IssuerStatus::InvalidProof),
            "private JWK member {private_member} was accepted"
        );
    }
    Ok(())
}

#[test]
fn parser_rejects_draft_typ_value() -> IssuerResult<()> {
    // The draft-era `typ: "JWT"` is rejected; only `openid4vci-proof+jwt` is valid.
    let jwt = proof_jwt(
        json!({ "alg": "ES256", "typ": "JWT" }),
        json!({ "iat": IAT, "nonce": "nonce-1", "aud": "https://issuer.example" }),
    )?;
    let result = CompactProofJwtParser::default().parse_unverified(&jwt);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn parser_rejects_missing_typ() -> IssuerResult<()> {
    let jwt = proof_jwt(
        json!({ "alg": "ES256" }),
        json!({ "iat": IAT, "nonce": "nonce-1", "aud": "https://issuer.example" }),
    )?;
    let result = CompactProofJwtParser::default().parse_unverified(&jwt);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn parser_rejects_unsupported_critical_headers_and_unconsumed_trust_chain() -> IssuerResult<()> {
    for header in [
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": "proof-key-1",
            "crit": ["future-extension"]
        }),
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": "proof-key-1",
            "b64": true
        }),
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": "proof-key-1",
            "trust_chain": ["signed-entity-statement"]
        }),
    ] {
        let jwt = proof_jwt(
            header,
            json!({ "iat": IAT, "nonce": "nonce-1", "aud": "https://issuer.example" }),
        )?;
        assert_eq!(
            CompactProofJwtParser::default()
                .parse_unverified(&jwt)
                .err()
                .map(|error| error.status()),
            Some(IssuerStatus::InvalidProof)
        );
    }
    Ok(())
}

#[test]
fn parser_rejects_missing_iat() -> IssuerResult<()> {
    // OpenID4VCI 1.0 Appendix F.1: `iat` is REQUIRED.
    let jwt = proof_jwt(
        json!({ "alg": "ES256", "typ": "openid4vci-proof+jwt" }),
        json!({ "nonce": "nonce-1", "aud": "https://issuer.example" }),
    )?;
    let result = CompactProofJwtParser::default().parse_unverified(&jwt);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn parser_rejects_mutually_exclusive_binding_headers() -> IssuerResult<()> {
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": bytes_to_base64url(&[7_u8; 32])
    });
    for conflicting_bindings in [
        json!({"kid": "proof-key-1", "jwk": jwk}),
        json!({"kid": "proof-key-1", "x5c": ["certificate"]}),
        json!({"jwk": jwk, "x5c": ["certificate"]}),
    ] {
        let mut header = json!({
            "alg": "EdDSA",
            "typ": "openid4vci-proof+jwt"
        });
        let header_object = header
            .as_object_mut()
            .ok_or(openid4vci_issuer::IssuerError::new(
                IssuerStatus::EncodingFailed,
            ))?;
        let binding_object =
            conflicting_bindings
                .as_object()
                .ok_or(openid4vci_issuer::IssuerError::new(
                    IssuerStatus::EncodingFailed,
                ))?;
        header_object.extend(binding_object.clone());
        let jwt = proof_jwt(
            header,
            json!({ "iat": IAT, "nonce": "nonce-1", "aud": "https://issuer.example" }),
        )?;
        let result = CompactProofJwtParser::default().parse_unverified(&jwt);
        assert_eq!(
            result.err().map(|error| error.status()),
            Some(IssuerStatus::InvalidProof)
        );
    }
    Ok(())
}

#[test]
fn parser_rejects_none_algorithm() -> IssuerResult<()> {
    let jwt = proof_jwt(
        json!({ "alg": "none" }),
        json!({ "iat": IAT, "nonce": "nonce-1", "aud": "https://issuer.example" }),
    )?;
    let result = CompactProofJwtParser::default().parse_unverified(&jwt);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn parser_rejects_oversized_proof_before_decoding() {
    let oversized = "a".repeat(DEFAULT_MAX_PROOF_JWT_BYTES.saturating_add(1));
    let result = CompactProofJwtParser::default().parse_unverified(&oversized);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
}

#[test]
fn parser_rejects_duplicate_header_and_claim_members() {
    let duplicate_header = proof_jwt_text(
        r#"{"alg":"ES256","alg":"EdDSA","typ":"openid4vci-proof+jwt"}"#,
        r#"{"iat":1700000000,"aud":"https://issuer.example"}"#,
    );
    let duplicate_claim = proof_jwt_text(
        r#"{"alg":"ES256","typ":"openid4vci-proof+jwt"}"#,
        r#"{"iat":1700000000,"iat":1700000001,"aud":"https://issuer.example"}"#,
    );

    for jwt in [duplicate_header, duplicate_claim] {
        let result = CompactProofJwtParser::default().parse_unverified(&jwt);
        assert_eq!(
            result.err().map(|error| error.status()),
            Some(IssuerStatus::InvalidProof)
        );
    }
}

#[test]
fn parser_rejects_excessive_json_nesting() {
    let mut nested = "0".to_owned();
    for _ in 0..140 {
        nested = format!("[{nested}]");
    }
    let payload =
        format!(r#"{{"iat":1700000000,"aud":"https://issuer.example","extension":{nested}}}"#);
    let jwt = proof_jwt_text(r#"{"alg":"ES256","typ":"openid4vci-proof+jwt"}"#, &payload);

    let result = CompactProofJwtParser::default().parse_unverified(&jwt);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
}

#[test]
fn parser_rejects_oversized_decoded_header_segment() {
    let padding = "a".repeat(8_192);
    let header =
        format!(r#"{{"alg":"ES256","typ":"openid4vci-proof+jwt","extension":"{padding}"}}"#);
    let jwt = proof_jwt_text(
        &header,
        r#"{"iat":1700000000,"aud":"https://issuer.example"}"#,
    );
    assert!(jwt.len() < DEFAULT_MAX_PROOF_JWT_BYTES);

    let result = CompactProofJwtParser::default().parse_unverified(&jwt);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
}

#[test]
fn parser_rejects_generated_malformed_compact_jwts() -> IssuerResult<()> {
    let bad_json = bytes_to_base64url(b"not-json");
    let valid_header = segment(&json!({
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt"
    }))?;
    let valid_payload = segment(&json!({"iat": IAT}))?;
    let cases = [
        "".to_owned(),
        " a.b.c".to_owned(),
        "a.b.c ".to_owned(),
        "a".to_owned(),
        "a.b".to_owned(),
        "a.b.c.d".to_owned(),
        ".b.c".to_owned(),
        "a..c".to_owned(),
        "a.b.".to_owned(),
        "%%%%.b.c".to_owned(),
        [bad_json.as_str(), valid_payload.as_str(), "sig"].join("."),
        [valid_header.as_str(), bad_json.as_str(), "sig"].join("."),
    ];

    for jwt in cases {
        let result = CompactProofJwtParser::default().parse_unverified(&jwt);
        assert_eq!(
            result.err().map(|error| error.status()),
            Some(IssuerStatus::InvalidProof)
        );
    }
    Ok(())
}

#[test]
fn common_claim_validation_rejects_missing_nonce_when_required() -> IssuerResult<()> {
    let jwt = proof_jwt(
        json!({ "alg": "EdDSA", "typ": "openid4vci-proof+jwt", "kid": "proof-key-1" }),
        json!({ "iat": IAT, "aud": "https://issuer.example" }),
    )?;
    let claims = CompactProofJwtParser::default().parse_unverified(&jwt)?;
    let result = validate_common_proof_claims(&claims, &context());
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn common_claim_validation_rejects_wrong_audience() -> IssuerResult<()> {
    let jwt = proof_jwt(
        json!({ "alg": "EdDSA", "typ": "openid4vci-proof+jwt", "kid": "proof-key-1" }),
        json!({ "iat": IAT, "nonce": "nonce-1", "aud": "https://other.example" }),
    )?;
    let claims = CompactProofJwtParser::default().parse_unverified(&jwt)?;
    let result = validate_common_proof_claims(&claims, &context());
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}
