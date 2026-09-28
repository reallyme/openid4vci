// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::json;

use crate::error::OpenId4VciError;

use super::{CredentialRequest, CredentialResponseEncryption, Proofs, PublicJwk};
use crate::{
    CredentialRequestEncryptionMetadata, CredentialResponseEncryptionMetadata, PublicJwkSet,
};

#[test]
fn credential_request_ignores_unrecognized_top_level_parameters() -> Result<(), OpenId4VciError> {
    let request = CredentialRequest::parse_json(
        r#"{"credential_identifier":"credential-1","proofs":{"jwt":["a.b.c"]},"extension":{"enabled":true}}"#,
    )?;

    assert_eq!(
        request.credential_identifier.as_deref(),
        Some("credential-1")
    );
    Ok(())
}

#[test]
fn credential_request_rejects_unrecognized_nested_proof_parameters() {
    let result = CredentialRequest::parse_json(
        r#"{"credential_identifier":"credential-1","proofs":{"jwt":["a.b.c"],"extension":true}}"#,
    );

    assert!(result.is_err());
}

#[test]
fn request_debug_redacts_proofs_jwk_and_identifiers() -> Result<(), OpenId4VciError> {
    let request = CredentialRequest {
        credential_configuration_id: None,
        credential_identifier: Some("credential-id-sensitive".to_owned()),
        proofs: Some(Proofs {
            jwt: vec!["proof-sensitive".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: Some(CredentialResponseEncryption {
            jwk: PublicJwk::new(json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x-sensitive",
                "y": "public-y-sensitive"
            }))?,
            enc: "A256GCM".to_owned(),
            zip: None,
        }),
    };

    let debug = format!("{request:?}");
    assert!(!debug.contains("credential-id-sensitive"));
    assert!(!debug.contains("proof-sensitive"));
    assert!(!debug.contains("public-x-sensitive"));
    assert!(debug.contains("jwt_count"));
    Ok(())
}

#[test]
fn response_encryption_rejects_private_and_symmetric_jwks() {
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
        let mut jwk = json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y"});
        jwk[private_member] = json!("secret");
        assert!(PublicJwk::new(jwk).is_err());
    }
    assert!(PublicJwk::new(json!({"kty": "oct", "public": "not-public-key-material"})).is_err());
    assert!(PublicJwk::new(
        json!({"kty": "EC", "extension": {"nested": [{"privateKey": "secret"}]}})
    )
    .is_err());
}

#[test]
fn public_jwk_deserialization_rejects_duplicate_members_and_redacts_debug() {
    let duplicate = serde_json::from_str::<PublicJwk>(
        r#"{"kty":"EC","kty":"RSA","crv":"P-256","x":"x","y":"y"}"#,
    );
    assert!(duplicate.is_err());

    let public = PublicJwk::new(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "public-x-sensitive",
        "y": "public-y-sensitive"
    }));
    assert!(public.is_ok());
    if let Ok(public) = public {
        let debug = format!("{public:?}");
        assert_eq!(debug, "PublicJwk(<redacted>)");
        assert!(!debug.contains("public-x-sensitive"));
    }
}

#[test]
fn response_encryption_serialization_cannot_emit_private_members() -> Result<(), OpenId4VciError> {
    let encryption = CredentialResponseEncryption {
        jwk: PublicJwk::new(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "public-x",
            "y": "public-y"
        }))?,
        enc: "A256GCM".to_owned(),
        zip: None,
    };
    let wire = serde_json::to_vec(&encryption)
        .map_err(|_| OpenId4VciError::new(crate::Reason::InvalidJson))?;
    let wire_text = core::str::from_utf8(&wire)
        .map_err(|_| OpenId4VciError::new(crate::Reason::InvalidJson))?;

    for forbidden in ["\"d\"", "\"p\"", "\"q\"", "\"k\"", "secret"] {
        assert!(!wire_text.contains(forbidden));
    }
    Ok(())
}

#[test]
fn request_encryption_metadata_rejects_malformed_jwk_sets_and_empty_zip() {
    assert!(PublicJwkSet::from_value(json!({"keys": []})).is_err());
    assert!(PublicJwkSet::from_value(json!({
        "keys": [{"kty":"EC","kid":"key-1","crv":"P-256","x":"x","y":"y"}]
    }))
    .is_err());
    assert!(PublicJwkSet::from_value(json!({
        "keys": [
            {"kty":"EC","kid":"key-1","alg":"ECDH-ES","crv":"P-256","x":"x","y":"y"},
            {"kty":"EC","kid":"key-1","alg":"ECDH-ES","crv":"P-256","x":"x2","y":"y2"}
        ]
    }))
    .is_err());

    let keys = PublicJwkSet::from_value(json!({
        "keys": [
            {"kty":"EC","kid":"key-1","alg":"ECDH-ES","crv":"P-256","x":"x","y":"y"}
        ]
    }));
    assert!(keys.is_ok());
    if let Ok(keys) = keys {
        let metadata = CredentialRequestEncryptionMetadata {
            alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
            enc_values_supported: vec!["A256GCM".to_owned()],
            zip_values_supported: Some(Vec::new()),
            jwks: keys,
            encryption_required: false,
        };
        assert!(metadata.validate().is_err());
    }
}

#[test]
fn response_encryption_metadata_always_requires_advertised_algorithms() {
    for metadata in [
        CredentialResponseEncryptionMetadata {
            alg_values_supported: None,
            enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            zip_values_supported: None,
            encryption_required: false,
        },
        CredentialResponseEncryptionMetadata {
            alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
            enc_values_supported: None,
            zip_values_supported: None,
            encryption_required: false,
        },
    ] {
        assert!(metadata.validate().is_err());
    }
}

#[test]
fn proof_owner_clears_all_string_bearing_proof_forms() {
    let mut proofs = Proofs {
        jwt: vec!["proof-sensitive".to_owned()],
        di_vp: vec![json!({"holder": {"name": "pii-sensitive"}})],
        attestation: vec!["attestation-sensitive".to_owned()],
    };

    proofs.zeroize_sensitive();

    assert!(proofs.jwt.is_empty());
    assert!(proofs.attestation.is_empty());
    assert_eq!(proofs.di_vp[0]["holder"]["name"].as_str(), Some(""));
}
