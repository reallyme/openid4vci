// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Final-spec OpenID4VCI wire-shape tests.

use std::collections::BTreeMap;

use reallyme_openid4vci_types::{
    build_credential_offer_uri, parse_credential_offer_uri, CredentialConfiguration,
    CredentialEnvelope, CredentialErrorCode, CredentialErrorResponse, CredentialFormat,
    CredentialOffer, CredentialRequest, CredentialResponse, DeferredCredentialErrorCode,
    DeferredCredentialErrorResponse, DeferredCredentialRequest, IssuerMetadata,
    KeyAttestationsRequired, NonceResponse, NotificationErrorCode, NotificationErrorResponse,
    NotificationEvent, NotificationRequest, OpenId4VciError, ParsedCredentialOffer,
    ProofTypeMetadata, Proofs, Reason, TxCode, TxCodeInputMode, MAX_CREDENTIAL_OFFER_URI_BYTES,
    MAX_CREDENTIAL_RESPONSE_JSON_BYTES,
};
use serde_json::{json, Value};

#[test]
fn credential_request_requires_exactly_one_selector() {
    let both = r#"{"credential_configuration_id":"pid","credential_identifier":"abc"}"#;
    let missing = r#"{"proofs":{"jwt":["a.b.c"]}}"#;

    assert_reason(
        CredentialRequest::parse_json(both),
        Reason::InvalidCredentialSelector,
    );
    assert_reason(
        CredentialRequest::parse_json(missing),
        Reason::InvalidCredentialSelector,
    );
}

#[test]
fn oversized_json_body_is_rejected_before_shape_validation() {
    let oversized = " ".repeat((64 * 1024) + 1);
    assert_reason(
        CredentialRequest::parse_json(&oversized),
        Reason::PayloadTooLarge,
    );
}

#[test]
fn batch_credential_response_uses_its_protocol_specific_bounded_limit() {
    let credential = "a".repeat(70 * 1024);
    let body = json!({"credentials": [{"credential": credential}]}).to_string();
    let parsed = CredentialResponse::parse_json(&body);
    assert!(parsed.is_ok());

    let oversized = " ".repeat(MAX_CREDENTIAL_RESPONSE_JSON_BYTES + 1);
    assert_reason(
        CredentialResponse::parse_json(&oversized),
        Reason::PayloadTooLarge,
    );
}

#[test]
fn deferred_request_json_is_bounded_and_validated() {
    let valid = r#"{"transaction_id":"transaction-1"}"#;
    let parsed = DeferredCredentialRequest::parse_json(valid);
    assert!(parsed.is_ok());

    let oversized = " ".repeat(64 * 1024 + 1);
    assert_eq!(
        DeferredCredentialRequest::parse_json(&oversized),
        Err(OpenId4VciError::new(Reason::PayloadTooLarge))
    );
}

#[test]
fn deeply_nested_json_body_is_rejected() {
    let body = deeply_nested_array(512);
    assert_reason(CredentialRequest::parse_json(&body), Reason::InvalidJson);
}

#[test]
fn duplicate_json_members_are_rejected_before_typed_deserialization() {
    let body = r#"{
        "credential_configuration_id":"pid",
        "credential_configuration_id":"other"
    }"#;
    assert_reason(CredentialRequest::parse_json(body), Reason::InvalidJson);
}

#[test]
fn trailing_json_value_is_rejected_before_typed_deserialization() {
    let body = r#"{"credential_configuration_id":"pid"}{}"#;
    assert_reason(CredentialRequest::parse_json(body), Reason::InvalidJson);
}

#[test]
fn extensible_documents_ignore_unknown_members_but_security_objects_remain_closed() {
    let request = r#"{
        "credential_configuration_id":"pid",
        "proofs":{"jwt":["a.b.c"],"unexpected":true}
    }"#;
    assert_reason(CredentialRequest::parse_json(request), Reason::InvalidJson);

    for extension in [json!(true), json!({"enabled": true}), json!([1, 2, 3])] {
        let response = json!({
            "credentials": [{"credential": "vc"}],
            "extension": extension.clone()
        });
        assert!(CredentialResponse::parse_json(&response.to_string()).is_ok());

        let wrapped_credential = json!({
            "credentials": [{"credential": "vc", "extension": extension.clone()}]
        });
        assert!(CredentialResponse::parse_json(&wrapped_credential.to_string()).is_ok());

        let deferred = json!({
            "transaction_id": "transaction-1",
            "extension": extension.clone()
        });
        assert!(DeferredCredentialRequest::parse_json(&deferred.to_string()).is_ok());

        let offer = json!({
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ["pid"],
            "grants": {"extension": extension.clone()},
            "extension": extension
        });
        assert!(CredentialOffer::parse_json(&offer.to_string()).is_ok());
    }

    let offer = r#"{
        "credential_issuer":"https://issuer.example",
        "credential_configuration_ids":["pid"],
        "grants":{"authorization_code":{"unexpected":true}}
    }"#;
    assert_reason(CredentialOffer::parse_json(offer), Reason::InvalidJson);

    let deferred_encryption = r#"{
        "transaction_id":"transaction-1",
        "credential_response_encryption":{
            "jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"},
            "enc":"A256GCM",
            "unexpected":true
        }
    }"#;
    assert_reason(
        DeferredCredentialRequest::parse_json(deferred_encryption),
        Reason::InvalidJson,
    );

    let nonce = r#"{"c_nonce":"nonce-1","unexpected":true}"#;
    assert_reason(NonceResponse::parse_json(nonce), Reason::InvalidJson);

    let credential_error = r#"{"error":"invalid_credential_request","unexpected":true}"#;
    assert_reason(
        CredentialErrorResponse::parse_json(credential_error),
        Reason::InvalidJson,
    );

    let deferred_error = r#"{"error":"invalid_credential_request","unexpected":true}"#;
    assert_reason(
        DeferredCredentialErrorResponse::parse_json(deferred_error),
        Reason::InvalidJson,
    );

    let notification_error = r#"{"error":"invalid_notification_request","unexpected":true}"#;
    assert_reason(
        NotificationErrorResponse::parse_json(notification_error),
        Reason::InvalidJson,
    );
}

#[test]
fn credential_response_rejects_removed_draft_shapes() {
    let top_level_credential = r#"{"credential":"vc"}"#;
    assert_reason(
        CredentialResponse::parse_json(top_level_credential),
        Reason::InvalidJson,
    );

    let raw_array_entry = r#"{"credentials":["vc"]}"#;
    assert_reason(
        CredentialResponse::parse_json(raw_array_entry),
        Reason::InvalidJson,
    );
}

#[test]
fn endpoint_specific_error_vocabularies_round_trip_every_final_code() -> Result<(), OpenId4VciError>
{
    for error in [
        CredentialErrorCode::InvalidCredentialRequest,
        CredentialErrorCode::InvalidProof,
        CredentialErrorCode::InvalidNonce,
        CredentialErrorCode::UnknownCredentialConfiguration,
        CredentialErrorCode::UnknownCredentialIdentifier,
        CredentialErrorCode::InvalidEncryptionParameters,
        CredentialErrorCode::CredentialRequestDenied,
    ] {
        let response = CredentialErrorResponse {
            error,
            error_description: None,
        };
        assert_eq!(
            CredentialErrorResponse::parse_json(&response.to_json()?)?,
            response
        );
    }
    for error in [
        DeferredCredentialErrorCode::InvalidCredentialRequest,
        DeferredCredentialErrorCode::InvalidTransactionId,
        DeferredCredentialErrorCode::InvalidEncryptionParameters,
        DeferredCredentialErrorCode::CredentialRequestDenied,
    ] {
        let response = DeferredCredentialErrorResponse { error };
        assert_eq!(
            DeferredCredentialErrorResponse::parse_json(&response.to_json()?)?,
            response
        );
    }
    for error in [
        NotificationErrorCode::InvalidNotificationRequest,
        NotificationErrorCode::InvalidNotificationId,
    ] {
        let response = NotificationErrorResponse { error };
        assert_eq!(
            NotificationErrorResponse::parse_json(&response.to_json()?)?,
            response
        );
    }
    Ok(())
}

#[test]
fn issuer_metadata_explicitly_allows_extension_members() -> Result<(), OpenId4VciError> {
    let metadata = r#"{
        "credential_issuer":"https://issuer.example",
        "credential_endpoint":"https://issuer.example/credential",
        "credential_configurations_supported":{
            "pid":{
                "format":"dc+sd-jwt",
                "vct":"https://credentials.example/pid",
                "x-configuration-extension":{"enabled":true}
            }
        },
        "x-issuer-extension":{"version":1}
    }"#;

    let parsed = IssuerMetadata::parse_json(metadata)?;
    assert_eq!(parsed.credential_issuer, "https://issuer.example");
    Ok(())
}

#[test]
fn oversized_serialized_json_is_rejected() -> Result<(), OpenId4VciError> {
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope::compact("a".repeat(262_144))],
        None,
    )?;
    assert_reason(response.to_json(), Reason::PayloadTooLarge);
    Ok(())
}

#[test]
fn proofs_allow_multiple_jwt_but_single_attestation() {
    let jwt = Proofs {
        jwt: vec!["a.b.c".to_owned(), "d.e.f".to_owned()],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    assert!(jwt.validate().is_ok());

    let attestation = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec!["a.b.c".to_owned()],
    };
    assert!(attestation.validate().is_ok());

    let two_attestations = Proofs {
        jwt: Vec::new(),
        di_vp: Vec::new(),
        attestation: vec!["a.b.c".to_owned(), "d.e.f".to_owned()],
    };
    assert_reason(two_attestations.validate(), Reason::InvalidProofs);
}

#[test]
fn nonce_response_contains_only_c_nonce() -> Result<(), OpenId4VciError> {
    let response = NonceResponse::new("nonce-1".to_owned())?;
    let json = response.to_json()?;
    assert_eq!(json, r#"{"c_nonce":"nonce-1"}"#);
    Ok(())
}

#[test]
fn notification_description_rejects_non_ascii() {
    let request = NotificationRequest {
        notification_id: "n-1".to_owned(),
        event: NotificationEvent::CredentialFailure,
        event_description: Some("not ascii: é".to_owned()),
    };
    assert_reason(request.validate(), Reason::InvalidNotification);
}

#[test]
fn issuer_metadata_rejects_batch_endpoint_extension() {
    let raw = serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "batch_credential_endpoint": "https://issuer.example/batch"
    });
    assert_reason(
        IssuerMetadata::parse_json(&raw.to_string()),
        Reason::InvalidJson,
    );
}

#[test]
fn pre_authorized_offer_uses_tx_code_without_user_pin() -> Result<(), OpenId4VciError> {
    let offer = CredentialOffer::pre_authorized_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        "pre-authorized-code-sensitive".to_owned(),
        Some(TxCode {
            input_mode: Some(TxCodeInputMode::Numeric),
            length: Some(6),
            description: Some("transaction-description-sensitive".to_owned()),
        }),
    )?;
    let debug = format!("{offer:?}");
    assert!(!debug.contains("pre-authorized-code-sensitive"));
    assert!(!debug.contains("transaction-description-sensitive"));
    let json = offer.to_json()?;
    assert!(json.contains("tx_code"));
    assert!(!json.contains("user_pin"));
    Ok(())
}

#[test]
fn issuer_metadata_accepts_final_minimum() -> Result<(), OpenId4VciError> {
    let mut configurations = BTreeMap::new();
    configurations.insert(
        "pid".to_owned(),
        CredentialConfiguration {
            format: CredentialFormat::SdJwtVc,
            scope: Some("pid".to_owned()),
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            vct: Some("https://credentials.example/pid".to_owned()),
            doctype: None,
            credential_metadata: Some(Value::Object(serde_json::Map::new())),
        },
    );
    let metadata = IssuerMetadata {
        credential_issuer: "https://issuer.example".to_owned(),
        authorization_servers: None,
        credential_endpoint: "https://issuer.example/credential".to_owned(),
        nonce_endpoint: Some("https://issuer.example/nonce".to_owned()),
        deferred_credential_endpoint: None,
        notification_endpoint: Some("https://issuer.example/notification".to_owned()),
        preferred_client_status_period: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        batch_credential_issuance: None,
        credential_configurations_supported: configurations,
    };
    metadata.validate()
}

#[test]
fn metadata_builder_derives_proof_metadata_without_batch_endpoint() -> Result<(), OpenId4VciError> {
    let metadata = IssuerMetadata::builder(
        "https://issuer.example".to_owned(),
        "https://issuer.example/credential".to_owned(),
    )
    .nonce_endpoint("https://issuer.example/nonce".to_owned())
    .notification_endpoint("https://issuer.example/notification".to_owned())
    .proof_required(true)
    .jwt_proof_signing_alg_values_supported(vec!["EdDSA".to_owned()])
    .credential_configuration(
        "pid".to_owned(),
        CredentialConfiguration {
            scope: Some("pid".to_owned()),
            ..CredentialConfiguration::new(CredentialFormat::SdJwtVc)
        },
    )
    .build()?;

    let json = metadata.to_json()?;
    assert!(json.contains("proof_types_supported"));
    assert!(!json.contains("batch_credential_endpoint"));
    assert_eq!(
        metadata
            .credential_configurations_supported
            .get("pid")
            .and_then(|configuration| configuration.proof_types_supported.as_ref())
            .and_then(|proof_types| proof_types.get("jwt"))
            .map(|metadata| metadata.proof_signing_alg_values_supported.as_slice()),
        Some(&["EdDSA".to_owned()][..])
    );
    Ok(())
}

#[test]
fn metadata_accepts_eudi_wua_status_period_preferences() -> Result<(), OpenId4VciError> {
    let mut proof_types = BTreeMap::new();
    proof_types.insert(
        "jwt".to_owned(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_owned()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: Some(vec!["high".to_owned()]),
                user_authentication: None,
                preferred_key_storage_status_period: Some(2_678_400),
            }),
        },
    );

    let metadata = IssuerMetadata::builder(
        "https://issuer.example".to_owned(),
        "https://issuer.example/credential".to_owned(),
    )
    .nonce_endpoint("https://issuer.example/nonce".to_owned())
    .preferred_client_status_period(2_678_400)
    .credential_configuration(
        "pid".to_owned(),
        CredentialConfiguration {
            proof_types_supported: Some(proof_types),
            ..CredentialConfiguration::new(CredentialFormat::SdJwtVc)
        },
    )
    .build()?;

    let json = metadata.to_json()?;
    let reparsed = IssuerMetadata::parse_json(&json)?;
    assert_eq!(reparsed.preferred_client_status_period, Some(2_678_400));
    assert!(json.contains("preferred_key_storage_status_period"));
    Ok(())
}

#[test]
fn metadata_builder_allows_proofs_without_optional_nonce_endpoint() {
    let result = IssuerMetadata::builder(
        "https://issuer.example".to_owned(),
        "https://issuer.example/credential".to_owned(),
    )
    .proof_required(true)
    .credential_configuration(
        "pid".to_owned(),
        CredentialConfiguration::new(CredentialFormat::SdJwtVc),
    )
    .build();

    assert!(result.is_ok());
}

#[test]
fn metadata_accepts_batch_issuance_and_rejects_batch_size_below_two() -> Result<(), OpenId4VciError>
{
    let valid = IssuerMetadata::builder(
        "https://issuer.example".to_owned(),
        "https://issuer.example/credential".to_owned(),
    )
    .batch_credential_issuance(2)
    .credential_configuration(
        "pid".to_owned(),
        CredentialConfiguration::new(CredentialFormat::SdJwtVc),
    )
    .build()?;
    assert!(valid.to_json()?.contains("batch_credential_issuance"));

    let invalid = IssuerMetadata::builder(
        "https://issuer.example".to_owned(),
        "https://issuer.example/credential".to_owned(),
    )
    .batch_credential_issuance(1)
    .credential_configuration(
        "pid".to_owned(),
        CredentialConfiguration::new(CredentialFormat::SdJwtVc),
    )
    .build();
    assert_reason(invalid, Reason::InvalidString);
    Ok(())
}

#[test]
fn credential_response_rejects_interval_with_credentials() {
    // OpenID4VCI 1.0 §8.3: `interval` MUST NOT be present alongside `credentials`.
    let body = r#"{"credentials":[{"credential":"vc"}],"interval":5}"#;
    assert_reason(
        CredentialResponse::parse_json(body),
        Reason::InvalidCredentialResponse,
    );
}

#[test]
fn credential_offer_rejects_issuer_identifier_with_fragment() {
    // OpenID4VCI 1.0 §12.2.1: the Credential Issuer Identifier has no fragment.
    let body = r#"{"credential_issuer":"https://issuer.example#frag","credential_configuration_ids":["pid"]}"#;
    assert_reason(CredentialOffer::parse_json(body), Reason::InvalidUrl);
}

#[test]
fn credential_offer_uri_rejects_multiple_offer_sources() -> Result<(), OpenId4VciError> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )?
    .to_uri()?;
    let both_sources = [
        offer.as_str(),
        "&credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1",
    ]
    .concat();

    assert_reason(
        parse_credential_offer_uri(&both_sources),
        Reason::InvalidUrl,
    );
    Ok(())
}

#[test]
fn credential_offer_uri_rejects_duplicate_offer_parameters() {
    let uri = [
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fone",
        "&credential_offer_uri=https%3A%2F%2Fissuer.example%2Ftwo",
    ]
    .concat();

    assert_reason(parse_credential_offer_uri(&uri), Reason::InvalidUrl);
}

#[test]
fn credential_offer_uri_rejects_oversized_input_before_decoding() {
    let uri = [
        "openid-credential-offer://?credential_offer=%",
        &"4".repeat(MAX_CREDENTIAL_OFFER_URI_BYTES),
    ]
    .concat();

    assert_reason(parse_credential_offer_uri(&uri), Reason::InvalidUrl);
}

#[test]
fn credential_offer_uri_builder_rejects_oversized_output() {
    let offer_json = "x".repeat(MAX_CREDENTIAL_OFFER_URI_BYTES);
    assert_reason(
        build_credential_offer_uri("openid-credential-offer://", &offer_json),
        Reason::InvalidUrl,
    );
}

#[test]
fn credential_offer_uri_accepts_single_reference() -> Result<(), OpenId4VciError> {
    let uri =
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1";
    let parsed = parse_credential_offer_uri(uri)?;
    assert!(matches!(
        parsed,
        ParsedCredentialOffer::Reference(reference)
            if reference == "https://issuer.example/offer/1"
    ));
    Ok(())
}

#[test]
fn generated_offer_uri_source_combinations_fail_closed() -> Result<(), OpenId4VciError> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )?
    .to_uri()?;
    let reference = "credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1";
    let inline = offer
        .split_once('?')
        .map(|(_, query)| query)
        .ok_or_else(|| OpenId4VciError::new(Reason::InvalidUrl))?;
    let cases = [
        ("".to_owned(), Reason::MissingRequiredField),
        ("credential_offer=%E0%A4%A".to_owned(), Reason::InvalidUrl),
        ([inline, inline].join("&"), Reason::InvalidUrl),
        ([reference, reference].join("&"), Reason::InvalidUrl),
        ([inline, reference].join("&"), Reason::InvalidUrl),
        ([reference, inline].join("&"), Reason::InvalidUrl),
    ];

    for (query, reason) in cases {
        assert_reason(
            parse_credential_offer_uri(&["openid-credential-offer://?", query.as_str()].concat()),
            reason,
        );
    }
    Ok(())
}

#[test]
fn tx_code_description_rejects_over_300_characters() {
    // OpenID4VCI 1.0 §4.1.1: tx_code description MUST NOT exceed 300 characters.
    let tx_code = TxCode {
        input_mode: Some(TxCodeInputMode::Numeric),
        length: Some(6),
        description: Some("a".repeat(301)),
    };
    assert_reason(tx_code.validate(), Reason::InvalidString);
}

#[test]
fn nonce_and_notification_debug_output_is_privacy_safe() -> Result<(), OpenId4VciError> {
    let nonce = NonceResponse::new("nonce-sensitive".to_owned())?;
    let notification = NotificationRequest {
        notification_id: "notification-sensitive".to_owned(),
        event: NotificationEvent::CredentialFailure,
        event_description: Some("description-sensitive".to_owned()),
    };
    let error = CredentialErrorResponse {
        error: CredentialErrorCode::InvalidProof,
        error_description: Some("description-sensitive".to_owned()),
    };

    let debug = format!("{nonce:?} {notification:?} {error:?}");
    assert!(!debug.contains("nonce-sensitive"));
    assert!(!debug.contains("notification-sensitive"));
    assert!(!debug.contains("description-sensitive"));
    assert!(debug.contains("<redacted>"));
    Ok(())
}

#[test]
fn credential_response_debug_output_is_privacy_safe() -> Result<(), OpenId4VciError> {
    let response = CredentialResponse::immediate(
        vec![CredentialEnvelope::json(
            json!({"given_name": "credential-pii-sensitive"}),
        )],
        Some("notification-id-sensitive".to_owned()),
    )?;
    let deferred = DeferredCredentialRequest {
        transaction_id: "transaction-id-sensitive".to_owned(),
        credential_response_encryption: None,
    };

    let debug = format!("{response:?} {deferred:?}");
    assert!(!debug.contains("credential-pii-sensitive"));
    assert!(!debug.contains("notification-id-sensitive"));
    assert!(!debug.contains("transaction-id-sensitive"));
    assert!(debug.contains("credential_count"));
    Ok(())
}

fn assert_reason<T>(result: Result<T, OpenId4VciError>, expected: Reason) {
    assert_eq!(result.err().map(|error| error.reason()), Some(expected));
}

fn deeply_nested_array(depth: usize) -> String {
    let mut value = String::with_capacity(depth.saturating_mul(2).saturating_add(1));
    for _ in 0..depth {
        value.push('[');
    }
    value.push('0');
    for _ in 0..depth {
        value.push(']');
    }
    value
}
