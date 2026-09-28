// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Round-trip coverage for the generated Buffa OpenID4VCI boundary.

use buffa::{EnumValue, Message};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::convert::{
    credential_envelope_from_proto, credential_envelope_to_proto, credential_offer_from_proto,
    credential_offer_to_proto, credential_request_from_proto, credential_request_to_proto,
    credential_response_from_proto, credential_response_to_proto, issuer_metadata_from_proto,
    issuer_metadata_to_proto, notification_request_from_proto, parsed_credential_offer_from_proto,
    parsed_credential_offer_to_proto, problem_details_from_proto, problem_details_to_proto,
    ProtoError,
};
use openid4vci_proto_codec::{
    decode_proto, encode_proto, json_to_proto, proto_to_json, ProtoCodecError,
    MAX_OPENID4VCI_EMBEDDED_JSON_BYTES, MAX_OPENID4VCI_PROTO_JSON_BYTES,
    MAX_OPENID4VCI_PROTO_MESSAGE_BYTES, OPENID4VCI_EMBEDDED_JSON_RECURSION_LIMIT,
    OPENID4VCI_PROTO_JSON_RECURSION_LIMIT,
};
use openid4vci_types::{
    BatchCredentialIssuance, CredentialConfiguration, CredentialEnvelope, CredentialFormat,
    CredentialOffer, CredentialPayload, CredentialRequest, CredentialRequestEncryptionMetadata,
    CredentialResponse, CredentialResponseEncryption, CredentialResponseEncryptionMetadata,
    CredentialSigningAlg, IssuerMetadata, KeyAttestationsRequired, ParsedCredentialOffer,
    PreAuthorizedCodeGrant, ProblemDetails, ProblemType, ProofTypeMetadata, Proofs, PublicJwk,
    PublicJwkSet, TxCode, TxCodeInputMode,
};
use serde_json::json;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestError {
    Codec(ProtoCodecError),
    Conversion(ProtoError),
    Decode,
    UnexpectedValue,
}

impl From<ProtoCodecError> for TestError {
    fn from(value: ProtoCodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<ProtoError> for TestError {
    fn from(value: ProtoError) -> Self {
        Self::Conversion(value)
    }
}

#[test]
fn credential_request_survives_buffa_binary_roundtrip() -> Result<(), TestError> {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid-sd-jwt".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec![
                "holder-proof.jwt".to_owned(),
                "holder-proof-2.jwt".to_owned(),
            ],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: Some(CredentialResponseEncryption {
            jwk: PublicJwk::new(json!({"kty":"EC","crv":"P-256","x":"abc","y":"def"}))
                .map_err(|_| TestError::UnexpectedValue)?,
            enc: "A256GCM".to_owned(),
            zip: Some("DEF".to_owned()),
        }),
    };

    let proto = credential_request_to_proto(&request)?;
    let bytes = encode_proto(&proto)?;
    let decoded: pb::CredentialRequest = decode_proto(&bytes)?;
    let converted = credential_request_from_proto(decoded)?;

    if converted == request {
        Ok(())
    } else {
        Err(TestError::UnexpectedValue)
    }
}

#[test]
fn public_generated_encoders_return_zeroizing_owners() -> Result<(), TestError> {
    let proto = proof_request_proto();
    let binary: Zeroizing<Vec<u8>> = encode_proto(&proto)?;
    let json: Zeroizing<String> = proto_to_json(&proto)?;

    if binary.is_empty() || json.is_empty() {
        Err(TestError::UnexpectedValue)
    } else {
        Ok(())
    }
}

#[test]
fn problem_details_preserve_typed_reason_across_binary_and_json() -> Result<(), TestError> {
    let problem = ProblemDetails::new(
        ProblemType::InvalidProof,
        Some("urn:reallyme:test:problem:1".to_owned()),
    );
    let proto = problem_details_to_proto(&problem)?;
    let bytes = encode_proto(&proto)?;
    let binary: pb::ProblemDetails = decode_proto(&bytes)?;
    let json = proto_to_json(&binary)?;
    let decoded: pb::ProblemDetails = json_to_proto(&json)?;
    let converted = problem_details_from_proto(decoded)?;

    if converted == problem {
        Ok(())
    } else {
        Err(TestError::UnexpectedValue)
    }
}

#[test]
fn problem_details_reject_inconsistent_reason_projection() {
    let mut proto = pb::ProblemDetails::default();
    proto.type_uri = "about:blank".to_owned();
    proto.title = "invalid_proof".to_owned();
    proto.status = 400;
    proto.error = "invalid_nonce".to_owned();
    proto.reason = EnumValue::from(pb::OpenId4VciErrorReason::InvalidProof);

    assert_eq!(
        problem_details_from_proto(proto),
        Err(ProtoError::InvalidWireValue)
    );
}

#[test]
fn oversized_binary_payload_is_rejected_before_decode() {
    let bytes = vec![0_u8; MAX_OPENID4VCI_PROTO_MESSAGE_BYTES + 1];
    let result = decode_proto::<pb::CredentialRequest>(&bytes);

    assert_eq!(result, Err(ProtoCodecError::PayloadTooLarge));
}

#[test]
fn unknown_binary_fields_are_rejected() {
    // Field number 99 is not part of CredentialRequest. Public decoders reject
    // it so old schema versions cannot silently discard security-relevant data.
    let unknown_field = [0x98_u8, 0x06, 0x01];
    let result = decode_proto::<pb::CredentialRequest>(&unknown_field);

    assert_eq!(result, Err(ProtoCodecError::Decode));
}

#[test]
fn oversized_proto_json_is_rejected_before_deserialization() {
    let json = " ".repeat(MAX_OPENID4VCI_PROTO_JSON_BYTES + 1);
    let result = json_to_proto::<pb::CredentialRequest>(&json);

    assert_eq!(result, Err(ProtoCodecError::PayloadTooLarge));
}

#[test]
fn malformed_protojson_inputs_fail_with_typed_errors() {
    let cases = [
        "{",
        r#"{}{}"#,
        r#"{"selector":{"credentialConfigurationId":"pid","credentialConfigurationId":"other"}}"#,
        r#"{"selector":{"credentialConfigurationId":"pid","unknown":true}}"#,
        r#"{"unknown":true}"#,
        r#"{"proofs":{"diVpJson":["%%%"]}}"#,
    ];

    for input in cases {
        assert_eq!(
            json_to_proto::<pb::CredentialRequest>(input),
            Err(ProtoCodecError::JsonDeserialize)
        );
    }

    assert_eq!(
        json_to_proto::<pb::NotificationRequest>(
            r#"{"notificationId":"notification-1","event":"NOTIFICATION_EVENT_NOT_REAL"}"#,
        ),
        Err(ProtoCodecError::JsonDeserialize)
    );
}

#[test]
fn protojson_recursion_limit_is_enforced_before_generated_deserialization() -> Result<(), TestError>
{
    let depth = usize::try_from(OPENID4VCI_PROTO_JSON_RECURSION_LIMIT)
        .map_err(|_| TestError::UnexpectedValue)?;
    let mut input = String::from(r#"{"unknown":"#);
    input.extend(std::iter::repeat_n('[', depth + 1));
    input.push('0');
    input.extend(std::iter::repeat_n(']', depth + 1));
    input.push('}');

    assert_eq!(
        json_to_proto::<pb::CredentialRequest>(&input),
        Err(ProtoCodecError::JsonDeserialize)
    );
    Ok(())
}

#[test]
fn oneof_protojson_rejects_unknown_fields_and_conflicting_variants() {
    assert_eq!(
        json_to_proto::<pb::CredentialSelector>(r#"{"unknown":"value"}"#),
        Err(ProtoCodecError::JsonDeserialize)
    );
    assert_eq!(
        json_to_proto::<pb::CredentialSelector>(
            r#"{"credentialConfigurationId":"pid","credentialIdentifier":"credential-1"}"#,
        ),
        Err(ProtoCodecError::JsonDeserialize)
    );
}

#[test]
fn oversized_binary_output_is_rejected() {
    let proto = pb::CredentialRequest {
        selector: buffa::MessageField::some(pb::CredentialSelector {
            selector: Some(
                pb::credential_selector::Selector::CredentialConfigurationId(
                    "x".repeat(MAX_OPENID4VCI_PROTO_MESSAGE_BYTES),
                ),
            ),
            __buffa_unknown_fields: Default::default(),
        }),
        ..Default::default()
    };

    assert_eq!(encode_proto(&proto), Err(ProtoCodecError::PayloadTooLarge));
}

#[test]
fn oversized_proto_json_output_is_rejected() {
    let proto = pb::CredentialRequest {
        selector: buffa::MessageField::some(pb::CredentialSelector {
            selector: Some(
                pb::credential_selector::Selector::CredentialConfigurationId(
                    "x".repeat(MAX_OPENID4VCI_PROTO_JSON_BYTES),
                ),
            ),
            __buffa_unknown_fields: Default::default(),
        }),
        ..Default::default()
    };

    assert_eq!(proto_to_json(&proto), Err(ProtoCodecError::PayloadTooLarge));
}

#[test]
fn generated_proto_json_uses_same_message_boundary() -> Result<(), TestError> {
    let proto = proof_request_proto();
    let json = proto_to_json(&proto)?;
    let decoded: pb::CredentialRequest = json_to_proto(&json)?;

    if decoded == proto {
        Ok(())
    } else {
        Err(TestError::UnexpectedValue)
    }
}

#[test]
fn credential_offer_preserves_final_tx_code_shape() -> Result<(), TestError> {
    let offer = CredentialOffer {
        credential_issuer: "https://issuer.example".to_owned(),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: Some(openid4vci_types::CredentialOfferGrant {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: "preauth-code".to_owned(),
                tx_code: Some(TxCode {
                    input_mode: Some(TxCodeInputMode::Numeric),
                    length: Some(6),
                    description: Some("Enter the issuer code".to_owned()),
                }),
                authorization_server: None,
            }),
        }),
    };

    let proto = credential_offer_to_proto(&offer);
    let bytes = proto.encode_to_vec();
    let decoded = pb::CredentialOffer::decode_from_slice(&bytes).map_err(|_| TestError::Decode)?;
    let converted = credential_offer_from_proto(decoded)?;

    let converted_grant = converted
        .grants
        .as_ref()
        .and_then(|grants| grants.pre_authorized_code.as_ref());
    let offer_grant = offer
        .grants
        .as_ref()
        .and_then(|grants| grants.pre_authorized_code.as_ref());
    if converted.credential_issuer == offer.credential_issuer
        && converted.credential_configuration_ids == offer.credential_configuration_ids
        && converted_grant.map(|grant| grant.pre_authorized_code.as_str())
            == offer_grant.map(|grant| grant.pre_authorized_code.as_str())
        && converted_grant.and_then(|grant| grant.tx_code.as_ref().map(|code| code.length))
            == offer_grant.and_then(|grant| grant.tx_code.as_ref().map(|code| code.length))
    {
        Ok(())
    } else {
        Err(TestError::UnexpectedValue)
    }
}

#[test]
fn credential_offer_reference_round_trip_preserves_encoded_separators() -> Result<(), TestError> {
    let reference =
        "https://issuer.example/offers/1?locale=en%2DGB&return=https%3A%2F%2Fwallet.example%2Fcb"
            .to_owned();
    let proto =
        parsed_credential_offer_to_proto(&ParsedCredentialOffer::Reference(reference.clone()));
    let converted = parsed_credential_offer_from_proto(proto)?;
    match converted {
        ParsedCredentialOffer::Reference(converted) if converted == reference => Ok(()),
        ParsedCredentialOffer::Reference(_) | ParsedCredentialOffer::Inline(_) => {
            Err(TestError::UnexpectedValue)
        }
    }
}

#[test]
fn credential_offer_reference_rejects_fragments_and_repeated_wrapper_keys() {
    let fragmented = pb::CredentialOfferUri {
        payload: Some(pb::credential_offer_uri::Payload::CredentialOfferUri(
            "https://issuer.example/offer#fragment".to_owned(),
        )),
        __buffa_unknown_fields: Default::default(),
    };
    assert!(parsed_credential_offer_from_proto(fragmented).is_err());

    let repeated = pb::CredentialOfferUri {
        payload: Some(pb::credential_offer_uri::Payload::CredentialOfferUri(
            "https://issuer.example/offer?credential_offer_uri=duplicate".to_owned(),
        )),
        __buffa_unknown_fields: Default::default(),
    };
    let converted = parsed_credential_offer_from_proto(repeated);
    assert!(converted.is_ok());
    if let Ok(ParsedCredentialOffer::Reference(uri)) = converted {
        assert_eq!(
            uri,
            "https://issuer.example/offer?credential_offer_uri=duplicate"
        );
    }
}

fn proof_request_proto() -> pb::CredentialRequest {
    let mut proofs = pb::Proofs::default();
    proofs.jwt = vec!["holder-proof.jwt".to_owned()];
    pb::CredentialRequest {
        selector: buffa::MessageField::some(pb::CredentialSelector {
            selector: Some(
                pb::credential_selector::Selector::CredentialConfigurationId(
                    "pid-sd-jwt".to_owned(),
                ),
            ),
            __buffa_unknown_fields: Default::default(),
        }),
        proofs: buffa::MessageField::some(proofs),
        ..Default::default()
    }
}

#[test]
fn credential_response_maps_compact_and_json_credentials() -> Result<(), TestError> {
    let response = CredentialResponse::immediate(
        vec![
            CredentialEnvelope::compact("compact.sd-jwt".to_owned()),
            CredentialEnvelope::json(json!({"doctype":"org.iso.18013.5.1.mDL"})),
        ],
        Some("notify-1".to_owned()),
    )
    .map_err(|_| TestError::UnexpectedValue)?;

    let proto = credential_response_to_proto(&response)?;
    let bytes = proto.encode_to_vec();
    let decoded =
        pb::CredentialResponse::decode_from_slice(&bytes).map_err(|_| TestError::Decode)?;
    let converted = credential_response_from_proto(decoded)?;

    if converted == response {
        Ok(())
    } else {
        Err(TestError::UnexpectedValue)
    }
}

#[test]
fn credential_envelope_round_trips_compact_and_binary_payloads() -> Result<(), TestError> {
    for envelope in [
        CredentialEnvelope::compact("compact.sd-jwt".to_owned()),
        CredentialEnvelope::binary(vec![0xd8, 0x18, 0xa1, 0x01, 0x02]),
    ] {
        let proto = credential_envelope_to_proto(&envelope)?;
        let decoded = credential_envelope_from_proto(proto)?;
        if decoded != envelope {
            return Err(TestError::UnexpectedValue);
        }
    }
    Ok(())
}

#[test]
fn unknown_notification_event_is_rejected() {
    let mut proto = pb::NotificationRequest::default();
    proto.notification_id = "notify-1".to_owned();
    proto.event = EnumValue::from(99);

    let result = notification_request_from_proto(proto);

    assert_eq!(result, Err(ProtoError::InvalidEnum));
}

#[test]
fn binary_credential_envelope_preserves_raw_bytes_across_proto() -> Result<(), TestError> {
    let mut immediate = pb::ImmediateCredentialResponse::default();
    immediate.credentials = vec![pb::CredentialEnvelope {
        credential: Some(pb::credential_envelope::Credential::Binary(vec![1, 2, 3])),
        __buffa_unknown_fields: Default::default(),
    }];
    let proto = pb::CredentialResponse {
        response: Some(pb::credential_response::Response::Immediate(Box::new(
            immediate,
        ))),
        ..Default::default()
    };

    let result = credential_response_from_proto(proto)?;
    let credential = result
        .credentials
        .as_ref()
        .and_then(|credentials| credentials.first())
        .map(|entry| &entry.credential);
    assert_eq!(credential, Some(&CredentialPayload::Binary(vec![1, 2, 3])));
    assert_eq!(
        serde_json::to_value(&result).map_err(|_| TestError::UnexpectedValue)?,
        json!({"credentials":[{"credential":"AQID"}]})
    );
    Ok(())
}

#[test]
fn preflight_response_survives_buffa_binary_roundtrip() -> Result<(), TestError> {
    let proto = pb::PreflightCredentialResponse {
        preflight: buffa::MessageField::some(pb::CredentialRequestPreflight {
            selector: buffa::MessageField::some(pb::CredentialSelector {
                selector: Some(
                    pb::credential_selector::Selector::CredentialConfigurationId("pid".to_owned()),
                ),
                __buffa_unknown_fields: Default::default(),
            }),
            binding_key_count: 2,
            verified_proof_count: 2,
            includes_key_attestation: false,
            response_encryption_requested: true,
            ..Default::default()
        }),
        ..Default::default()
    };

    let bytes = proto.encode_to_vec();
    let decoded = pb::PreflightCredentialResponse::decode_from_slice(&bytes)
        .map_err(|_| TestError::Decode)?;

    if decoded == proto {
        Ok(())
    } else {
        Err(TestError::UnexpectedValue)
    }
}

#[test]
fn issuer_metadata_preserves_final_and_eudi_fields() -> Result<(), TestError> {
    let mut proof_types = std::collections::BTreeMap::new();
    proof_types.insert(
        "jwt".to_owned(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_owned()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: Some(vec!["high".to_owned()]),
                user_authentication: Some(vec!["high".to_owned()]),
                preferred_key_storage_status_period: Some(2_678_400),
            }),
        },
    );
    let mut configurations = std::collections::BTreeMap::new();
    configurations.insert(
        "pid".to_owned(),
        CredentialConfiguration {
            format: CredentialFormat::SdJwtVc,
            scope: Some("pid".to_owned()),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_owned()]),
            credential_signing_alg_values_supported: Some(vec![CredentialSigningAlg::Named(
                "ES256".to_owned(),
            )]),
            proof_types_supported: Some(proof_types),
            vct: Some("https://credentials.example/pid".to_owned()),
            doctype: None,
            credential_metadata: Some(json!({"display":[{"name":"PID"}]})),
        },
    );
    let metadata = IssuerMetadata {
        credential_issuer: "https://issuer.example".to_owned(),
        authorization_servers: Some(vec!["https://as.example".to_owned()]),
        credential_endpoint: "https://issuer.example/credential".to_owned(),
        nonce_endpoint: Some("https://issuer.example/nonce".to_owned()),
        deferred_credential_endpoint: Some("https://issuer.example/deferred".to_owned()),
        notification_endpoint: Some("https://issuer.example/notification".to_owned()),
        preferred_client_status_period: Some(2_678_400),
        credential_request_encryption: Some(CredentialRequestEncryptionMetadata {
            alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
            enc_values_supported: vec!["A256GCM".to_owned()],
            zip_values_supported: None,
            jwks: PublicJwkSet::from_value(json!({
                "keys":[{
                    "kty":"EC",
                    "crv":"P-256",
                    "x":"x",
                    "y":"y",
                    "kid":"request-key-1",
                    "alg":"ECDH-ES"
                }]
            }))
            .map_err(|_| TestError::UnexpectedValue)?,
            encryption_required: true,
        }),
        credential_response_encryption: Some(CredentialResponseEncryptionMetadata {
            alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
            enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            zip_values_supported: None,
            encryption_required: true,
        }),
        batch_credential_issuance: Some(BatchCredentialIssuance { batch_size: 2 }),
        credential_configurations_supported: configurations,
    };

    let proto = issuer_metadata_to_proto(&metadata)?;
    let bytes = proto.encode_to_vec();
    let decoded = pb::IssuerMetadata::decode_from_slice(&bytes).map_err(|_| TestError::Decode)?;
    let converted = issuer_metadata_from_proto(decoded)?;

    if converted == metadata {
        Ok(())
    } else {
        Err(TestError::UnexpectedValue)
    }
}

#[test]
fn issuer_metadata_rejects_malformed_json_byte_fields() {
    let mut proto = pb::IssuerMetadata::default();
    proto.credential_issuer = "https://issuer.example".to_owned();
    proto.credential_endpoint = "https://issuer.example/credential".to_owned();
    let mut configuration = pb::CredentialConfiguration::default();
    configuration.format = EnumValue::from(pb::CredentialFormat::DcSdJwt);
    configuration.credential_metadata_json = vec![0xff, 0x00];
    proto
        .credential_configurations_supported
        .push(pb::CredentialConfigurationEntry {
            credential_configuration_id: "pid".to_owned(),
            configuration: configuration.into(),
            __buffa_unknown_fields: Default::default(),
        });

    let result = issuer_metadata_from_proto(proto);

    assert_eq!(result, Err(ProtoError::InvalidJson));
}

#[test]
fn issuer_metadata_rejects_duplicate_configuration_entries() {
    let mut proto = minimal_proto_issuer_metadata();
    proto.credential_configurations_supported = vec![
        proto_configuration_entry("pid", minimal_proto_configuration()),
        proto_configuration_entry("pid", minimal_proto_configuration()),
    ];

    assert_eq!(
        issuer_metadata_from_proto(proto),
        Err(ProtoError::InvalidWireValue)
    );
}

#[test]
fn issuer_metadata_rejects_duplicate_proof_type_entries() {
    let mut configuration = minimal_proto_configuration();
    configuration.proof_types_supported = vec![
        pb::ProofTypeMetadataEntry {
            proof_type: "jwt".to_owned(),
            metadata: pb::ProofTypeMetadata::default().into(),
            __buffa_unknown_fields: Default::default(),
        },
        pb::ProofTypeMetadataEntry {
            proof_type: "jwt".to_owned(),
            metadata: pb::ProofTypeMetadata::default().into(),
            __buffa_unknown_fields: Default::default(),
        },
    ];
    let mut proto = minimal_proto_issuer_metadata();
    proto.credential_configurations_supported =
        vec![proto_configuration_entry("pid", configuration)];

    assert_eq!(
        issuer_metadata_from_proto(proto),
        Err(ProtoError::InvalidWireValue)
    );
}

#[test]
fn embedded_json_rejects_duplicate_object_keys() {
    let proto = credential_request_with_jwk_json(br#"{"kty":"EC","kty":"RSA"}"#.to_vec());

    let result = credential_request_from_proto(proto);

    assert_eq!(result, Err(ProtoError::InvalidJson));
}

#[test]
fn embedded_json_rejects_floating_point_numbers() {
    let proto = credential_request_with_jwk_json(br#"{"kty":"EC","extension":1.5}"#.to_vec());

    let result = credential_request_from_proto(proto);

    assert_eq!(result, Err(ProtoError::InvalidJson));
}

#[test]
fn embedded_json_rejects_integers_outside_the_interoperable_range() {
    for value in [
        br#"{"kty":"EC","extension":9007199254740992}"#.as_slice(),
        br#"{"kty":"EC","extension":-9007199254740992}"#.as_slice(),
    ] {
        let proto = credential_request_with_jwk_json(value.to_vec());
        assert_eq!(
            credential_request_from_proto(proto),
            Err(ProtoError::InvalidJson)
        );
    }
}

#[test]
fn embedded_json_accepts_integer_range_boundaries() {
    for value in [
        br#"{"kty":"EC","extension":9007199254740991}"#.as_slice(),
        br#"{"kty":"EC","extension":-9007199254740991}"#.as_slice(),
    ] {
        let proto = credential_request_with_jwk_json(value.to_vec());
        assert!(credential_request_from_proto(proto).is_ok());
    }
}

fn minimal_proto_issuer_metadata() -> pb::IssuerMetadata {
    let mut metadata = pb::IssuerMetadata::default();
    metadata.credential_issuer = "https://issuer.example".to_owned();
    metadata.credential_endpoint = "https://issuer.example/credential".to_owned();
    metadata
}

fn minimal_proto_configuration() -> pb::CredentialConfiguration {
    let mut configuration = pb::CredentialConfiguration::default();
    configuration.format = EnumValue::from(pb::CredentialFormat::DcSdJwt);
    configuration.vct = "https://credentials.example/pid".to_owned();
    configuration
}

fn proto_configuration_entry(
    id: &str,
    configuration: pb::CredentialConfiguration,
) -> pb::CredentialConfigurationEntry {
    pb::CredentialConfigurationEntry {
        credential_configuration_id: id.to_owned(),
        configuration: configuration.into(),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn embedded_json_rejects_excessive_nesting() -> Result<(), TestError> {
    let depth = usize::try_from(OPENID4VCI_EMBEDDED_JSON_RECURSION_LIMIT)
        .map_err(|_| TestError::UnexpectedValue)?;
    let mut json = vec![b'['; depth + 1];
    json.push(b'0');
    json.extend(std::iter::repeat_n(b']', depth + 1));
    let proto = credential_request_with_jwk_json(json);

    let result = credential_request_from_proto(proto);

    if result == Err(ProtoError::InvalidJson) {
        Ok(())
    } else {
        Err(TestError::UnexpectedValue)
    }
}

#[test]
fn embedded_json_rejects_oversized_fields_before_parsing() {
    let proto =
        credential_request_with_jwk_json(vec![b' '; MAX_OPENID4VCI_EMBEDDED_JSON_BYTES + 1]);

    let result = credential_request_from_proto(proto);

    assert_eq!(result, Err(ProtoError::PayloadTooLarge));
}

fn credential_request_with_jwk_json(jwk_json: Vec<u8>) -> pb::CredentialRequest {
    let mut encryption = pb::CredentialResponseEncryption::default();
    encryption.jwk_json = jwk_json;
    encryption.enc = "A256GCM".to_owned();

    pb::CredentialRequest {
        selector: buffa::MessageField::some(pb::CredentialSelector {
            selector: Some(
                pb::credential_selector::Selector::CredentialConfigurationId("pid".to_owned()),
            ),
            __buffa_unknown_fields: Default::default(),
        }),
        credential_response_encryption: buffa::MessageField::some(encryption),
        ..Default::default()
    }
}
