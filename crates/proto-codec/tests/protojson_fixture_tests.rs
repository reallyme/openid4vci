// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-language golden ProtoJSON and protobuf-binary parity tests.

use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::convert::{
    credential_offer_from_proto, credential_request_from_proto, credential_response_from_proto,
    deferred_credential_request_from_proto, issuer_metadata_from_proto,
    notification_request_from_proto, problem_details_from_proto, ProtoError,
};
use openid4vci_proto_codec::{
    decode_proto, encode_proto, json_to_proto, proto_to_json, OpenId4VciProtoJson, ProtoCodecError,
};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
enum FixtureError {
    #[error("proto_codec")]
    Codec,
    #[error("proto_conversion")]
    Conversion,
    #[error("fixture_json")]
    FixtureJson,
    #[error("fixture_hex")]
    FixtureHex,
    #[error("parity")]
    Parity,
}

impl From<ProtoCodecError> for FixtureError {
    fn from(_: ProtoCodecError) -> Self {
        Self::Codec
    }
}

impl From<ProtoError> for FixtureError {
    fn from(_: ProtoError) -> Self {
        Self::Conversion
    }
}

#[test]
fn credential_offer_fixture_has_binary_json_and_domain_parity() -> Result<(), FixtureError> {
    let proto: pb::CredentialOffer = assert_fixture(include_str!(
        "../../proto/tests/fixtures/protojson/credential-offer.json"
    ))?;
    credential_offer_from_proto(proto)?;
    Ok(())
}

#[test]
fn issuer_metadata_fixture_has_binary_json_and_domain_parity() -> Result<(), FixtureError> {
    let proto: pb::IssuerMetadata = assert_fixture(include_str!(
        "../../proto/tests/fixtures/protojson/issuer-metadata.json"
    ))?;
    issuer_metadata_from_proto(proto)?;
    Ok(())
}

#[test]
fn credential_request_fixture_has_binary_json_and_domain_parity() -> Result<(), FixtureError> {
    let proto: pb::CredentialRequest = assert_fixture(include_str!(
        "../../proto/tests/fixtures/protojson/credential-request.json"
    ))?;
    credential_request_from_proto(proto)?;
    Ok(())
}

#[test]
fn credential_response_fixture_has_binary_json_and_domain_parity() -> Result<(), FixtureError> {
    let proto: pb::CredentialResponse = assert_fixture(include_str!(
        "../../proto/tests/fixtures/protojson/credential-response.json"
    ))?;
    credential_response_from_proto(proto)?;
    Ok(())
}

#[test]
fn deferred_request_fixture_has_binary_json_and_domain_parity() -> Result<(), FixtureError> {
    let proto: pb::DeferredCredentialRequest = assert_fixture(include_str!(
        "../../proto/tests/fixtures/protojson/deferred-credential-request.json"
    ))?;
    deferred_credential_request_from_proto(proto)?;
    Ok(())
}

#[test]
fn notification_fixture_has_binary_json_and_domain_parity() -> Result<(), FixtureError> {
    let proto: pb::NotificationRequest = assert_fixture(include_str!(
        "../../proto/tests/fixtures/protojson/notification-request.json"
    ))?;
    notification_request_from_proto(proto)?;
    Ok(())
}

#[test]
fn problem_details_fixture_has_binary_json_and_domain_parity() -> Result<(), FixtureError> {
    let proto: pb::ProblemDetails = assert_fixture(include_str!(
        "../../proto/tests/fixtures/protojson/problem-details.json"
    ))?;
    problem_details_from_proto(proto)?;
    Ok(())
}

#[test]
fn every_public_generated_message_has_binary_and_protojson_parity() -> Result<(), FixtureError> {
    macro_rules! assert_messages {
        ($($message:ty),+ $(,)?) => {
            $(assert_default_message_parity::<$message>()?;)+
        };
    }

    assert_messages!(
        pb::ProblemDetails,
        pb::TxCode,
        pb::AuthorizationCodeGrant,
        pb::PreAuthorizedCodeGrant,
        pb::CredentialOfferGrants,
        pb::CredentialOffer,
        pb::CredentialOfferUri,
        pb::CredentialSelector,
        pb::Proofs,
        pb::CredentialResponseEncryption,
        pb::CredentialRequest,
        pb::CredentialEnvelope,
        pb::ImmediateCredentialResponse,
        pb::DeferredCredentialResponse,
        pb::CredentialResponse,
        pb::DeferredCredentialRequest,
        pb::NonceRequest,
        pb::NonceResponse,
        pb::GetNonceRequest,
        pb::GetNonceResponse,
        pb::NotificationRequest,
        pb::NotifyRequest,
        pb::NotifyResponse,
        pb::IssueCredentialRequest,
        pb::IssueCredentialResponse,
        pb::CredentialRequestPreflight,
        pb::PreflightCredentialRequest,
        pb::PreflightCredentialResponse,
        pb::GetDeferredCredentialRequest,
        pb::GetDeferredCredentialResponse,
        pb::ProofTypeMetadata,
        pb::KeyAttestationsRequired,
        pb::CredentialSigningAlg,
        pb::CredentialConfiguration,
        pb::CredentialRequestEncryptionMetadata,
        pb::CredentialResponseEncryptionMetadata,
        pb::BatchCredentialIssuance,
        pb::IssuerMetadata,
        pb::OpenId4VciOperationError,
        pb::OpenId4VciOperationRequest,
        pb::OpenId4VciOperationResult,
        pb::OpenId4VciOperationResponse,
    );
    Ok(())
}

#[test]
fn protobuf_wire_fixtures_match_protojson_contracts() -> Result<(), FixtureError> {
    assert_wire_fixture::<pb::CredentialOffer>(
        include_str!("../../proto/tests/fixtures/protojson/credential-offer.json"),
        include_str!("../../proto/tests/fixtures/protobuf/credential-offer.pb.hex"),
    )?;
    assert_wire_fixture::<pb::IssuerMetadata>(
        include_str!("../../proto/tests/fixtures/protojson/issuer-metadata.json"),
        include_str!("../../proto/tests/fixtures/protobuf/issuer-metadata.pb.hex"),
    )?;
    assert_wire_fixture::<pb::CredentialRequest>(
        include_str!("../../proto/tests/fixtures/protojson/credential-request.json"),
        include_str!("../../proto/tests/fixtures/protobuf/credential-request.pb.hex"),
    )?;
    assert_wire_fixture::<pb::CredentialResponse>(
        include_str!("../../proto/tests/fixtures/protojson/credential-response.json"),
        include_str!("../../proto/tests/fixtures/protobuf/credential-response.pb.hex"),
    )?;
    assert_wire_fixture::<pb::DeferredCredentialRequest>(
        include_str!("../../proto/tests/fixtures/protojson/deferred-credential-request.json"),
        include_str!("../../proto/tests/fixtures/protobuf/deferred-credential-request.pb.hex"),
    )?;
    assert_wire_fixture::<pb::NotificationRequest>(
        include_str!("../../proto/tests/fixtures/protojson/notification-request.json"),
        include_str!("../../proto/tests/fixtures/protobuf/notification-request.pb.hex"),
    )?;
    assert_wire_fixture::<pb::ProblemDetails>(
        include_str!("../../proto/tests/fixtures/protojson/problem-details.json"),
        include_str!("../../proto/tests/fixtures/protobuf/problem-details.pb.hex"),
    )?;
    Ok(())
}

fn assert_default_message_parity<M>() -> Result<(), FixtureError>
where
    M: Default + OpenId4VciProtoJson + PartialEq,
{
    let original = M::default();
    let binary = encode_proto(&original)?;
    let from_binary: M = decode_proto(&binary)?;
    if from_binary != original {
        return Err(FixtureError::Parity);
    }

    let json = proto_to_json(&from_binary)?;
    let from_json: M = json_to_proto(&json)?;
    if from_json != original || encode_proto(&from_json)? != binary {
        return Err(FixtureError::Parity);
    }
    Ok(())
}

fn assert_fixture<M>(fixture: &str) -> Result<M, FixtureError>
where
    M: OpenId4VciProtoJson + PartialEq,
{
    let from_json: M = json_to_proto(fixture)?;
    let binary = encode_proto(&from_json)?;
    let from_binary: M = decode_proto(&binary)?;
    if from_binary != from_json {
        return Err(FixtureError::Parity);
    }

    let canonical_json = proto_to_json(&from_binary)?;
    let expected: Value = serde_json::from_str(fixture).map_err(|_| FixtureError::FixtureJson)?;
    let actual: Value =
        serde_json::from_str(&canonical_json).map_err(|_| FixtureError::FixtureJson)?;
    if actual != expected {
        return Err(FixtureError::Parity);
    }
    Ok(from_binary)
}

fn assert_wire_fixture<M>(json_fixture: &str, hex_fixture: &str) -> Result<(), FixtureError>
where
    M: OpenId4VciProtoJson + PartialEq,
{
    let message: M = json_to_proto(json_fixture)?;
    let expected = decode_lower_hex(hex_fixture.trim())?;
    let encoded = encode_proto(&message)?;
    if encoded.as_slice() != expected.as_slice() {
        return Err(FixtureError::Parity);
    }
    let decoded: M = decode_proto(&expected)?;
    if decoded != message {
        return Err(FixtureError::Parity);
    }
    Ok(())
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, FixtureError> {
    let (chunks, remainder) = value.as_bytes().as_chunks::<2>();
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for chunk in chunks {
        let high = decode_lower_nibble(chunk[0])?;
        let low = decode_lower_nibble(chunk[1])?;
        decoded.push((high << 4) | low);
    }
    if remainder.is_empty() {
        Ok(decoded)
    } else {
        Err(FixtureError::FixtureHex)
    }
}

fn decode_lower_nibble(value: u8) -> Result<u8, FixtureError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(FixtureError::FixtureHex),
    }
}
