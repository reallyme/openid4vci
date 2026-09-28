// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical operation boundary and provider-output validation coverage.

use buffa::{EnumValue, Message};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::{
    decode_operation_response_v1, decode_proto, encode_proto, execute_operation_json_v1,
    execute_operation_v1, json_to_proto, proto_to_json, OpenId4VciOperationKind, ProtoCodecError,
    MAX_OPENID4VCI_OPERATION_RESPONSE_BYTES, MAX_OPENID4VCI_OPERATION_RESPONSE_OVERHEAD_BYTES,
    MAX_OPENID4VCI_PROTO_MESSAGE_BYTES,
};
use thiserror::Error;

use pb::open_id4vci_operation_request::Operation as RequestOperation;
use pb::open_id4vci_operation_response::Outcome as ResponseOutcome;

#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
enum OperationTestError {
    #[error("codec")]
    Codec,
    #[error("unexpected_outcome")]
    UnexpectedOutcome,
}

impl From<ProtoCodecError> for OperationTestError {
    fn from(_: ProtoCodecError) -> Self {
        Self::Codec
    }
}

#[test]
fn every_operation_has_binary_and_protojson_execution_parity() -> Result<(), OperationTestError> {
    assert_eq!(
        MAX_OPENID4VCI_PROTO_MESSAGE_BYTES
            .checked_add(MAX_OPENID4VCI_OPERATION_RESPONSE_OVERHEAD_BYTES),
        Some(MAX_OPENID4VCI_OPERATION_RESPONSE_BYTES)
    );
    for (operation, kind) in valid_operations()? {
        let request = operation_request(operation);
        let binary_request = encode_proto(&request)?;
        let json_request = proto_to_json(&request)?;

        let binary_response = execute_operation_v1(&binary_request);
        let json_response = execute_operation_json_v1(json_request.as_bytes());
        if binary_response.as_slice() != json_response.as_slice() {
            return Err(OperationTestError::UnexpectedOutcome);
        }

        let response = decode_operation_response_v1(&binary_response, kind)?;
        if matches!(response.outcome, Some(ResponseOutcome::Error(_))) {
            return Err(OperationTestError::UnexpectedOutcome);
        }
    }
    Ok(())
}

#[test]
fn malformed_oversized_and_incomplete_requests_return_typed_errors(
) -> Result<(), OperationTestError> {
    assert_error_reason(
        execute_operation_v1(&[0xff]),
        pb::OpenId4VciErrorReason::ProtoDecode,
    )?;
    assert_error_reason(
        execute_operation_v1(&vec![0_u8; MAX_OPENID4VCI_PROTO_MESSAGE_BYTES + 1]),
        pb::OpenId4VciErrorReason::PayloadTooLarge,
    )?;
    assert_error_reason(
        execute_operation_json_v1(b"{"),
        pb::OpenId4VciErrorReason::ProtoJsonDeserialize,
    )?;

    let missing = operation_request_without_operation(pb::OpenId4VciOperationContractVersion::V1);
    assert_error_reason(
        execute_operation_v1(&encode_proto(&missing)?),
        pb::OpenId4VciErrorReason::ProtoMissingRequiredField,
    )?;

    let unsupported =
        operation_request_without_operation(pb::OpenId4VciOperationContractVersion::Unspecified);
    assert_error_reason(
        execute_operation_v1(&encode_proto(&unsupported)?),
        pb::OpenId4VciErrorReason::ProtoInvalidEnum,
    )?;
    Ok(())
}

#[test]
fn response_decoder_rejects_wrong_operation_invalid_reason_and_unknown_fields(
) -> Result<(), OperationTestError> {
    let mut operations = valid_operations()?;
    let Some((operation, _)) = operations.drain(..).next() else {
        return Err(OperationTestError::UnexpectedOutcome);
    };
    let response = execute_operation_v1(&encode_proto(&operation_request(operation))?);
    assert_eq!(
        decode_operation_response_v1(&response, OpenId4VciOperationKind::IssuerMetadata),
        Err(ProtoCodecError::Decode)
    );

    let invalid_error = pb::OpenId4VciOperationResponse {
        contract_version: EnumValue::from(pb::OpenId4VciOperationContractVersion::V1),
        outcome: Some(ResponseOutcome::Error(Box::default())),
        ..Default::default()
    };
    assert_eq!(
        decode_operation_response_v1(
            &invalid_error.encode_to_vec(),
            OpenId4VciOperationKind::CredentialOffer
        ),
        Err(ProtoCodecError::Decode)
    );
    assert_eq!(
        decode_operation_response_v1(
            &[0x98_u8, 0x06, 0x01],
            OpenId4VciOperationKind::CredentialOffer
        ),
        Err(ProtoCodecError::Decode)
    );
    Ok(())
}

fn valid_operations() -> Result<Vec<(RequestOperation, OpenId4VciOperationKind)>, OperationTestError>
{
    Ok(vec![
        (
            RequestOperation::CredentialOffer(Box::new(json_to_proto(include_str!(
                "../../proto/tests/fixtures/protojson/credential-offer.json"
            ))?)),
            OpenId4VciOperationKind::CredentialOffer,
        ),
        (
            RequestOperation::IssuerMetadata(Box::new(json_to_proto(include_str!(
                "../../proto/tests/fixtures/protojson/issuer-metadata.json"
            ))?)),
            OpenId4VciOperationKind::IssuerMetadata,
        ),
        (
            RequestOperation::CredentialRequest(Box::new(json_to_proto(include_str!(
                "../../proto/tests/fixtures/protojson/credential-request.json"
            ))?)),
            OpenId4VciOperationKind::CredentialRequest,
        ),
        (
            RequestOperation::CredentialResponse(Box::new(json_to_proto(include_str!(
                "../../proto/tests/fixtures/protojson/credential-response.json"
            ))?)),
            OpenId4VciOperationKind::CredentialResponse,
        ),
        (
            RequestOperation::DeferredCredentialRequest(Box::new(json_to_proto(include_str!(
                "../../proto/tests/fixtures/protojson/deferred-credential-request.json"
            ))?)),
            OpenId4VciOperationKind::DeferredCredentialRequest,
        ),
        (
            RequestOperation::NonceResponse(Box::new(nonce_response())),
            OpenId4VciOperationKind::NonceResponse,
        ),
        (
            RequestOperation::NotificationRequest(Box::new(json_to_proto(include_str!(
                "../../proto/tests/fixtures/protojson/notification-request.json"
            ))?)),
            OpenId4VciOperationKind::NotificationRequest,
        ),
        (
            RequestOperation::ProblemDetails(Box::new(json_to_proto(include_str!(
                "../../proto/tests/fixtures/protojson/problem-details.json"
            ))?)),
            OpenId4VciOperationKind::ProblemDetails,
        ),
    ])
}

fn operation_request(operation: RequestOperation) -> pb::OpenId4VciOperationRequest {
    pb::OpenId4VciOperationRequest {
        contract_version: EnumValue::from(pb::OpenId4VciOperationContractVersion::V1),
        operation: Some(operation),
        ..Default::default()
    }
}

fn nonce_response() -> pb::NonceResponse {
    let mut response = pb::NonceResponse::default();
    response.c_nonce = "nonce-for-operation-vector".to_owned();
    response
}

fn operation_request_without_operation(
    version: pb::OpenId4VciOperationContractVersion,
) -> pb::OpenId4VciOperationRequest {
    pb::OpenId4VciOperationRequest {
        contract_version: EnumValue::from(version),
        ..Default::default()
    }
}

fn assert_error_reason(
    response: impl AsRef<[u8]>,
    expected: pb::OpenId4VciErrorReason,
) -> Result<(), OperationTestError> {
    let response: pb::OpenId4VciOperationResponse = decode_proto(response.as_ref())?;
    let Some(ResponseOutcome::Error(error)) = response.outcome else {
        return Err(OperationTestError::UnexpectedOutcome);
    };
    if error.reason.as_known() == Some(expected) {
        Ok(())
    } else {
        Err(OperationTestError::UnexpectedOutcome)
    }
}
