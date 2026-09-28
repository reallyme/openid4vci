// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical versioned operation boundary used by native and Wasm SDKs.

use std::str;

use buffa::{EnumValue, Message};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use zeroize::Zeroizing;

use crate::convert::{self, ProtoError, ProtoResult};
use crate::decode::{decode_proto, decode_proto_with_limit};
use crate::encode::encode_proto_zeroizing_with_limit;
use crate::map_error_reason::{proto_codec_error_to_proto, proto_error_to_proto};
use crate::{json_to_proto, ProtoCodecError, ProtoCodecResult, MAX_OPENID4VCI_PROTO_JSON_BYTES};

use pb::open_id4vci_operation_request::Operation as RequestOperation;
use pb::open_id4vci_operation_response::Outcome as ResponseOutcome;
use pb::open_id4vci_operation_result::Result as OperationResult;

/// Maximum protobuf framing added by the versioned response envelope.
pub const MAX_OPENID4VCI_OPERATION_RESPONSE_OVERHEAD_BYTES: usize = 32;

/// Maximum accepted output from a composed OpenID4VCI platform provider.
pub const MAX_OPENID4VCI_OPERATION_RESPONSE_BYTES: usize = 65_568;

/// Operation identity a response consumer expects from an untrusted provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OpenId4VciOperationKind {
    /// Credential offer validation and normalization.
    CredentialOffer,
    /// Credential issuer metadata validation and normalization.
    IssuerMetadata,
    /// Credential request validation and normalization.
    CredentialRequest,
    /// Credential response validation and normalization.
    CredentialResponse,
    /// Deferred credential request validation and normalization.
    DeferredCredentialRequest,
    /// Nonce response validation and normalization.
    NonceResponse,
    /// Notification request validation and normalization.
    NotificationRequest,
    /// RFC 9457 problem details validation and normalization.
    ProblemDetails,
}

/// Executes a trusted generated request through the canonical domain boundary.
#[must_use]
pub fn execute_operation_request(
    mut request: pb::OpenId4VciOperationRequest,
) -> pb::OpenId4VciOperationResponse {
    if request.contract_version.as_known() != Some(pb::OpenId4VciOperationContractVersion::V1) {
        return error_response(proto_error_to_proto(ProtoError::InvalidEnum));
    }

    // Keep the generated owner alive until return. Hardened generated Drop
    // implementations can then wipe retained unknown fields after the selected
    // child has been moved into its domain conversion.
    let Some(operation) = request.operation.take() else {
        return error_response(proto_error_to_proto(ProtoError::MissingRequiredField));
    };

    match normalize_operation(operation) {
        Ok(result) => result_response(result),
        Err(error) => error_response(proto_error_to_proto(error)),
    }
}

/// Executes bounded binary protobuf input and returns a canonical binary response.
#[must_use]
pub fn execute_operation_v1(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let response = match decode_proto(request_bytes) {
        Ok(request) => execute_operation_request(request),
        Err(error) => error_response(proto_codec_error_to_proto(error)),
    };
    encode_response_or_error(response)
}

/// Executes bounded generated ProtoJSON input and returns a canonical binary response.
#[must_use]
pub fn execute_operation_json_v1(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    let response = if request_json.len() > MAX_OPENID4VCI_PROTO_JSON_BYTES {
        error_response(pb::OpenId4VciErrorReason::PayloadTooLarge)
    } else {
        match str::from_utf8(request_json) {
            Ok(json) => match json_to_proto(json) {
                Ok(request) => execute_operation_request(request),
                Err(error) => error_response(proto_codec_error_to_proto(error)),
            },
            Err(_) => error_response(pb::OpenId4VciErrorReason::ProtoJsonDeserialize),
        }
    };
    encode_response_or_error(response)
}

/// Decodes and validates provider output for the operation submitted by a caller.
///
/// # Errors
///
/// Returns a fixed codec error when output is oversized, malformed, unversioned,
/// omits its outcome, carries an invalid reason, or selects another operation.
pub fn decode_operation_response_v1(
    bytes: &[u8],
    expected_operation: OpenId4VciOperationKind,
) -> ProtoCodecResult<pb::OpenId4VciOperationResponse> {
    let response = decode_proto_with_limit(bytes, MAX_OPENID4VCI_OPERATION_RESPONSE_BYTES)
        .map_err(|_| ProtoCodecError::Decode)?;
    validate_response(&response, expected_operation)?;
    Ok(response)
}

fn normalize_operation(operation: RequestOperation) -> ProtoResult<OperationResult> {
    match operation {
        RequestOperation::CredentialOffer(value) => {
            let domain = convert::credential_offer_from_proto(*value)?;
            Ok(OperationResult::CredentialOffer(Box::new(
                convert::credential_offer_to_proto(&domain),
            )))
        }
        RequestOperation::IssuerMetadata(value) => {
            let domain = convert::issuer_metadata_from_proto(*value)?;
            Ok(OperationResult::IssuerMetadata(Box::new(
                convert::issuer_metadata_to_proto(&domain)?,
            )))
        }
        RequestOperation::CredentialRequest(value) => {
            let domain = convert::credential_request_from_proto(*value)?;
            Ok(OperationResult::CredentialRequest(Box::new(
                convert::credential_request_to_proto(&domain)?,
            )))
        }
        RequestOperation::CredentialResponse(value) => {
            let domain = convert::credential_response_from_proto(*value)?;
            Ok(OperationResult::CredentialResponse(Box::new(
                convert::credential_response_to_proto(&domain)?,
            )))
        }
        RequestOperation::DeferredCredentialRequest(value) => {
            let domain = convert::deferred_credential_request_from_proto(*value)?;
            Ok(OperationResult::DeferredCredentialRequest(Box::new(
                convert::deferred_credential_request_to_proto(&domain)?,
            )))
        }
        RequestOperation::NonceResponse(value) => {
            let domain = convert::nonce_response_from_proto(*value)?;
            Ok(OperationResult::NonceResponse(Box::new(
                convert::nonce_response_to_proto(&domain),
            )))
        }
        RequestOperation::NotificationRequest(value) => {
            let domain = convert::notification_request_from_proto(*value)?;
            Ok(OperationResult::NotificationRequest(Box::new(
                convert::notification_request_to_proto(&domain),
            )))
        }
        RequestOperation::ProblemDetails(value) => {
            let domain = convert::problem_details_from_proto(*value)?;
            Ok(OperationResult::ProblemDetails(Box::new(
                convert::problem_details_to_proto(&domain)?,
            )))
        }
    }
}

fn validate_response(
    response: &pb::OpenId4VciOperationResponse,
    expected_operation: OpenId4VciOperationKind,
) -> ProtoCodecResult<()> {
    if response.contract_version.as_known() != Some(pb::OpenId4VciOperationContractVersion::V1) {
        return Err(ProtoCodecError::Decode);
    }
    let Some(outcome) = &response.outcome else {
        return Err(ProtoCodecError::Decode);
    };
    match outcome {
        ResponseOutcome::Error(error) => {
            match error.reason.as_known() {
                Some(pb::OpenId4VciErrorReason::Unspecified) | None => {
                    return Err(ProtoCodecError::Decode);
                }
                Some(_) => {}
            }
            Ok(())
        }
        ResponseOutcome::Result(result) => {
            let Some(result) = &result.result else {
                return Err(ProtoCodecError::Decode);
            };
            match result {
                OperationResult::CredentialOffer(_) => {
                    require_operation(expected_operation, OpenId4VciOperationKind::CredentialOffer)
                }
                OperationResult::IssuerMetadata(_) => {
                    require_operation(expected_operation, OpenId4VciOperationKind::IssuerMetadata)
                }
                OperationResult::CredentialRequest(_) => require_operation(
                    expected_operation,
                    OpenId4VciOperationKind::CredentialRequest,
                ),
                OperationResult::CredentialResponse(_) => require_operation(
                    expected_operation,
                    OpenId4VciOperationKind::CredentialResponse,
                ),
                OperationResult::DeferredCredentialRequest(_) => require_operation(
                    expected_operation,
                    OpenId4VciOperationKind::DeferredCredentialRequest,
                ),
                OperationResult::NonceResponse(_) => {
                    require_operation(expected_operation, OpenId4VciOperationKind::NonceResponse)
                }
                OperationResult::NotificationRequest(_) => require_operation(
                    expected_operation,
                    OpenId4VciOperationKind::NotificationRequest,
                ),
                OperationResult::ProblemDetails(_) => {
                    require_operation(expected_operation, OpenId4VciOperationKind::ProblemDetails)
                }
            }
        }
    }
}

fn require_operation(
    actual: OpenId4VciOperationKind,
    expected: OpenId4VciOperationKind,
) -> ProtoCodecResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProtoCodecError::Decode)
    }
}

fn result_response(result: OperationResult) -> pb::OpenId4VciOperationResponse {
    response_with_outcome(ResponseOutcome::Result(Box::new(
        pb::OpenId4VciOperationResult {
            result: Some(result),
            __buffa_unknown_fields: Default::default(),
        },
    )))
}

fn response_with_outcome(outcome: ResponseOutcome) -> pb::OpenId4VciOperationResponse {
    pb::OpenId4VciOperationResponse {
        contract_version: EnumValue::from(pb::OpenId4VciOperationContractVersion::V1),
        outcome: Some(outcome),
        ..Default::default()
    }
}

fn error_response(reason: pb::OpenId4VciErrorReason) -> pb::OpenId4VciOperationResponse {
    response_with_outcome(ResponseOutcome::Error(Box::new(
        pb::OpenId4VciOperationError {
            reason: EnumValue::from(reason),
            ..Default::default()
        },
    )))
}

fn encode_response_or_error(response: pb::OpenId4VciOperationResponse) -> Zeroizing<Vec<u8>> {
    if let Ok(encoded) =
        encode_proto_zeroizing_with_limit(&response, MAX_OPENID4VCI_OPERATION_RESPONSE_BYTES)
    {
        return encoded;
    }

    // The fallback is a fixed, tiny generated message. Encoding it directly
    // ensures even serialization-limit failures retain a typed response.
    Zeroizing::new(error_response(pb::OpenId4VciErrorReason::PayloadTooLarge).encode_to_vec())
}
