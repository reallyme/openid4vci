// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Converts scalar values and RFC 9457 problem details.

use std::mem;

use buffa::EnumValue;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_types as types;

use crate::map_error_reason::{problem_type_from_proto, problem_type_to_proto};

use super::convert_messages::{optional_string, ProtoError, ProtoResult};

/// Converts validated RFC 9457 problem details into the canonical protobuf contract.
pub fn problem_details_to_proto(value: &types::ProblemDetails) -> ProtoResult<pb::ProblemDetails> {
    let problem_type = problem_type_from_error_code(
        value
            .error
            .as_deref()
            .ok_or(ProtoError::MissingRequiredField)?,
    )
    .ok_or(ProtoError::InvalidWireValue)?;
    let expected_code = problem_type.error_code();
    if value.status != problem_type.status()
        || value.title != expected_code
        || !is_valid_problem_text(&value.type_url)
        || value
            .instance
            .as_deref()
            .is_some_and(|instance| !is_valid_problem_text(instance))
    {
        return Err(ProtoError::InvalidWireValue);
    }

    let mut proto = pb::ProblemDetails::default();
    proto.type_uri.clone_from(&value.type_url);
    proto.title.clone_from(&value.title);
    proto.status = u32::from(value.status);
    proto.instance = value.instance.clone().unwrap_or_default();
    proto.error = expected_code.to_owned();
    proto.reason = EnumValue::from(problem_type_to_proto(problem_type));
    Ok(proto)
}

/// Converts canonical protobuf problem details into the validated RFC 9457 model.
pub fn problem_details_from_proto(
    mut value: pb::ProblemDetails,
) -> ProtoResult<types::ProblemDetails> {
    let reason = value.reason.as_known().ok_or(ProtoError::InvalidEnum)?;
    let problem_type = problem_type_from_proto(reason)?;
    let expected_code = problem_type.error_code();
    let status = u16::try_from(value.status).map_err(|_| ProtoError::InvalidWireValue)?;
    if status != problem_type.status()
        || value.title != expected_code
        || value.error != expected_code
        || !is_valid_problem_text(&value.type_uri)
        || (!value.instance.is_empty() && !is_valid_problem_text(&value.instance))
    {
        return Err(ProtoError::InvalidWireValue);
    }

    Ok(types::ProblemDetails {
        type_url: mem::take(&mut value.type_uri),
        title: mem::take(&mut value.title),
        status,
        instance: optional_string(mem::take(&mut value.instance)),
        error: Some(mem::take(&mut value.error)),
    })
}

/// Converts an OpenID4VCI credential format into protobuf.
#[must_use]
pub fn credential_format_to_proto(value: &types::CredentialFormat) -> pb::CredentialFormat {
    match value {
        types::CredentialFormat::JwtVcJson => pb::CredentialFormat::JwtVcJson,
        types::CredentialFormat::JwtVcJsonLd => pb::CredentialFormat::JwtVcJsonLd,
        types::CredentialFormat::SdJwtVc => pb::CredentialFormat::DcSdJwt,
        types::CredentialFormat::MsoMdoc => pb::CredentialFormat::MsoMdoc,
        types::CredentialFormat::LdpVc => pb::CredentialFormat::LdpVc,
        _ => pb::CredentialFormat::Unspecified,
    }
}

/// Converts a protobuf credential format into OpenID4VCI.
pub fn credential_format_from_proto(
    value: pb::CredentialFormat,
) -> ProtoResult<types::CredentialFormat> {
    match value {
        pb::CredentialFormat::JwtVcJson => Ok(types::CredentialFormat::JwtVcJson),
        pb::CredentialFormat::JwtVcJsonLd => Ok(types::CredentialFormat::JwtVcJsonLd),
        pb::CredentialFormat::DcSdJwt => Ok(types::CredentialFormat::SdJwtVc),
        pb::CredentialFormat::MsoMdoc => Ok(types::CredentialFormat::MsoMdoc),
        pb::CredentialFormat::LdpVc => Ok(types::CredentialFormat::LdpVc),
        pb::CredentialFormat::Unspecified => Err(ProtoError::InvalidEnum),
    }
}

/// Converts OpenID4VCI tx_code input mode into protobuf.
#[must_use]
pub fn tx_code_input_mode_to_proto(value: types::TxCodeInputMode) -> pb::TxCodeInputMode {
    match value {
        types::TxCodeInputMode::Numeric => pb::TxCodeInputMode::Numeric,
        types::TxCodeInputMode::Text => pb::TxCodeInputMode::Text,
    }
}

/// Converts protobuf tx_code input mode into OpenID4VCI.
pub fn tx_code_input_mode_from_proto(
    value: EnumValue<pb::TxCodeInputMode>,
) -> ProtoResult<Option<types::TxCodeInputMode>> {
    match value.as_known() {
        Some(pb::TxCodeInputMode::Numeric) => Ok(Some(types::TxCodeInputMode::Numeric)),
        Some(pb::TxCodeInputMode::Text) => Ok(Some(types::TxCodeInputMode::Text)),
        Some(pb::TxCodeInputMode::Unspecified) => Ok(None),
        None => Err(ProtoError::InvalidEnum),
    }
}

/// Converts an OpenID4VCI notification event into protobuf.
#[must_use]
pub fn notification_event_to_proto(value: types::NotificationEvent) -> pb::NotificationEvent {
    match value {
        types::NotificationEvent::CredentialAccepted => pb::NotificationEvent::CredentialAccepted,
        types::NotificationEvent::CredentialFailure => pb::NotificationEvent::CredentialFailure,
        types::NotificationEvent::CredentialDeleted => pb::NotificationEvent::CredentialDeleted,
    }
}

/// Converts a protobuf notification event into OpenID4VCI.
pub fn notification_event_from_proto(
    value: EnumValue<pb::NotificationEvent>,
) -> ProtoResult<types::NotificationEvent> {
    match value.as_known() {
        Some(pb::NotificationEvent::CredentialAccepted) => {
            Ok(types::NotificationEvent::CredentialAccepted)
        }
        Some(pb::NotificationEvent::CredentialFailure) => {
            Ok(types::NotificationEvent::CredentialFailure)
        }
        Some(pb::NotificationEvent::CredentialDeleted) => {
            Ok(types::NotificationEvent::CredentialDeleted)
        }
        Some(pb::NotificationEvent::Unspecified) | None => Err(ProtoError::InvalidEnum),
    }
}

fn problem_type_from_error_code(value: &str) -> Option<types::ProblemType> {
    match value {
        "invalid_request" => Some(types::ProblemType::InvalidRequest),
        "invalid_proof" => Some(types::ProblemType::InvalidProof),
        "invalid_nonce" => Some(types::ProblemType::InvalidNonce),
        "invalid_notification_id" => Some(types::ProblemType::InvalidNotificationId),
        "invalid_notification_request" => Some(types::ProblemType::InvalidNotificationRequest),
        "unknown_credential_configuration" => Some(types::ProblemType::UnsupportedCredential),
        "unknown_credential_identifier" => Some(types::ProblemType::UnknownCredentialIdentifier),
        "invalid_encryption_parameters" => Some(types::ProblemType::EncryptionRequired),
        "invalid_transaction_id" => Some(types::ProblemType::InvalidTransaction),
        "request_too_large" => Some(types::ProblemType::PayloadTooLarge),
        "storage_unavailable" => Some(types::ProblemType::StorageUnavailable),
        "server_error" => Some(types::ProblemType::ServerError),
        _ => None,
    }
}

fn is_valid_problem_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains(['\r', '\n'])
}
