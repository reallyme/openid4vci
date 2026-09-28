// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conversion helpers for generated OpenID4VCI protobuf messages.
//!
//! The generated Buffa messages are the primary RPC boundary. These adapters
//! cross into `openid4vci-types` only after checking protobuf presence, enum, and
//! JSON-byte constraints so HTTP/JSON adapters inherit the same validation.

use std::collections::{btree_map::Entry, BTreeMap};
use std::mem;

use buffa::{EnumValue, MessageField, ProtoBox};
use openid4vci_types as types;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;

use super::convert_values::{notification_event_from_proto, notification_event_to_proto};

/// Result alias for protobuf conversion.
pub type ProtoResult<T> = Result<T, ProtoError>;

/// Deterministic protobuf conversion errors.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// A required protobuf field was absent.
    #[error("missing_required_field")]
    MissingRequiredField,
    /// An enum value was unspecified or unknown.
    #[error("invalid_enum")]
    InvalidEnum,
    /// A JSON byte field was not valid UTF-8 or JSON.
    #[error("invalid_json")]
    InvalidJson,
    /// An embedded JSON byte field exceeded its fixed resource limit.
    #[error("embedded_json_payload_too_large")]
    PayloadTooLarge,
    /// The mapped OpenID4VCI wire type rejected the value.
    #[error("invalid_wire_value")]
    InvalidWireValue,
}

/// Converts an OpenID4VCI Credential Request into protobuf.
pub fn credential_request_to_proto(
    value: &types::CredentialRequest,
) -> ProtoResult<pb::CredentialRequest> {
    map_wire(value.validate())?;
    let mut domain_selector = value.selector().map_err(|_| ProtoError::InvalidWireValue)?;
    let selector = match &mut domain_selector {
        types::CredentialSelector::ConfigurationId(id) => pb::CredentialSelector {
            selector: Some(
                pb::credential_selector::Selector::CredentialConfigurationId(mem::take(id)),
            ),
            __buffa_unknown_fields: Default::default(),
        },
        types::CredentialSelector::CredentialIdentifier(id) => pb::CredentialSelector {
            selector: Some(pb::credential_selector::Selector::CredentialIdentifier(
                mem::take(id),
            )),
            __buffa_unknown_fields: Default::default(),
        },
    };

    Ok(pb::CredentialRequest {
        selector: MessageField::some(selector),
        proofs: value
            .proofs
            .as_ref()
            .map(proofs_to_proto)
            .transpose()?
            .into(),
        credential_response_encryption: value
            .credential_response_encryption
            .as_ref()
            .map(credential_response_encryption_to_proto)
            .transpose()?
            .into(),
        ..Default::default()
    })
}

/// Converts a protobuf Credential Request into OpenID4VCI.
pub fn credential_request_from_proto(
    value: pb::CredentialRequest,
) -> ProtoResult<types::CredentialRequest> {
    let mut selector = credential_selector_from_proto(
        value
            .selector
            .into_option()
            .ok_or(ProtoError::MissingRequiredField)?,
    )?;
    let (credential_configuration_id, credential_identifier) = match &mut selector {
        types::CredentialSelector::ConfigurationId(id) => (Some(mem::take(id)), None),
        types::CredentialSelector::CredentialIdentifier(id) => (None, Some(mem::take(id))),
    };
    let request = types::CredentialRequest {
        credential_configuration_id,
        credential_identifier,
        proofs: option_from_message_field(value.proofs)
            .map(proofs_from_proto)
            .transpose()?,
        credential_response_encryption: option_from_message_field(
            value.credential_response_encryption,
        )
        .map(credential_response_encryption_from_proto)
        .transpose()?,
    };
    map_wire(request.validate())?;
    Ok(request)
}

/// Converts an OpenID4VCI Credential Response into protobuf.
pub fn credential_response_to_proto(
    value: &types::CredentialResponse,
) -> ProtoResult<pb::CredentialResponse> {
    map_wire(value.validate())?;
    let response = if let Some(credentials) = &value.credentials {
        let immediate = pb::ImmediateCredentialResponse {
            credentials: credentials
                .iter()
                .map(credential_envelope_to_proto)
                .collect::<ProtoResult<Vec<_>>>()?,
            notification_id: value.notification_id.clone().unwrap_or_default(),
            __buffa_unknown_fields: Default::default(),
        };
        pb::credential_response::Response::Immediate(Box::new(immediate))
    } else {
        let transaction_id = value
            .transaction_id
            .clone()
            .ok_or(ProtoError::MissingRequiredField)?;
        let interval = value.interval.ok_or(ProtoError::MissingRequiredField)?;
        pb::credential_response::Response::Deferred(Box::new(pb::DeferredCredentialResponse {
            transaction_id,
            interval,
            __buffa_unknown_fields: Default::default(),
        }))
    };
    Ok(pb::CredentialResponse {
        response: Some(response),
        ..Default::default()
    })
}

/// Converts a protobuf Credential Response into OpenID4VCI.
pub fn credential_response_from_proto(
    value: pb::CredentialResponse,
) -> ProtoResult<types::CredentialResponse> {
    let response = match value.response {
        Some(pb::credential_response::Response::Immediate(mut immediate)) => {
            types::CredentialResponse {
                credentials: Some(
                    mem::take(&mut immediate.credentials)
                        .into_iter()
                        .map(credential_envelope_from_proto)
                        .collect::<ProtoResult<Vec<_>>>()?,
                ),
                transaction_id: None,
                interval: None,
                notification_id: optional_string(mem::take(&mut immediate.notification_id)),
            }
        }
        Some(pb::credential_response::Response::Deferred(mut deferred)) => {
            types::CredentialResponse {
                credentials: None,
                transaction_id: Some(mem::take(&mut deferred.transaction_id)),
                interval: Some(deferred.interval),
                notification_id: None,
            }
        }
        None => return Err(ProtoError::MissingRequiredField),
    };
    map_wire(response.validate())?;
    Ok(response)
}

/// Converts an OpenID4VCI Deferred Credential Request into protobuf.
pub fn deferred_credential_request_to_proto(
    value: &types::DeferredCredentialRequest,
) -> ProtoResult<pb::DeferredCredentialRequest> {
    map_wire(value.validate())?;
    Ok(pb::DeferredCredentialRequest {
        transaction_id: value.transaction_id.clone(),
        credential_response_encryption: value
            .credential_response_encryption
            .as_ref()
            .map(credential_response_encryption_to_proto)
            .transpose()?
            .into(),
        __buffa_unknown_fields: Default::default(),
    })
}

/// Converts a protobuf Deferred Credential Request into OpenID4VCI.
pub fn deferred_credential_request_from_proto(
    mut value: pb::DeferredCredentialRequest,
) -> ProtoResult<types::DeferredCredentialRequest> {
    let request = types::DeferredCredentialRequest {
        transaction_id: mem::take(&mut value.transaction_id),
        credential_response_encryption: option_from_message_field(mem::take(
            &mut value.credential_response_encryption,
        ))
        .map(credential_response_encryption_from_proto)
        .transpose()?,
    };
    map_wire(request.validate())?;
    Ok(request)
}

/// Converts an OpenID4VCI Nonce Response into protobuf.
#[must_use]
pub fn nonce_response_to_proto(value: &types::NonceResponse) -> pb::NonceResponse {
    pb::NonceResponse {
        c_nonce: value.c_nonce.clone(),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Converts a protobuf Nonce Response into OpenID4VCI.
pub fn nonce_response_from_proto(
    mut value: pb::NonceResponse,
) -> ProtoResult<types::NonceResponse> {
    types::NonceResponse::new(mem::take(&mut value.c_nonce))
        .map_err(|_| ProtoError::InvalidWireValue)
}

/// Converts an OpenID4VCI Notification Request into protobuf.
#[must_use]
pub fn notification_request_to_proto(
    value: &types::NotificationRequest,
) -> pb::NotificationRequest {
    pb::NotificationRequest {
        notification_id: value.notification_id.clone(),
        event: EnumValue::from(notification_event_to_proto(value.event)),
        event_description: value.event_description.clone().unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Converts a protobuf Notification Request into OpenID4VCI.
pub fn notification_request_from_proto(
    mut value: pb::NotificationRequest,
) -> ProtoResult<types::NotificationRequest> {
    let request = types::NotificationRequest {
        notification_id: mem::take(&mut value.notification_id),
        event: notification_event_from_proto(value.event)?,
        event_description: optional_string(mem::take(&mut value.event_description)),
    };
    map_wire(request.validate())?;
    Ok(request)
}

fn credential_selector_from_proto(
    mut value: pb::CredentialSelector,
) -> ProtoResult<types::CredentialSelector> {
    let mut selector = value
        .selector
        .take()
        .ok_or(ProtoError::MissingRequiredField)?;
    match &mut selector {
        pb::credential_selector::Selector::CredentialConfigurationId(id) => {
            Ok(types::CredentialSelector::ConfigurationId(mem::take(id)))
        }
        pb::credential_selector::Selector::CredentialIdentifier(id) => Ok(
            types::CredentialSelector::CredentialIdentifier(mem::take(id)),
        ),
    }
}

fn proofs_to_proto(value: &types::Proofs) -> ProtoResult<pb::Proofs> {
    Ok(pb::Proofs {
        jwt: value.jwt.clone(),
        di_vp_json: value
            .di_vp
            .iter()
            .map(json_to_vec)
            .collect::<ProtoResult<Vec<_>>>()?,
        attestation: value.attestation.clone(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn proofs_from_proto(mut value: pb::Proofs) -> ProtoResult<types::Proofs> {
    let encoded_presentations = mem::take(&mut value.di_vp_json);
    let proofs = types::Proofs {
        jwt: mem::take(&mut value.jwt),
        di_vp: encoded_presentations
            .into_iter()
            .map(|json| {
                let json = Zeroizing::new(json);
                json_from_slice(&json)
            })
            .collect::<ProtoResult<Vec<_>>>()?,
        attestation: mem::take(&mut value.attestation),
    };
    map_wire(proofs.validate())?;
    Ok(proofs)
}

fn credential_response_encryption_to_proto(
    value: &types::CredentialResponseEncryption,
) -> ProtoResult<pb::CredentialResponseEncryption> {
    Ok(pb::CredentialResponseEncryption {
        jwk_json: json_to_vec(&value.jwk)?,
        enc: value.enc.clone(),
        zip: value.zip.clone().unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn credential_response_encryption_from_proto(
    mut value: pb::CredentialResponseEncryption,
) -> ProtoResult<types::CredentialResponseEncryption> {
    let encryption = types::CredentialResponseEncryption {
        jwk: types::PublicJwk::try_from(json_from_slice(&value.jwk_json)?)
            .map_err(|_| ProtoError::InvalidWireValue)?,
        enc: mem::take(&mut value.enc),
        zip: optional_string(mem::take(&mut value.zip)),
    };
    map_wire(encryption.validate())?;
    Ok(encryption)
}

/// Convert and validate one issued credential envelope for bounded persistence.
pub fn credential_envelope_to_proto(
    value: &types::CredentialEnvelope,
) -> ProtoResult<pb::CredentialEnvelope> {
    map_wire(value.validate())?;
    let credential = match &value.credential {
        types::CredentialPayload::Compact(compact) => {
            pb::credential_envelope::Credential::Compact(compact.clone())
        }
        types::CredentialPayload::Json(value) => {
            pb::credential_envelope::Credential::Json(json_to_vec(value)?)
        }
        types::CredentialPayload::Binary(value) => {
            pb::credential_envelope::Credential::Binary(value.clone())
        }
    };
    Ok(pb::CredentialEnvelope {
        credential: Some(credential),
        __buffa_unknown_fields: Default::default(),
    })
}

/// Convert and validate one persisted credential envelope.
pub fn credential_envelope_from_proto(
    mut value: pb::CredentialEnvelope,
) -> ProtoResult<types::CredentialEnvelope> {
    let mut credential = value
        .credential
        .take()
        .ok_or(ProtoError::MissingRequiredField)?;
    let credential = match &mut credential {
        pb::credential_envelope::Credential::Compact(compact) => {
            types::CredentialPayload::Compact(mem::take(compact))
        }
        pb::credential_envelope::Credential::Json(bytes) => {
            types::CredentialPayload::Json(json_from_slice(bytes)?)
        }
        pb::credential_envelope::Credential::Binary(bytes) => {
            types::CredentialPayload::Binary(mem::take(bytes))
        }
    };
    let envelope = types::CredentialEnvelope { credential };
    map_wire(envelope.validate())?;
    Ok(envelope)
}

pub(crate) fn json_to_vec<T: Serialize>(value: &T) -> ProtoResult<Vec<u8>> {
    crate::json::serialize_value(value)
}

fn json_from_slice(bytes: &[u8]) -> ProtoResult<Value> {
    crate::json::deserialize_value(bytes)
}

pub(crate) fn option_from_message_field<T: Default, P: ProtoBox<T>>(
    value: MessageField<T, P>,
) -> Option<T> {
    value.into_option()
}

pub(crate) fn optional_string(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn optional_vec<T>(value: Vec<T>) -> Option<Vec<T>> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn optional_map<K, V>(value: BTreeMap<K, V>) -> Option<BTreeMap<K, V>> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn insert_unique<K: Ord, V>(
    values: &mut BTreeMap<K, V>,
    key: K,
    value: V,
) -> ProtoResult<()> {
    match values.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(())
        }
        Entry::Occupied(_) => Err(ProtoError::InvalidWireValue),
    }
}

pub(crate) fn optional_u64(value: u64) -> Option<u64> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn optional_json_bytes(value: &[u8]) -> ProtoResult<Option<Value>> {
    if value.is_empty() {
        Ok(None)
    } else {
        json_from_slice(value).map(Some)
    }
}

pub(crate) fn map_wire<T>(result: types::OpenId4VciResult<T>) -> ProtoResult<T> {
    result.map_err(|_| ProtoError::InvalidWireValue)
}
