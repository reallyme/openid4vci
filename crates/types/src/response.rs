// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential and Deferred Credential response wire types.

use core::fmt::{Debug, Formatter};

use reallyme_codec::base64url::bytes_to_base64url;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use zeroize::Zeroize;

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::request::CredentialResponseEncryption;
use crate::validation::{
    is_optional_non_empty, parse_json, to_json, validate_non_empty_asciiish, zeroize_json_strings,
    JsonBoundaryPolicy, EXTENSIBLE_DOCUMENT_JSON, MAX_JSON_OUTPUT_BYTES,
};

/// Maximum accepted plaintext JSON Credential Response size.
///
/// Batch mdoc responses can legitimately exceed the shared 64 KiB operation
/// boundary because every credential carries an encoded IssuerSigned object.
/// The response remains strictly bounded at the same 256 KiB ceiling used by
/// the canonical serializer; all other operation documents retain the smaller
/// shared limit.
pub const MAX_CREDENTIAL_RESPONSE_JSON_BYTES: usize = MAX_JSON_OUTPUT_BYTES;

const CREDENTIAL_RESPONSE_JSON: JsonBoundaryPolicy = JsonBoundaryPolicy {
    max_input_bytes: MAX_CREDENTIAL_RESPONSE_JSON_BYTES,
    ..EXTENSIBLE_DOCUMENT_JSON
};

/// Canonical credential payload retained across JSON and protobuf adapters.
#[derive(Clone, PartialEq)]
pub enum CredentialPayload {
    /// Compact credential serialization, such as an SD-JWT VC.
    Compact(String),
    /// Structured JSON credential serialization.
    Json(Value),
    /// Binary credential serialization, such as raw CBOR `IssuerSigned`.
    Binary(Vec<u8>),
}

impl Debug for CredentialPayload {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        let kind = match self {
            Self::Compact(_) => "compact",
            Self::Json(_) => "json",
            Self::Binary(_) => "binary",
        };
        formatter
            .debug_struct("CredentialPayload")
            .field("kind", &kind)
            .finish()
    }
}

impl Serialize for CredentialPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Compact(value) => serializer.serialize_str(value),
            Self::Json(value) => value.serialize(serializer),
            // OpenID4VCI carries mdoc IssuerSigned CBOR as an unpadded
            // base64url string. The protobuf boundary retains the raw bytes.
            Self::Binary(value) => serializer.serialize_str(&bytes_to_base64url(value)),
        }
    }
}

impl<'de> Deserialize<'de> for CredentialPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Ok(match value {
            Value::String(compact) => Self::Compact(compact),
            other => Self::Json(other),
        })
    }
}

impl Drop for CredentialPayload {
    fn drop(&mut self) {
        match self {
            Self::Compact(value) => value.zeroize(),
            Self::Json(value) => zeroize_json_strings(value),
            Self::Binary(value) => value.zeroize(),
        }
    }
}

/// One issued credential entry in a Credential Response.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialEnvelope {
    /// Issued credential value in its canonical representation.
    pub credential: CredentialPayload,
}

impl Debug for CredentialEnvelope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialEnvelope")
            .field("credential", &"<redacted>")
            .finish()
    }
}

impl CredentialEnvelope {
    /// Creates an envelope for a compact credential serialization.
    #[must_use]
    pub fn compact(value: String) -> Self {
        Self {
            credential: CredentialPayload::Compact(value),
        }
    }

    /// Creates an envelope for a structured JSON credential serialization.
    #[must_use]
    pub fn json(value: Value) -> Self {
        Self {
            credential: CredentialPayload::Json(value),
        }
    }

    /// Creates an envelope for a binary credential serialization.
    #[must_use]
    pub fn binary(value: Vec<u8>) -> Self {
        Self {
            credential: CredentialPayload::Binary(value),
        }
    }

    /// Validates that the credential payload is present.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        let missing = match &self.credential {
            CredentialPayload::Compact(value) => value.is_empty(),
            CredentialPayload::Json(value) => value.is_null(),
            CredentialPayload::Binary(value) => value.is_empty(),
        };
        if missing {
            return Err(OpenId4VciError::new(Reason::MissingRequiredField));
        }
        Ok(())
    }
}

/// OpenID4VCI Credential Response body.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// Immediately issued credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<CredentialEnvelope>>,
    /// Deferred issuance transaction identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Positive polling interval in seconds for deferred issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Notification identifier for accepted/deleted/failure callbacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
}

impl Debug for CredentialResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialResponse")
            .field("credential_count", &self.credentials.as_ref().map(Vec::len))
            .field(
                "transaction_id",
                &self.transaction_id.as_ref().map(|_| "<redacted>"),
            )
            .field("interval", &self.interval)
            .field(
                "notification_id",
                &self.notification_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for CredentialResponse {
    fn drop(&mut self) {
        self.transaction_id.zeroize();
        self.notification_id.zeroize();
    }
}

impl CredentialResponse {
    /// Builds an immediate response containing one or more credentials.
    pub fn immediate(
        credentials: Vec<CredentialEnvelope>,
        notification_id: Option<String>,
    ) -> OpenId4VciResult<Self> {
        let response = Self {
            credentials: Some(credentials),
            transaction_id: None,
            interval: None,
            notification_id,
        };
        response.validate()?;
        Ok(response)
    }

    /// Builds a deferred response containing a transaction and interval.
    pub fn deferred(transaction_id: String, interval: u64) -> OpenId4VciResult<Self> {
        let response = Self {
            credentials: None,
            transaction_id: Some(transaction_id),
            interval: Some(interval),
            notification_id: None,
        };
        response.validate()?;
        Ok(response)
    }

    /// Parses and validates a JSON Credential Response.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        let value: Value = parse_json(body, CREDENTIAL_RESPONSE_JSON)?;
        let response = parse_credential_response_value(value)?;
        response.validate()?;
        Ok(response)
    }

    /// Serializes a validated Credential Response.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        self.validate()?;
        to_json(self)
    }

    /// Validates immediate-vs-deferred response shape rules.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        let has_credentials = self.credentials.is_some();
        let has_transaction = self.transaction_id.is_some();
        if has_credentials == has_transaction {
            return Err(OpenId4VciError::new(Reason::InvalidCredentialResponse));
        }
        if let Some(credentials) = &self.credentials {
            if credentials.is_empty() {
                return Err(OpenId4VciError::new(Reason::InvalidCredentialResponse));
            }
            for credential in credentials {
                credential.validate()?;
            }
            // OpenID4VCI 1.0 §8.3: `interval` MUST NOT be present alongside `credentials`.
            if self.interval.is_some() {
                return Err(OpenId4VciError::new(Reason::InvalidCredentialResponse));
            }
            is_optional_non_empty(&self.notification_id)?;
        }
        if let Some(transaction_id) = &self.transaction_id {
            validate_non_empty_asciiish(transaction_id)?;
            match self.interval {
                Some(0) | None => {
                    return Err(OpenId4VciError::new(Reason::InvalidCredentialResponse));
                }
                Some(_) => {}
            }
            if self.notification_id.is_some() {
                return Err(OpenId4VciError::new(Reason::InvalidCredentialResponse));
            }
        }
        Ok(())
    }
}

fn parse_credential_response_value(value: Value) -> OpenId4VciResult<CredentialResponse> {
    let mut value = value;
    let result = parse_credential_response_object(&mut value);
    // Members successfully transferred into typed owners are cleared by those
    // owners. Clear every unconsumed string as well, including on rejection.
    zeroize_json_strings(&mut value);
    result
}

fn parse_credential_response_object(value: &mut Value) -> OpenId4VciResult<CredentialResponse> {
    if !value.is_object() {
        return Err(OpenId4VciError::new(Reason::InvalidJson));
    }
    let has_credentials = value.get("credentials").is_some();
    let has_transaction = value.get("transaction_id").is_some();
    let has_interval = value.get("interval").is_some();

    if has_credentials && has_interval {
        return Err(OpenId4VciError::new(Reason::InvalidCredentialResponse));
    }
    if let Some(credentials_value) = value.get_mut("credentials") {
        if has_transaction {
            return Err(OpenId4VciError::new(Reason::InvalidCredentialResponse));
        }
        let credentials = parse_credentials_array(core::mem::take(credentials_value))?;
        let notification_id = take_optional_string_member(value, "notification_id")?;
        return Ok(CredentialResponse {
            credentials: Some(credentials),
            transaction_id: None,
            interval: None,
            notification_id,
        });
    }
    if has_transaction {
        return Ok(CredentialResponse {
            credentials: None,
            transaction_id: take_optional_string_member(value, "transaction_id")?,
            interval: take_optional_u64_member(value, "interval")?,
            notification_id: take_optional_string_member(value, "notification_id")?,
        });
    }
    Err(OpenId4VciError::new(Reason::InvalidJson))
}

fn parse_credentials_array(value: Value) -> OpenId4VciResult<Vec<CredentialEnvelope>> {
    let Value::Array(values) = value else {
        return Err(OpenId4VciError::new(Reason::InvalidJson));
    };
    let mut credentials = Vec::with_capacity(values.len());
    for mut value in values {
        if !value.is_object() {
            zeroize_json_strings(&mut value);
            return Err(OpenId4VciError::new(Reason::InvalidJson));
        }
        let Some(inner) = value.get_mut("credential") else {
            zeroize_json_strings(&mut value);
            return Err(OpenId4VciError::new(Reason::InvalidJson));
        };
        let credential = match core::mem::take(inner) {
            Value::String(compact) => CredentialPayload::Compact(compact),
            other => CredentialPayload::Json(other),
        };
        // Credential response entries are extension points in OpenID4VCI.
        // Clear ignored extension values before releasing their allocation so
        // an extension cannot accidentally retain credential-adjacent data.
        zeroize_json_strings(&mut value);
        credentials.push(CredentialEnvelope { credential });
    }
    Ok(credentials)
}

fn take_optional_string_member(value: &mut Value, name: &str) -> OpenId4VciResult<Option<String>> {
    let Some(member) = value.get_mut(name) else {
        return Ok(None);
    };
    match core::mem::take(member) {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text)),
        mut rejected => {
            zeroize_json_strings(&mut rejected);
            Err(OpenId4VciError::new(Reason::InvalidJson))
        }
    }
}

fn take_optional_u64_member(value: &mut Value, name: &str) -> OpenId4VciResult<Option<u64>> {
    let Some(member) = value.get_mut(name) else {
        return Ok(None);
    };
    match core::mem::take(member) {
        Value::Null => Ok(None),
        Value::Number(number) => number
            .as_u64()
            .map(Some)
            .ok_or(OpenId4VciError::new(Reason::InvalidJson)),
        mut rejected => {
            zeroize_json_strings(&mut rejected);
            Err(OpenId4VciError::new(Reason::InvalidJson))
        }
    }
}

/// OpenID4VCI Deferred Credential Request body.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DeferredCredentialRequest {
    /// Deferred issuance transaction identifier.
    pub transaction_id: String,
    /// Optional fresh encryption parameters for deferred response encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

impl Debug for DeferredCredentialRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeferredCredentialRequest")
            .field("transaction_id", &"<redacted>")
            .field(
                "credential_response_encryption",
                &self.credential_response_encryption,
            )
            .finish()
    }
}

impl Drop for DeferredCredentialRequest {
    fn drop(&mut self) {
        self.transaction_id.zeroize();
    }
}

impl DeferredCredentialRequest {
    /// Parses and validates a bounded Deferred Credential Request JSON body.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        let request: Self = crate::validation::parse_json(body, EXTENSIBLE_DOCUMENT_JSON)?;
        request.validate()?;
        Ok(request)
    }

    /// Serializes a validated Deferred Credential Request JSON body.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        self.validate()?;
        crate::validation::to_json(self)
    }

    /// Validates a Deferred Credential Request.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_non_empty_asciiish(&self.transaction_id)?;
        if let Some(encryption) = &self.credential_response_encryption {
            encryption.validate()?;
        }
        Ok(())
    }
}
