// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed OAuth Authorization Server adapter surface for conformance HTTP routes.

use std::collections::BTreeMap;

use serde::Serialize;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::oauth_authorization_server_capabilities::OAuthAuthorizationServerCapabilities;

/// Maximum JSON response emitted by the co-located OAuth adapter.
const MAX_OAUTH_RESPONSE_JSON_BYTES: usize = 65_536;

/// Parsed OAuth request parameters with drop-time value clearing.
///
/// Names are protocol vocabulary; values can contain codes, PKCE verifiers,
/// issuer state, and client identifiers.
pub struct OAuthParameters {
    values: BTreeMap<String, String>,
}

impl OAuthParameters {
    /// Borrows one parameter value without copying it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&String> {
        self.values.get(name)
    }

    /// Returns whether the request contains a parameter name.
    #[must_use]
    pub fn contains_key(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }
}

impl Drop for OAuthParameters {
    fn drop(&mut self) {
        for value in self.values.values_mut() {
            value.zeroize();
        }
    }
}

const MAX_OAUTH_FORM_PARAMETERS: usize = 64;
const MAX_OAUTH_FORM_KEY_BYTES: usize = 256;
const MAX_OAUTH_FORM_VALUE_BYTES: usize = 16_384;
const MAX_DPOP_HEADER_BYTES: usize = 16_384;
const MAX_CLIENT_ATTESTATION_HEADER_BYTES: usize = 32_768;

/// Parses an `application/x-www-form-urlencoded` OAuth request body.
///
/// Duplicate names are rejected; decoded components have explicit size and
/// UTF-8 policies.
pub fn parse_oauth_form(body: &[u8]) -> OAuthHttpResult<OAuthParameters> {
    let mut parameters = OAuthParameters {
        values: BTreeMap::new(),
    };
    if body.is_empty() {
        return Ok(parameters);
    }
    let mut parameter_count = 0_usize;
    for field in body.split(|byte| *byte == b'&') {
        parameter_count = parameter_count.checked_add(1).ok_or_else(invalid_request)?;
        if parameter_count > MAX_OAUTH_FORM_PARAMETERS || field.is_empty() {
            return Err(invalid_request());
        }
        let separator = field
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(invalid_request)?;
        let value_offset = separator.checked_add(1).ok_or_else(invalid_request)?;
        let key = decode_form_component(
            field.get(..separator).ok_or_else(invalid_request)?,
            MAX_OAUTH_FORM_KEY_BYTES,
        )?;
        let value = decode_form_component(
            field.get(value_offset..).ok_or_else(invalid_request)?,
            MAX_OAUTH_FORM_VALUE_BYTES,
        )?;
        if key.is_empty() || parameters.contains_key(&key) {
            return Err(invalid_request());
        }
        parameters.values.insert(key, value);
    }
    Ok(parameters)
}

fn decode_form_component(input: &[u8], max_bytes: usize) -> OAuthHttpResult<String> {
    if input.len() > max_bytes {
        return Err(invalid_request());
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut offset = 0_usize;
    while offset < input.len() {
        let byte = *input.get(offset).ok_or_else(invalid_request)?;
        if byte == b'%' {
            let high_offset = offset.checked_add(1).ok_or_else(invalid_request)?;
            let low_offset = offset.checked_add(2).ok_or_else(invalid_request)?;
            let next_offset = offset.checked_add(3).ok_or_else(invalid_request)?;
            let high = form_hex_nibble(*input.get(high_offset).ok_or_else(invalid_request)?)?;
            let low = form_hex_nibble(*input.get(low_offset).ok_or_else(invalid_request)?)?;
            decoded.push((high << 4) | low);
            offset = next_offset;
        } else {
            decoded.push(if byte == b'+' { b' ' } else { byte });
            offset = offset.checked_add(1).ok_or_else(invalid_request)?;
        }
        if decoded.len() > max_bytes {
            return Err(invalid_request());
        }
    }
    match String::from_utf8(core::mem::take(&mut *decoded)) {
        Ok(value) => Ok(value),
        Err(error) => {
            let _rejected = Zeroizing::new(error.into_bytes());
            Err(invalid_request())
        }
    }
}

fn form_hex_nibble(value: u8) -> OAuthHttpResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid_request()),
    }
}

fn invalid_request() -> OAuthHttpError {
    OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest)
}

/// OAuth HTTP adapter result.
pub type OAuthHttpResult<T> = Result<T, OAuthHttpError>;

/// Bounded OAuth response serialization result.
pub type OAuthResponseResult<T> = Result<T, OAuthResponseEncodingError>;

/// Stable OAuth response serialization failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OAuthResponseEncodingError {
    /// Serde could not encode the typed response.
    #[error("response_encoding_failed")]
    EncodingFailed,
    /// The encoded response exceeded the adapter output limit.
    #[error("response_too_large")]
    OutputTooLarge,
}

/// Stable OAuth adapter error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{reason}")]
pub struct OAuthHttpError {
    /// Typed reason exposed to HTTP error mapping.
    pub reason: OAuthHttpErrorReason,
}

impl OAuthHttpError {
    /// Creates a stable OAuth HTTP error.
    #[must_use]
    pub const fn new(reason: OAuthHttpErrorReason) -> Self {
        Self { reason }
    }
}

/// Non-secret OAuth adapter error reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OAuthHttpErrorReason {
    /// The optional authorization server adapter was not configured.
    #[error("authorization_server_unavailable")]
    AuthorizationServerUnavailable,
    /// The request omitted a required parameter.
    #[error("invalid_request")]
    InvalidRequest,
    /// The authorization code is unknown, expired, already used, or not bound
    /// to the presented client.
    #[error("invalid_grant")]
    InvalidGrant,
    /// The client authentication material is missing or invalid.
    #[error("invalid_client")]
    InvalidClient,
    /// The request violates PAR policy.
    #[error("invalid_pushed_authorization_request")]
    InvalidPushedAuthorizationRequest,
    /// The DPoP proof is missing, malformed, or not bound to this request.
    #[error("invalid_dpop_proof")]
    InvalidDpopProof,
    /// The pushed request URI is unknown, expired, already used, or not valid
    /// for this authorization request.
    #[error("invalid_request_uri")]
    InvalidRequestUri,
    /// The access token does not authorize the selected credential.
    #[error("insufficient_authorization")]
    InsufficientAuthorization,
}

/// Trusted OAuth authorization-server operations used by the issuer adapter.
///
/// Capability declarations are checked at composition and proved by provider contract tests.
pub trait OAuthAuthorizationServer: Send + Sync {
    /// Declares security behavior enforced by this trusted provider.
    ///
    /// Router construction rejects declarations below the composition policy;
    /// provider contract tests must detect false declarations.
    fn security_capabilities(&self) -> OAuthAuthorizationServerCapabilities;

    /// Handles RFC 9126 Pushed Authorization Requests.
    fn pushed_authorization_request(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
    ) -> OAuthHttpResult<PushedAuthorizationResponse>;

    /// Handles Authorization Endpoint requests.
    ///
    /// Implementations return an explicit [`AuthorizationResponse`] for any
    /// success or protocol error that may be redirected to a previously
    /// validated client callback. Returning [`OAuthHttpError`] always produces
    /// a direct response and never trusts request parameters as a redirect
    /// destination.
    fn authorize(&self, parameters: &OAuthParameters) -> OAuthHttpResult<AuthorizationResponse>;

    /// Handles Authorization Code token requests.
    fn token(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
    ) -> OAuthHttpResult<TokenResponse>;
}

/// Security-relevant HTTP headers supplied to OAuth AS routes.
pub struct OAuthRequestHeaders {
    /// Optional DPoP proof value.
    dpop: Option<String>,
    /// Optional OAuth client attestation JWT.
    client_attestation: Option<String>,
    /// Optional OAuth client attestation proof JWT.
    client_attestation_pop: Option<String>,
}

impl OAuthRequestHeaders {
    pub(crate) fn new(
        dpop: Option<String>,
        client_attestation: Option<String>,
        client_attestation_pop: Option<String>,
    ) -> OAuthHttpResult<Self> {
        validate_optional_header(&dpop, MAX_DPOP_HEADER_BYTES)?;
        validate_optional_header(&client_attestation, MAX_CLIENT_ATTESTATION_HEADER_BYTES)?;
        validate_optional_header(&client_attestation_pop, MAX_DPOP_HEADER_BYTES)?;
        Ok(Self {
            dpop,
            client_attestation,
            client_attestation_pop,
        })
    }

    /// Returns the optional DPoP proof without transferring its owner.
    #[must_use]
    pub fn dpop(&self) -> Option<&str> {
        self.dpop.as_deref()
    }

    /// Returns the optional client attestation without transferring its owner.
    #[must_use]
    pub fn client_attestation(&self) -> Option<&str> {
        self.client_attestation.as_deref()
    }

    /// Returns the optional client-attestation proof without transferring its owner.
    #[must_use]
    pub fn client_attestation_pop(&self) -> Option<&str> {
        self.client_attestation_pop.as_deref()
    }
}

impl Drop for OAuthRequestHeaders {
    fn drop(&mut self) {
        self.dpop.zeroize();
        self.client_attestation.zeroize();
        self.client_attestation_pop.zeroize();
    }
}

fn validate_optional_header(value: &Option<String>, limit: usize) -> OAuthHttpResult<()> {
    if value.as_ref().is_some_and(|header| header.len() > limit) {
        return Err(invalid_request());
    }
    Ok(())
}

/// Successful PAR response.
#[derive(Serialize)]
pub struct PushedAuthorizationResponse {
    /// Opaque request URI accepted by the AS.
    pub request_uri: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
}

impl PushedAuthorizationResponse {
    /// Creates a response whose opaque request URI remains owned by this value.
    #[must_use]
    pub fn new(request_uri: String, expires_in: u64) -> Self {
        Self {
            request_uri,
            expires_in,
        }
    }

    /// Serializes a PAR response through the bounded OAuth JSON boundary.
    pub fn to_json(&self) -> OAuthResponseResult<String> {
        serialize_response(self)
    }
}

impl Drop for PushedAuthorizationResponse {
    fn drop(&mut self) {
        self.request_uri.zeroize();
    }
}

/// Authorization Endpoint action.
pub enum AuthorizationResponse {
    /// Redirect the wallet/user-agent back to the supplied client redirect URI.
    Redirect {
        /// Absolute redirect target.
        location: String,
    },
}

impl AuthorizationResponse {
    /// Creates a redirect while retaining ownership of the code-bearing URI.
    #[must_use]
    pub fn redirect(location: String) -> Self {
        Self::Redirect { location }
    }

    /// Borrows the redirect target without copying authorization material.
    #[must_use]
    pub fn location(&self) -> &str {
        match self {
            Self::Redirect { location } => location,
        }
    }
}

impl Drop for AuthorizationResponse {
    fn drop(&mut self) {
        match self {
            Self::Redirect { location } => location.zeroize(),
        }
    }
}

/// Successful Token Endpoint response.
#[derive(Serialize)]
pub struct TokenResponse {
    /// Access token value.
    pub access_token: String,
    /// Token type. HAIP/FAPI DPoP flows use `DPoP`.
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// Optional refresh token issued by the Authorization Server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Optional OpenID4VCI authorization details response.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_details: Vec<serde_json::Value>,
}

impl TokenResponse {
    /// Creates a token response whose bearer material is zeroized on drop.
    #[must_use]
    pub fn new(
        access_token: String,
        token_type: String,
        expires_in: u64,
        authorization_details: Vec<serde_json::Value>,
    ) -> Self {
        Self {
            access_token,
            token_type,
            expires_in,
            refresh_token: None,
            authorization_details,
        }
    }

    /// Adds a refresh token to the response while preserving its zeroizing owner.
    #[must_use]
    pub fn with_refresh_token(mut self, refresh_token: String) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    /// Serializes a token response through the bounded OAuth JSON boundary.
    pub fn to_json(&self) -> OAuthResponseResult<String> {
        serialize_response(self)
    }
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        for detail in &mut self.authorization_details {
            zeroize_json_strings(detail);
        }
    }
}

fn zeroize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(values) => {
            for nested in values {
                zeroize_json_strings(nested);
            }
        }
        serde_json::Value::Object(values) => {
            for nested in values.values_mut() {
                zeroize_json_strings(nested);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// OAuth error response body.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OAuthErrorBody {
    /// OAuth error code.
    pub error: &'static str,
}

impl OAuthErrorBody {
    /// Serializes an OAuth error through the bounded OAuth JSON boundary.
    pub fn to_json(&self) -> OAuthResponseResult<String> {
        serialize_response(self)
    }
}

fn serialize_response<T: Serialize>(value: &T) -> OAuthResponseResult<String> {
    let mut output = Zeroizing::new(
        serde_json::to_string(value).map_err(|_| OAuthResponseEncodingError::EncodingFailed)?,
    );
    if output.len() > MAX_OAUTH_RESPONSE_JSON_BYTES {
        return Err(OAuthResponseEncodingError::OutputTooLarge);
    }
    Ok(core::mem::take(&mut *output))
}

#[path = "tests/serve_oauth_tests.rs"]
#[cfg(test)]
mod serve_oauth_tests;
