// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reads bounded request bodies and builds protocol-correct responses.

use axum::body::{to_bytes, Body};
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, LOCATION, VARY, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use openid4vci_issuer::{
    decrypt_credential_request_json, CredentialRequestJson, CredentialResponseBody, IssuerError,
};
use openid4vci_types::problem::PROBLEM_JSON_CONTENT_TYPE;
use openid4vci_types::{
    CredentialErrorCode, CredentialErrorResponse, DeferredCredentialErrorCode,
    DeferredCredentialErrorResponse, IssuerProblemStatus, NotificationErrorCode,
    NotificationErrorResponse, ProblemDetails, ProblemType,
};
use zeroize::{Zeroize, Zeroizing};

use crate::media_type::has_content_type;
use crate::serve_oauth::{
    parse_oauth_form, OAuthErrorBody, OAuthHttpError, OAuthHttpErrorReason, OAuthParameters,
    OAuthRequestHeaders,
};

use super::configure::AxumIssuerState;

pub(crate) const APPLICATION_JSON: &str = "application/json";
const APPLICATION_JWT: &str = "application/jwt";
const NO_STORE: &str = "no-store";
const METADATA_CACHE_CONTROL: &str = "public, max-age=3600";
const PROBLEM_SERIALIZATION_FALLBACK: &str =
    "{\"type\":\"about:blank\",\"title\":\"server_error\",\"status\":500,\"error\":\"server_error\"}";

pub(crate) async fn read_json_body(
    request: Request<Body>,
    limit: usize,
) -> Result<Zeroizing<String>, ProblemDetails> {
    let mut bytes = read_body_bytes(request, limit).await?;
    match String::from_utf8(core::mem::take(&mut *bytes)) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let mut invalid_bytes = error.into_bytes();
            invalid_bytes.zeroize();
            Err(ProblemDetails::new(ProblemType::InvalidRequest, None))
        }
    }
}

/// Returns whether the request body is an encrypted Credential Request
/// (`Content-Type: application/jwt`, a compact JWE) rather than plaintext JSON.
pub(crate) fn request_body_is_encrypted(headers: &HeaderMap) -> bool {
    has_content_type(headers, APPLICATION_JWT)
}

/// Reads the request body as JSON, decrypting first when the body is an
/// encrypted (`application/jwt`) Credential Request. Fails closed if an
/// encrypted body arrives but no request decryptor is configured.
pub(crate) async fn read_request_body(
    request: Request<Body>,
    state: &AxumIssuerState,
    encrypted: bool,
) -> Result<CredentialRequestJson, ProblemDetails> {
    if !encrypted {
        let mut value = read_json_body(request, state.max_body_bytes).await?;
        return CredentialRequestJson::new(core::mem::take(&mut *value))
            .map_err(issuer_problem_details);
    }
    let decryptor = state
        .request_decryptor
        .as_ref()
        .ok_or_else(|| ProblemDetails::new(ProblemType::ServerError, None))?;
    let compact_jwe = read_json_body(request, state.max_body_bytes).await?;
    decrypt_credential_request_json(decryptor.as_ref(), &compact_jwe)
        .map_err(issuer_problem_details)
}

pub(crate) fn issuer_problem_details(error: IssuerError) -> ProblemDetails {
    ProblemDetails::from_issuer_status(IssuerProblemStatus::from(error.status()), None)
}

pub(crate) async fn read_body_bytes(
    request: Request<Body>,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, ProblemDetails> {
    let bytes = to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| ProblemDetails::new(ProblemType::PayloadTooLarge, None))?;
    // Move the boundary into an explicitly zeroizing owner immediately. Axum
    // may return shared `Bytes`, so request validity must not depend on whether
    // its backing allocation happens to be uniquely owned. When uniqueness is
    // available, wipe that source allocation as an additional best effort.
    let owned = Zeroizing::new(bytes.to_vec());
    if let Ok(mut mutable) = bytes.try_into_mut() {
        mutable.as_mut().zeroize();
    }
    Ok(owned)
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OAuthFormReadError {
    #[error("invalid_form")]
    Invalid,
    #[error("form_too_large")]
    PayloadTooLarge,
}

pub(crate) async fn read_oauth_form(
    request: Request<Body>,
    limit: usize,
) -> Result<OAuthParameters, OAuthFormReadError> {
    if !has_form_content_type(request.headers()) {
        return Err(OAuthFormReadError::Invalid);
    }
    let body = read_body_bytes(request, limit).await.map_err(|problem| {
        if problem.status == StatusCode::PAYLOAD_TOO_LARGE.as_u16() {
            OAuthFormReadError::PayloadTooLarge
        } else {
            OAuthFormReadError::Invalid
        }
    })?;
    parse_oauth_form(&body).map_err(|_| OAuthFormReadError::Invalid)
}

pub(crate) fn has_form_content_type(headers: &HeaderMap) -> bool {
    has_content_type(headers, "application/x-www-form-urlencoded")
}

pub(crate) fn oauth_form_error_response(error: OAuthFormReadError) -> Response {
    match error {
        OAuthFormReadError::Invalid => {
            oauth_error_response(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
        }
        OAuthFormReadError::PayloadTooLarge => {
            problem_response(ProblemDetails::new(ProblemType::PayloadTooLarge, None))
        }
    }
}

pub(crate) fn json_response(status: StatusCode, body: String) -> Response {
    response_with_content_type(status, APPLICATION_JSON, body)
}

/// Serializes a public, cacheable JSON document (used for Credential Issuer
/// Metadata, which is not sender-constrained and benefits from HTTP caching).
pub(crate) fn cacheable_json_response(status: StatusCode, body: String) -> Response {
    cacheable_response(status, APPLICATION_JSON, body)
}

/// Serializes public, cacheable signed Credential Issuer Metadata.
pub(crate) fn cacheable_jwt_response(status: StatusCode, body: String) -> Response {
    cacheable_response(status, APPLICATION_JWT, body)
}

fn cacheable_response(status: StatusCode, content_type: &'static str, body: String) -> Response {
    let headers = [
        (CONTENT_TYPE, HeaderValue::from_static(content_type)),
        (
            CACHE_CONTROL,
            HeaderValue::from_static(METADATA_CACHE_CONTROL),
        ),
        (VARY, HeaderValue::from_static("Accept")),
    ];
    (status, headers, Body::from(body)).into_response()
}

/// Returns whether an Accept header explicitly requests signed metadata.
pub(crate) fn metadata_jwt_requested(headers: &HeaderMap) -> bool {
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(jwt_media_range_is_acceptable)
}

fn jwt_media_range_is_acceptable(range: &str) -> bool {
    let mut parts = range.split(';');
    let Some(media_type) = parts.next() else {
        return false;
    };
    if !media_type.trim().eq_ignore_ascii_case(APPLICATION_JWT) {
        return false;
    }
    for parameter in parts {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            return false;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            return valid_nonzero_quality(value.trim());
        }
    }
    true
}

fn valid_nonzero_quality(value: &str) -> bool {
    if value == "1" {
        return true;
    }
    if let Some(fraction) = value.strip_prefix("1.") {
        return !fraction.is_empty()
            && fraction.len() <= 3
            && fraction.bytes().all(|byte| byte == b'0');
    }
    let Some(fraction) = value.strip_prefix("0.") else {
        return false;
    };
    !fraction.is_empty()
        && fraction.len() <= 3
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().any(|byte| byte != b'0')
}

pub(crate) fn redirect_response(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(header) => {
            let headers = [(LOCATION, header)];
            (StatusCode::FOUND, headers).into_response()
        }
        Err(_) => oauth_error_response(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest)),
    }
}

pub(crate) fn authorization_error_response(error: OAuthHttpError) -> Response {
    // The adapter cannot know whether a caller-supplied redirect URI was
    // registered. An Authorization Server that has validated a callback must
    // return an explicit AuthorizationResponse; trait errors always stay on
    // the direct response channel to prevent an open redirect.
    oauth_error_response(error)
}

pub(crate) fn oauth_headers(headers: &HeaderMap) -> Result<OAuthRequestHeaders, OAuthHttpError> {
    OAuthRequestHeaders::new(
        header_to_string(headers, "DPoP")?,
        header_to_string(headers, "OAuth-Client-Attestation")?,
        header_to_string(headers, "OAuth-Client-Attestation-PoP")?,
    )
}

pub(crate) fn header_to_string(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Option<String>, OAuthHttpError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest));
    }
    value
        .to_str()
        .map(|header| Some(header.to_owned()))
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
}

pub(crate) fn oauth_error_response(error: OAuthHttpError) -> Response {
    let status = match error.reason {
        OAuthHttpErrorReason::InvalidClient => StatusCode::UNAUTHORIZED,
        OAuthHttpErrorReason::AuthorizationServerUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        OAuthHttpErrorReason::InvalidRequest
        | OAuthHttpErrorReason::InvalidGrant
        | OAuthHttpErrorReason::InvalidPushedAuthorizationRequest
        | OAuthHttpErrorReason::InvalidDpopProof
        | OAuthHttpErrorReason::InvalidRequestUri => StatusCode::BAD_REQUEST,
        OAuthHttpErrorReason::InsufficientAuthorization => StatusCode::FORBIDDEN,
    };
    let body = OAuthErrorBody {
        error: oauth_error_code(error.reason),
    };
    match body.to_json() {
        Ok(json) => json_response(status, json),
        Err(_) => response_with_content_type(
            StatusCode::INTERNAL_SERVER_ERROR,
            APPLICATION_JSON,
            "{\"error\":\"server_error\"}".to_owned(),
        ),
    }
}

pub(crate) fn oauth_error_code(reason: OAuthHttpErrorReason) -> &'static str {
    match reason {
        OAuthHttpErrorReason::AuthorizationServerUnavailable => "server_error",
        OAuthHttpErrorReason::InvalidRequest
        | OAuthHttpErrorReason::InvalidPushedAuthorizationRequest => "invalid_request",
        OAuthHttpErrorReason::InvalidGrant => "invalid_grant",
        OAuthHttpErrorReason::InvalidClient => "invalid_client",
        OAuthHttpErrorReason::InvalidDpopProof => "invalid_dpop_proof",
        OAuthHttpErrorReason::InvalidRequestUri => "invalid_request_uri",
        OAuthHttpErrorReason::InsufficientAuthorization => "insufficient_scope",
    }
}

/// Empty `204 No Content` response for the Notification Endpoint success case.
pub(crate) fn no_content_response() -> Response {
    let headers = [(CACHE_CONTROL, HeaderValue::from_static(NO_STORE))];
    (StatusCode::NO_CONTENT, headers).into_response()
}

pub(crate) fn credential_response_body(
    body: CredentialResponseBody,
) -> openid4vci_issuer::IssuerResult<Response> {
    // OpenID4VCI 1.0 §8.3 / §9.2: a still-pending deferred response uses HTTP 202.
    let status = if body.is_deferred() {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    match body {
        CredentialResponseBody::Json(response) => response
            .to_json()
            .map(|body| json_response(status, body))
            .map_err(|_| {
                openid4vci_issuer::IssuerError::new(openid4vci_issuer::IssuerStatus::EncodingFailed)
            }),
        CredentialResponseBody::Jwt { encrypted, .. } => Ok(response_with_content_type(
            status,
            APPLICATION_JWT,
            encrypted.into_string(),
        )),
    }
}

pub(crate) fn problem_response(problem: ProblemDetails) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = match problem.to_json() {
        Ok(body) => body,
        Err(_) => PROBLEM_SERIALIZATION_FALLBACK.to_owned(),
    };
    response_with_content_type(status, PROBLEM_JSON_CONTENT_TYPE, body)
}

pub(crate) fn invalid_token_response(dpop_required: bool) -> Response {
    let challenge = if dpop_required {
        HeaderValue::from_static("DPoP error=\"invalid_token\"")
    } else {
        HeaderValue::from_static("Bearer error=\"invalid_token\"")
    };
    let headers = [
        (WWW_AUTHENTICATE, challenge),
        (CACHE_CONTROL, HeaderValue::from_static(NO_STORE)),
        (CONTENT_TYPE, HeaderValue::from_static(APPLICATION_JSON)),
    ];
    (
        StatusCode::UNAUTHORIZED,
        headers,
        "{\"error\":\"invalid_token\"}",
    )
        .into_response()
}

pub(crate) fn credential_error_response(problem: ProblemDetails) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = CredentialErrorResponse {
        error: credential_error_code(problem.error.as_deref()),
        error_description: None,
    };
    match body.to_json() {
        Ok(json) => json_response(status, json),
        Err(_) => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
    }
}

pub(crate) fn deferred_credential_error_response(problem: ProblemDetails) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let error = match problem.error.as_deref() {
        Some("invalid_transaction_id") => DeferredCredentialErrorCode::InvalidTransactionId,
        Some("invalid_encryption_parameters") => {
            DeferredCredentialErrorCode::InvalidEncryptionParameters
        }
        Some("credential_request_denied") => DeferredCredentialErrorCode::CredentialRequestDenied,
        _ => DeferredCredentialErrorCode::InvalidCredentialRequest,
    };
    match (DeferredCredentialErrorResponse { error }).to_json() {
        Ok(json) => json_response(status, json),
        Err(_) => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
    }
}

pub(crate) fn notification_error_response(problem: ProblemDetails) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let error = match problem.error.as_deref() {
        Some("invalid_notification_id") => NotificationErrorCode::InvalidNotificationId,
        _ => NotificationErrorCode::InvalidNotificationRequest,
    };
    match (NotificationErrorResponse { error }).to_json() {
        Ok(json) => json_response(status, json),
        Err(_) => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
    }
}

pub(crate) fn credential_error_code(code: Option<&str>) -> CredentialErrorCode {
    match code {
        Some("invalid_proof") => CredentialErrorCode::InvalidProof,
        Some("invalid_nonce") => CredentialErrorCode::InvalidNonce,
        Some("unknown_credential_configuration") => {
            CredentialErrorCode::UnknownCredentialConfiguration
        }
        Some("unknown_credential_identifier") => CredentialErrorCode::UnknownCredentialIdentifier,
        Some("invalid_encryption_parameters") => CredentialErrorCode::InvalidEncryptionParameters,
        Some("credential_request_denied") => CredentialErrorCode::CredentialRequestDenied,
        _ => CredentialErrorCode::InvalidCredentialRequest,
    }
}

pub(crate) fn response_with_content_type<B>(
    status: StatusCode,
    content_type: &'static str,
    body: B,
) -> Response
where
    B: Into<Body>,
{
    let headers = [
        (CONTENT_TYPE, HeaderValue::from_static(content_type)),
        (CACHE_CONTROL, HeaderValue::from_static(NO_STORE)),
    ];
    (status, headers, body.into()).into_response()
}

#[path = "../tests/axum_issuer_header_tests.rs"]
#[cfg(test)]
mod axum_issuer_header_tests;
