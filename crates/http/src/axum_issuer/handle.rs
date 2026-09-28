// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handles OpenID4VCI and OAuth HTTP routes.

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use openid4vci_issuer::{
    handle_credential_request_body, handle_deferred_credential_request_body, handle_nonce_request,
    handle_notification_request,
};
use openid4vci_types::{IssuerProblemStatus, NotificationRequest, ProblemDetails, ProblemType};

use crate::serve_oauth::{parse_oauth_form, OAuthHttpError, OAuthHttpErrorReason};
use crate::validate_access_token::CredentialAuthorizationDecision;
use crate::validate_http_security::{
    validate_http_security, HttpSecurityError, HttpSecurityValidation,
};

use super::authorize_credential_access::authorize_credential_access;
use super::configure::AxumIssuerState;
use super::respond::{
    authorization_error_response, cacheable_json_response, cacheable_jwt_response,
    credential_error_response, credential_response_body, deferred_credential_error_response,
    invalid_token_response, issuer_problem_details, json_response, metadata_jwt_requested,
    no_content_response, notification_error_response, oauth_error_response,
    oauth_form_error_response, oauth_headers, problem_response, read_json_body, read_oauth_form,
    read_request_body, redirect_response, request_body_is_encrypted,
};

pub(crate) async fn get_issuer_metadata(
    State(state): State<AxumIssuerState>,
    headers: HeaderMap,
) -> Response {
    // Credential Issuer Metadata is public and cacheable (OpenID4VCI 1.0 §11.2).
    if metadata_jwt_requested(&headers) {
        if let Some(signer) = &state.metadata_signer {
            return match signer.sign_metadata(&state.metadata, state.clock.now_unix()) {
                Ok(signed) => cacheable_jwt_response(StatusCode::OK, signed.as_str().to_owned()),
                Err(_) => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
            };
        }
    }
    match state.metadata.to_json() {
        Ok(body) => cacheable_json_response(StatusCode::OK, body),
        Err(_) => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
    }
}

pub(crate) async fn get_oauth_authorization_server_metadata(
    State(state): State<AxumIssuerState>,
) -> Response {
    match state.authorization_server_metadata {
        Some(metadata) => match metadata.to_json() {
            Ok(body) => cacheable_json_response(StatusCode::OK, body),
            Err(_) => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
        },
        None => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
    }
}

pub(crate) async fn get_openid_metadata(State(state): State<AxumIssuerState>) -> Response {
    get_oauth_authorization_server_metadata(State(state)).await
}

pub(crate) async fn post_pushed_authorization_request(
    State(state): State<AxumIssuerState>,
    request: Request<Body>,
) -> Response {
    let headers = match oauth_headers(request.headers()) {
        Ok(headers) => headers,
        Err(error) => return oauth_error_response(error),
    };
    let parameters = match read_oauth_form(request, state.max_body_bytes).await {
        Ok(parameters) => parameters,
        Err(error) => return oauth_form_error_response(error),
    };
    let Some(service) = state.oauth_authorization_server else {
        return oauth_error_response(OAuthHttpError::new(
            OAuthHttpErrorReason::AuthorizationServerUnavailable,
        ));
    };
    match service.pushed_authorization_request(&headers, &parameters) {
        Ok(value) => match value.to_json() {
            Ok(body) => json_response(StatusCode::CREATED, body),
            Err(_) => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
        },
        Err(error) => oauth_error_response(error),
    }
}

pub(crate) async fn get_authorize(
    State(state): State<AxumIssuerState>,
    request: Request<Body>,
) -> Response {
    let parameters =
        match parse_oauth_form(request.uri().query().map(str::as_bytes).unwrap_or_default()) {
            Ok(parameters) => parameters,
            Err(error) => return oauth_error_response(error),
        };
    let Some(service) = state.oauth_authorization_server else {
        return oauth_error_response(OAuthHttpError::new(
            OAuthHttpErrorReason::AuthorizationServerUnavailable,
        ));
    };
    match service.authorize(&parameters) {
        Ok(value) => redirect_response(value.location()),
        Err(error) => authorization_error_response(error),
    }
}

pub(crate) async fn post_token(
    State(state): State<AxumIssuerState>,
    request: Request<Body>,
) -> Response {
    let headers = match oauth_headers(request.headers()) {
        Ok(headers) => headers,
        Err(error) => return oauth_error_response(error),
    };
    let parameters = match read_oauth_form(request, state.max_body_bytes).await {
        Ok(parameters) => parameters,
        Err(error) => return oauth_form_error_response(error),
    };
    let Some(service) = state.oauth_authorization_server else {
        return oauth_error_response(OAuthHttpError::new(
            OAuthHttpErrorReason::AuthorizationServerUnavailable,
        ));
    };
    match service.token(&headers, &parameters) {
        Ok(value) => match value.to_json() {
            Ok(body) => json_response(StatusCode::OK, body),
            Err(_) => problem_response(ProblemDetails::new(ProblemType::ServerError, None)),
        },
        Err(error) => oauth_error_response(error),
    }
}

pub(crate) async fn post_nonce(State(state): State<AxumIssuerState>) -> Response {
    // The Nonce Endpoint is unauthenticated by design (OpenID4VCI 1.0 §7), so it
    // is intentionally not gated by `validate_http_security`.
    let issued_at = now_unix(&state);
    match handle_nonce_request(
        state.nonce_manager.as_ref(),
        issued_at,
        state.nonce_ttl_seconds,
    )
    .and_then(|nonce| {
        nonce.to_json().map_err(|_| {
            openid4vci_issuer::IssuerError::new(openid4vci_issuer::IssuerStatus::EncodingFailed)
        })
    }) {
        Ok(body) => json_response(StatusCode::OK, body),
        Err(error) => problem_response(issuer_problem_details(error)),
    }
}

/// Current Unix time as a non-negative second count for store expiry math.
pub(crate) fn now_unix(state: &AxumIssuerState) -> u64 {
    u64::try_from(state.clock.now_unix()).unwrap_or(0)
}

/// Enforces the configured DPoP and wallet-attestation policy for a protected
/// endpoint before the request body is consumed.
pub(crate) fn enforce_http_security(
    state: &AxumIssuerState,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> Result<zeroize::Zeroizing<String>, HttpSecurityError> {
    validate_http_security(
        &state.http_security,
        HttpSecurityValidation {
            dpop_verifier: state.dpop_verifier.as_ref(),
            attestation_verifier: state.attestation_client_authentication_verifier.as_ref(),
            attestation_evidence_recorder: state.wallet_attestation_evidence_recorder.as_ref(),
            access_token_validator: &state.access_token_validator,
            issuer: &state.metadata.credential_issuer,
            headers,
            uri,
        },
        state.clock.now_unix(),
    )
}

fn http_security_error_response(state: &AxumIssuerState, error: HttpSecurityError) -> Response {
    match error {
        HttpSecurityError::InvalidAccessToken => {
            invalid_token_response(state.http_security.dpop.is_some())
        }
        HttpSecurityError::Policy(problem) => problem_response(problem),
    }
}

pub(crate) async fn post_credential(
    State(state): State<AxumIssuerState>,
    OriginalUri(original_uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    let access_token = match enforce_http_security(&state, request.headers(), &original_uri) {
        Ok(value) => value,
        Err(error) => return http_security_error_response(&state, error),
    };
    let request_was_encrypted = request_body_is_encrypted(request.headers());
    let body = match read_request_body(request, &state, request_was_encrypted).await {
        Ok(body) => body,
        Err(problem) => return credential_error_response(problem),
    };
    let credential_input = match body.parse_credential_request() {
        Ok(value) => value,
        Err(error) => return credential_error_response(issuer_problem_details(error)),
    };
    let credential_request = credential_input.request();
    let selector = match credential_request.selector() {
        Ok(value) => value,
        Err(error) => return credential_error_response(ProblemDetails::from_error(error, None)),
    };
    let authorization =
        match authorize_credential_access(&state, Some(access_token.as_str()), &selector) {
            Ok(CredentialAuthorizationDecision::Authorized(context)) => context,
            Ok(CredentialAuthorizationDecision::UnknownCredentialConfiguration) => {
                return credential_error_response(ProblemDetails::from_issuer_status(
                    IssuerProblemStatus::UnsupportedCredential,
                    None,
                ));
            }
            Ok(CredentialAuthorizationDecision::UnknownCredentialIdentifier) => {
                return credential_error_response(ProblemDetails::from_issuer_status(
                    IssuerProblemStatus::UnknownCredentialIdentifier,
                    None,
                ));
            }
            Ok(CredentialAuthorizationDecision::InsufficientAuthorization) => {
                return oauth_error_response(OAuthHttpError::new(
                    OAuthHttpErrorReason::InsufficientAuthorization,
                ));
            }
            Err(problem) => return oauth_error_response(problem),
        };
    let Some(credential_config) = state
        .credential_configs
        .get(authorization.credential_configuration_id())
    else {
        return credential_error_response(ProblemDetails::from_issuer_status(
            IssuerProblemStatus::UnsupportedCredential,
            None,
        ));
    };
    match handle_credential_request_body(
        &authorization,
        &credential_input,
        credential_config,
        state.proof_verifier.as_ref(),
        state.credential_issuer.as_ref(),
        state.response_encryptor.as_ref(),
        state.nonce_manager.as_ref(),
        now_unix(&state),
    )
    .and_then(credential_response_body)
    {
        Ok(response) => response,
        Err(error) => credential_error_response(issuer_problem_details(error)),
    }
}

pub(crate) async fn post_deferred_credential(
    State(state): State<AxumIssuerState>,
    OriginalUri(original_uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    let access_token = match enforce_http_security(&state, request.headers(), &original_uri) {
        Ok(value) => value,
        Err(error) => return http_security_error_response(&state, error),
    };
    let request_was_encrypted = request_body_is_encrypted(request.headers());
    let body = match read_request_body(request, &state, request_was_encrypted).await {
        Ok(body) => body,
        Err(problem) => return deferred_credential_error_response(problem),
    };
    let deferred_input = match body.parse_deferred_credential_request() {
        Ok(value) => value,
        Err(error) => return deferred_credential_error_response(issuer_problem_details(error)),
    };
    let deferred_request = deferred_input.request();
    let authorization = match state
        .access_token_validator
        .authorize_deferred_credential_request(&access_token, &deferred_request.transaction_id)
    {
        Ok(value) => value,
        Err(error) => return oauth_error_response(error),
    };
    let Some(credential_config) = state
        .credential_configs
        .get(authorization.credential_configuration_id())
    else {
        return deferred_credential_error_response(ProblemDetails::from_issuer_status(
            IssuerProblemStatus::UnsupportedCredential,
            None,
        ));
    };
    match handle_deferred_credential_request_body(
        &authorization,
        &deferred_input,
        credential_config,
        state.deferred_issuer.as_ref(),
        state.response_encryptor.as_ref(),
    )
    .and_then(credential_response_body)
    {
        Ok(response) => response,
        Err(error) => deferred_credential_error_response(issuer_problem_details(error)),
    }
}

pub(crate) async fn post_notification(
    State(state): State<AxumIssuerState>,
    OriginalUri(original_uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    // The Notification Endpoint is an OAuth protected resource (OpenID4VCI 1.0
    // §11.1), so it is sender-constrained under the same policy as issuance.
    let access_token = match enforce_http_security(&state, request.headers(), &original_uri) {
        Ok(value) => value,
        Err(error) => return http_security_error_response(&state, error),
    };
    let body = match read_json_body(request, state.max_body_bytes).await {
        Ok(body) => body,
        Err(problem) => return notification_error_response(problem),
    };
    let notification = match NotificationRequest::parse_json(&body) {
        Ok(value) => value,
        Err(error) => return notification_error_response(ProblemDetails::from_error(error, None)),
    };
    if let Err(error) = state
        .access_token_validator
        .authorize_notification_request(&access_token, &notification.notification_id)
    {
        return oauth_error_response(error);
    }
    match handle_notification_request(&notification, state.notification_handler.as_ref()) {
        // OpenID4VCI 1.0 §11.2 requires 204 No Content on success.
        Ok(()) => no_content_response(),
        Err(error) => notification_error_response(issuer_problem_details(error)),
    }
}
