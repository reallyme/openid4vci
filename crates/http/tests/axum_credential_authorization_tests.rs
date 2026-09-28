// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected Credential Endpoint access-token authorization tests.

#![cfg(feature = "axum")]

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use openid4vci_http::{default_max_body_bytes, issuer_router, AxumIssuerState};
use reallyme_openid_oauth::{OAUTH_CLIENT_ATTESTATION_HEADER, OAUTH_CLIENT_ATTESTATION_POP_HEADER};
use tower::ServiceExt;

#[path = "support/exercise_axum_issuer.rs"]
mod exercise_axum_issuer;

use exercise_axum_issuer::{
    response_body, secured_state_with_resource_authorization, security_headers, RouteTestError,
    TestResourceAuthorization,
};

const CREDENTIAL_URI: &str = "https://issuer.example/credential";

#[tokio::test]
async fn authorized_configuration_reaches_canonical_issuer() -> Result<(), RouteTestError> {
    let response = credential_request(
        secured_state_with_resource_authorization(TestResourceAuthorization::SdJwtPid)?,
        br#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#.to_vec(),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn cross_configuration_substitution_is_denied_before_issuance() -> Result<(), RouteTestError>
{
    let response = credential_request(
        secured_state_with_resource_authorization(TestResourceAuthorization::SdJwtPid)?,
        br#"{"credential_configuration_id":"pid-mdoc","proofs":{"jwt":["a.b.c"]}}"#.to_vec(),
    )
    .await?;

    assert_credential_denied(response).await
}

#[tokio::test]
async fn missing_credential_authorization_is_denied_before_issuance() -> Result<(), RouteTestError>
{
    let response = credential_request(
        secured_state_with_resource_authorization(TestResourceAuthorization::None)?,
        br#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#.to_vec(),
    )
    .await?;

    assert_credential_denied(response).await
}

#[tokio::test]
async fn unknown_configuration_uses_credential_endpoint_error() -> Result<(), RouteTestError> {
    let response = credential_request(
        secured_state_with_resource_authorization(TestResourceAuthorization::SdJwtPid)?,
        br#"{"credential_configuration_id":"unknown","proofs":{"jwt":["a.b.c"]}}"#.to_vec(),
    )
    .await?;

    assert_credential_error(response, "unknown_credential_configuration").await
}

#[tokio::test]
async fn unknown_identifier_uses_credential_endpoint_error() -> Result<(), RouteTestError> {
    let response = credential_request(
        secured_state_with_resource_authorization(TestResourceAuthorization::SdJwtPid)?,
        br#"{"credential_identifier":"unknown","proofs":{"jwt":["a.b.c"]}}"#.to_vec(),
    )
    .await?;

    assert_credential_error(response, "unknown_credential_identifier").await
}

#[tokio::test]
async fn malformed_selector_fails_before_resource_authorization() -> Result<(), RouteTestError> {
    let response = credential_request(
        secured_state_with_resource_authorization(TestResourceAuthorization::SdJwtPid)?,
        br#"{"credential_configuration_id":"pid","credential_identifier":"pid-credential-1","proofs":{"jwt":["a.b.c"]}}"#.to_vec(),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_body(response).await?;
    let error: serde_json::Value = serde_json::from_str(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        error.get("error").and_then(serde_json::Value::as_str),
        Some("invalid_credential_request")
    );
    Ok(())
}

#[tokio::test]
async fn oversized_request_fails_before_resource_authorization() -> Result<(), RouteTestError> {
    let oversized_length = default_max_body_bytes()
        .checked_add(1)
        .ok_or(RouteTestError::Request)?;
    let response = credential_request(
        secured_state_with_resource_authorization(TestResourceAuthorization::SdJwtPid)?,
        vec![b'a'; oversized_length],
    )
    .await?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}

async fn credential_request(
    state: AxumIssuerState,
    body: Vec<u8>,
) -> Result<Response, RouteTestError> {
    let headers = security_headers(CREDENTIAL_URI)?;
    issuer_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .header("dpop", headers.dpop)
                .header(AUTHORIZATION, headers.authorization)
                .header(OAUTH_CLIENT_ATTESTATION_HEADER, headers.client_attestation)
                .header(
                    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
                    headers.client_attestation_pop,
                )
                .body(Body::from(body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)
}

async fn assert_credential_denied(response: Response) -> Result<(), RouteTestError> {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_body(response).await?;
    let error: serde_json::Value = serde_json::from_str(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        error.get("error").and_then(serde_json::Value::as_str),
        Some("insufficient_scope")
    );
    Ok(())
}

async fn assert_credential_error(
    response: Response,
    expected_error: &str,
) -> Result<(), RouteTestError> {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_body(response).await?;
    let error: serde_json::Value = serde_json::from_str(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        error.get("error").and_then(serde_json::Value::as_str),
        Some(expected_error)
    );
    Ok(())
}
