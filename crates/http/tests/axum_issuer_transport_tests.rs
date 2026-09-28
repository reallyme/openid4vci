// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public transport and negative-route tests for the Axum issuer.

#![cfg(feature = "axum")]

use axum::body::Body;
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, VARY, WWW_AUTHENTICATE,
};
use axum::http::{Request, StatusCode};
use openid4vci_http::{default_max_body_bytes, issuer_router};
use openid4vci_types::ProblemDetails;
use reallyme_openid_oauth::{OAUTH_CLIENT_ATTESTATION_HEADER, OAUTH_CLIENT_ATTESTATION_POP_HEADER};
use tower::ServiceExt;

#[path = "support/exercise_axum_issuer.rs"]
mod exercise_axum_issuer;

use exercise_axum_issuer::{response_body, secured_state, security_headers, state, RouteTestError};

const CONNECT_ROUTES: &[&str] = &[
    "/reallyme.openid4vci.v1.OpenId4VciIssuerService/GetNonce",
    "/reallyme.openid4vci.v1.OpenId4VciIssuerService/PreflightCredential",
    "/reallyme.openid4vci.v1.OpenId4VciIssuerService/IssueCredential",
    "/reallyme.openid4vci.v1.OpenId4VciIssuerService/GetDeferredCredential",
    "/reallyme.openid4vci.v1.OpenId4VciIssuerService/Notify",
];

#[tokio::test]
async fn internal_connect_service_is_not_exposed_by_public_router() -> Result<(), RouteTestError> {
    let router = issuer_router(state()?);
    for route in CONNECT_ROUTES {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(*route)
                    .header(CONTENT_TYPE, "application/proto")
                    .body(Body::empty())
                    .map_err(|_| RouteTestError::Request)?,
            )
            .await
            .map_err(|_| RouteTestError::Response)?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    Ok(())
}

#[tokio::test]
async fn protected_resource_rejects_missing_access_token() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#,
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer error=\"invalid_token\"")
    );
    Ok(())
}

#[tokio::test]
async fn unauthenticated_nonce_endpoint_does_not_use_a_global_starvation_bucket(
) -> Result<(), RouteTestError> {
    let router = issuer_router(state()?);
    for _ in 0..256 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/nonce")
                    .body(Body::empty())
                    .map_err(|_| RouteTestError::Request)?,
            )
            .await
            .map_err(|_| RouteTestError::Response)?;
        assert_eq!(response.status(), StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn secured_notification_endpoint_requires_dpop_header() -> Result<(), RouteTestError> {
    let response = issuer_router(secured_state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/notification")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"notification_id":"notification-1","event":"credential_accepted"}"#,
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("DPoP error=\"invalid_token\"")
    );
    Ok(())
}

#[tokio::test]
async fn notification_endpoint_returns_no_content_on_success() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/notification")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(
                    r#"{"notification_id":"notification-1","event":"credential_accepted"}"#,
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response_body(response).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn notification_endpoint_rejects_non_utf8_body() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/notification")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(vec![0xff_u8, 0xfe_u8, 0xfd_u8]))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn notification_endpoint_rejects_oversized_body() -> Result<(), RouteTestError> {
    let body = vec![b'a'; default_max_body_bytes() + 1];
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/notification")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}

#[tokio::test]
async fn secured_credential_rejects_duplicate_security_headers() -> Result<(), RouteTestError> {
    let headers = security_headers("https://issuer.example/credential")?;
    let response = issuer_router(secured_state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .header("dpop", headers.dpop.clone())
                .header("dpop", headers.dpop)
                .header(AUTHORIZATION, headers.authorization)
                .header(OAUTH_CLIENT_ATTESTATION_HEADER, headers.client_attestation)
                .header(
                    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
                    headers.client_attestation_pop,
                )
                .body(Body::from(
                    r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#,
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = serde_json::from_str::<ProblemDetails>(&response_body(response).await?)
        .map_err(|_| RouteTestError::Json)?;
    assert_eq!(problem.error.as_deref(), Some("invalid_proof"));
    Ok(())
}

#[tokio::test]
async fn secured_credential_endpoint_rejects_duplicate_wallet_attestation_headers(
) -> Result<(), RouteTestError> {
    assert_duplicate_wallet_header_rejected(OAUTH_CLIENT_ATTESTATION_HEADER).await
}

#[tokio::test]
async fn secured_credential_endpoint_rejects_duplicate_wallet_attestation_pop_headers(
) -> Result<(), RouteTestError> {
    assert_duplicate_wallet_header_rejected(OAUTH_CLIENT_ATTESTATION_POP_HEADER).await
}

async fn assert_duplicate_wallet_header_rejected(
    duplicated_header: &'static str,
) -> Result<(), RouteTestError> {
    let headers = security_headers("https://issuer.example/credential")?;
    let request = Request::builder()
        .method("POST")
        .uri("/credential")
        .header(CONTENT_TYPE, "application/json")
        .header("dpop", headers.dpop)
        .header(AUTHORIZATION, headers.authorization)
        .header(
            OAUTH_CLIENT_ATTESTATION_HEADER,
            headers.client_attestation.clone(),
        )
        .header(
            OAUTH_CLIENT_ATTESTATION_POP_HEADER,
            headers.client_attestation_pop.clone(),
        )
        .header(
            duplicated_header,
            if duplicated_header == OAUTH_CLIENT_ATTESTATION_HEADER {
                headers.client_attestation
            } else {
                headers.client_attestation_pop
            },
        );
    let response = issuer_router(secured_state()?)
        .oneshot(
            request
                .body(Body::from(
                    r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#,
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn metadata_endpoint_sets_representation_cache_key() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .header(ACCEPT, "application/json")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=3600")
    );
    assert_eq!(
        response
            .headers()
            .get(VARY)
            .and_then(|value| value.to_str().ok()),
        Some("Accept")
    );
    Ok(())
}
