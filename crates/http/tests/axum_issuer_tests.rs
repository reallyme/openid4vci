// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Axum issuer route tests.

#![cfg(feature = "axum")]

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use axum::http::{Request, StatusCode};
use axum::Router;
use openid4vci_http::{
    issuer_router, issuer_router_at_path, AxumIssuerError, AxumIssuerSecurityPolicy,
    AxumIssuerState,
};
use openid4vci_types::{
    CredentialErrorResponse, CredentialResponse, IssuerMetadata, NonceResponse, ProblemDetails,
};
use reallyme_openid_oauth::{
    AuthorizationServerMetadata, OAUTH_CLIENT_ATTESTATION_HEADER,
    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
};
use serde_json::{json, Value};

use tower::ServiceExt;

#[path = "support/exercise_axum_issuer.rs"]
mod exercise_axum_issuer;

use exercise_axum_issuer::{
    parts, response_body, secured_state, security_headers, state,
    state_with_authorization_server_metadata, state_with_authorization_server_routes,
    RouteTestError, ISSUER, TEST_NONCE,
};

#[test]
fn router_rejects_runtime_policy_that_weakens_published_metadata() -> Result<(), RouteTestError> {
    let mut parts = parts()?;
    let config = parts
        .credential_configs
        .get_mut("pid")
        .ok_or(RouteTestError::State)?;
    config.proof_required = false;

    assert_eq!(
        AxumIssuerState::new(parts).err(),
        Some(AxumIssuerError::InvalidCredentialPolicy)
    );
    Ok(())
}

#[test]
fn router_rejects_unsatisfied_high_assurance_policy() -> Result<(), RouteTestError> {
    let mut parts = parts()?;
    parts.security_policy = AxumIssuerSecurityPolicy::new(true, true, true, true)
        .with_haip_authorization_server_controls();

    assert_eq!(
        AxumIssuerState::new(parts).err(),
        Some(AxumIssuerError::UnsatisfiedSecurityPolicy)
    );
    Ok(())
}

#[tokio::test]
async fn missing_access_token_returns_bearer_challenge() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::empty())
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
async fn metadata_endpoint_serves_final_spec_document() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await?;
    let metadata = IssuerMetadata::parse_json(&body).map_err(|_| RouteTestError::Json)?;

    assert_eq!(metadata.credential_issuer, ISSUER);
    assert_eq!(
        metadata.nonce_endpoint.as_deref(),
        Some("https://issuer.example/nonce")
    );
    Ok(())
}

#[tokio::test]
async fn unconfigured_path_scoped_metadata_endpoint_is_not_routed() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer/openid4vci/example-issuer")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn configured_path_scoped_routes_follow_issuer_metadata_urls_and_rfc8615_suffix(
) -> Result<(), RouteTestError> {
    let router = issuer_router_at_path(state()?, "/openid4vci/example-issuer/")
        .map_err(|_| RouteTestError::State)?;
    let metadata_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer/openid4vci/example-issuer/")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;
    assert_eq!(metadata_response.status(), StatusCode::OK);

    let without_required_trailing_slash = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer/openid4vci/example-issuer")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;
    assert_eq!(
        without_required_trailing_slash.status(),
        StatusCode::NOT_FOUND
    );

    let nonce_response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/openid4vci/example-issuer/nonce")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;
    assert_eq!(nonce_response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn oauth_authorization_server_metadata_endpoint_uses_oauth_model(
) -> Result<(), RouteTestError> {
    let response = issuer_router(state_with_authorization_server_metadata()?)
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await?;
    let metadata =
        AuthorizationServerMetadata::parse_json(&body).map_err(|_| RouteTestError::Response)?;

    assert_eq!(metadata.issuer, ISSUER);
    assert_eq!(
        metadata.pushed_authorization_request_endpoint.as_deref(),
        Some("https://issuer.example/par")
    );
    Ok(())
}

#[tokio::test]
async fn par_route_delegates_to_configured_authorization_server() -> Result<(), RouteTestError> {
    let response = issuer_router(state_with_authorization_server_routes()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/par")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("dpop", "dpop-proof")
                .header("oauth-client-attestation", "attestation")
                .body(Body::from(
                    "client_id=client-1&redirect_uri=https%3A%2F%2Fwallet.example%2Fcb&response_type=code&code_challenge_method=S256&code_challenge=challenge",
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response_body(response).await?;
    let value = serde_json::from_str::<Value>(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        value.get("request_uri").and_then(Value::as_str),
        Some("urn:openid4vci:test-request")
    );
    assert_eq!(value.get("expires_in").and_then(Value::as_u64), Some(90));
    Ok(())
}

#[tokio::test]
async fn par_route_fails_closed_without_authorization_server() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/par")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("client_id=client-1"))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_body(response).await?;
    let value = serde_json::from_str::<Value>(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        value.get("error").and_then(Value::as_str),
        Some("server_error")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_route_returns_registered_redirect() -> Result<(), RouteTestError> {
    let response = issuer_router(state_with_authorization_server_routes()?)
        .oneshot(
            Request::builder()
                .uri("/authorize?request_uri=urn%3Aopenid4vci%3Atest-request")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example/cb?code=test-code&iss=https%3A%2F%2Fissuer.example")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_route_does_not_redirect_unvalidated_error_callback() -> Result<(), RouteTestError>
{
    let response = issuer_router(state_with_authorization_server_routes()?)
        .oneshot(
            Request::builder()
                .uri(
                    "/authorize?client_id=client-1&redirect_uri=https%3A%2F%2Fwallet.example%2Fcb&state=state%20one",
                )
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(LOCATION).is_none());
    Ok(())
}

#[tokio::test]
async fn token_route_delegates_to_configured_authorization_server() -> Result<(), RouteTestError> {
    let response = issuer_router(state_with_authorization_server_routes()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("dpop", "dpop-proof")
                .header("oauth-client-attestation", "attestation")
                .body(Body::from(
                    "grant_type=authorization_code&code=test-code&code_verifier=verifier",
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await?;
    let value = serde_json::from_str::<Value>(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        value.get("access_token").and_then(Value::as_str),
        Some("access-token")
    );
    assert_eq!(
        value.get("token_type").and_then(Value::as_str),
        Some("DPoP")
    );
    Ok(())
}

#[tokio::test]
async fn black_box_issuer_http_fixture_covers_final_openid4vci_endpoints(
) -> Result<(), RouteTestError> {
    let router = issuer_router(state()?);

    let nonce_response = router
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
    assert_eq!(nonce_response.status(), StatusCode::OK);
    let nonce_body = response_body(nonce_response).await?;
    let nonce = NonceResponse::parse_json(&nonce_body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(nonce.c_nonce, TEST_NONCE);

    let credential_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(
                    r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#,
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;
    assert_eq!(credential_response.status(), StatusCode::OK);
    let credential_body = response_body(credential_response).await?;
    let issued =
        CredentialResponse::parse_json(&credential_body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(issued.credentials.as_ref().map(Vec::len), Some(1));
    assert_eq!(issued.notification_id.as_deref(), Some("notification-1"));

    let deferred_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/deferred_credential")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(r#"{"transaction_id":"transaction-1"}"#))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;
    assert_eq!(deferred_response.status(), StatusCode::OK);
    let deferred_body = response_body(deferred_response).await?;
    let deferred =
        CredentialResponse::parse_json(&deferred_body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(deferred.credentials.as_ref().map(Vec::len), Some(1));

    let notification_response = router
        .clone()
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
    assert_eq!(notification_response.status(), StatusCode::NO_CONTENT);

    let second_nonce_response = router
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
    assert_eq!(second_nonce_response.status(), StatusCode::OK);

    let encrypted_response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/jwt")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(
                    r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]},"credential_response_encryption":{"jwk":{"kty":"EC","alg":"ECDH-ES"},"enc":"A256GCM"}}"#,
                ))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;
    assert_eq!(encrypted_response.status(), StatusCode::OK);
    assert_eq!(
        encrypted_response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/jwt")
    );

    let problem_response = issuer_router(secured_state()?)
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
    assert_eq!(problem_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        problem_response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("DPoP error=\"invalid_token\"")
    );
    let problem_body = response_body(problem_response).await?;
    let problem = serde_json::from_str::<Value>(&problem_body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(problem.get("error"), Some(&json!("invalid_token")));

    Ok(())
}

#[tokio::test]
async fn json_credential_endpoint_issues_response() -> Result<(), RouteTestError> {
    let request_body = r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#;
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await?;
    let credential_response =
        CredentialResponse::parse_json(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        credential_response.credentials.as_ref().map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn unconfigured_path_scoped_credential_endpoint_is_not_routed() -> Result<(), RouteTestError>
{
    let request_body = r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#;
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/openid4vci/example-issuer/credential")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn json_credential_endpoint_returns_credential_error() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from("{}"))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_body(response).await?;
    let error = CredentialErrorResponse::parse_json(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        serde_json::to_value(error.error).map_err(|_| RouteTestError::Json)?,
        json!("invalid_credential_request")
    );
    Ok(())
}

#[tokio::test]
async fn encrypted_credential_endpoint_returns_application_jwt() -> Result<(), RouteTestError> {
    let request_body = r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]},"credential_response_encryption":{"jwk":{"kty":"EC","alg":"ECDH-ES"},"enc":"A256GCM"}}"#;
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/jwt")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/jwt")
    );
    let body = response_body(response).await?;
    assert_eq!(body, "a.b.c.d.e");
    Ok(())
}

#[tokio::test]
async fn plaintext_request_with_response_encryption_is_rejected() -> Result<(), RouteTestError> {
    // OpenID4VCI 1.0 §8.2: a plaintext (application/json) Credential Request that
    // asks for response encryption must be rejected to prevent key substitution.
    let request_body = r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]},"credential_response_encryption":{"jwk":{"kty":"EC","alg":"ECDH-ES"},"enc":"A256GCM"}}"#;
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_body(response).await?;
    let error = CredentialErrorResponse::parse_json(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(
        serde_json::to_value(error.error).map_err(|_| RouteTestError::Json)?,
        json!("invalid_encryption_parameters")
    );
    Ok(())
}

#[tokio::test]
async fn encrypted_deferred_endpoint_returns_application_jwt() -> Result<(), RouteTestError> {
    let request_body = r#"{"transaction_id":"encrypted-transaction-1","credential_response_encryption":{"jwk":{"kty":"EC","alg":"ECDH-ES"},"enc":"A256GCM"}}"#;
    let response = issuer_router(state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/deferred_credential")
                .header(CONTENT_TYPE, "application/jwt")
                .header(AUTHORIZATION, "Bearer access-token")
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/jwt")
    );
    let body = response_body(response).await?;
    assert_eq!(body, "a.b.c.d.e");
    Ok(())
}

#[tokio::test]
async fn secured_credential_endpoint_requires_dpop_header() -> Result<(), RouteTestError> {
    let request_body = r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#;
    let response = issuer_router(secured_state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request_body))
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
    let body = response_body(response).await?;
    let problem = serde_json::from_str::<Value>(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(problem.get("error"), Some(&json!("invalid_token")));
    Ok(())
}

#[tokio::test]
async fn secured_credential_endpoint_accepts_dpop_and_wallet_attestation(
) -> Result<(), RouteTestError> {
    let headers = security_headers("https://issuer.example/credential")?;
    let request_body = r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#;
    let response = issuer_router(secured_state()?)
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
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn nested_router_dpop_target_retains_prefix_and_omits_query() -> Result<(), RouteTestError> {
    let headers = security_headers("https://issuer.example/tenant/credential")?;
    let request_body = r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#;
    let response = Router::new()
        .nest("/tenant", issuer_router(secured_state()?))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tenant/credential?transport_hint=ignored")
                .header(CONTENT_TYPE, "application/json")
                .header("dpop", headers.dpop)
                .header(AUTHORIZATION, headers.authorization)
                .header(OAUTH_CLIENT_ATTESTATION_HEADER, headers.client_attestation)
                .header(
                    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
                    headers.client_attestation_pop,
                )
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn secured_credential_endpoint_requires_wallet_attestation_headers(
) -> Result<(), RouteTestError> {
    // HAIP/EUDI deployments require wallet attestation in addition to DPoP. A
    // sender-constrained access token alone is insufficient client authentication.
    let headers = security_headers("https://issuer.example/credential")?;
    let request_body = r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#;
    let response = issuer_router(secured_state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/credential")
                .header(CONTENT_TYPE, "application/json")
                .header("dpop", headers.dpop)
                .header(AUTHORIZATION, headers.authorization)
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_body(response).await?;
    let problem =
        serde_json::from_str::<ProblemDetails>(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(problem.error.as_deref(), Some("invalid_proof"));
    Ok(())
}

#[tokio::test]
async fn secured_deferred_endpoint_checks_dpop_target_uri() -> Result<(), RouteTestError> {
    let headers = security_headers("https://issuer.example/credential")?;
    let request_body = r#"{"transaction_id":"transaction-1"}"#;
    let response = issuer_router(secured_state()?)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/deferred_credential")
                .header(CONTENT_TYPE, "application/json")
                .header("dpop", headers.dpop)
                .header(AUTHORIZATION, headers.authorization)
                .header(OAUTH_CLIENT_ATTESTATION_HEADER, headers.client_attestation)
                .header(
                    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
                    headers.client_attestation_pop,
                )
                .body(Body::from(request_body))
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_body(response).await?;
    let problem =
        serde_json::from_str::<ProblemDetails>(&body).map_err(|_| RouteTestError::Json)?;
    assert_eq!(problem.error.as_deref(), Some("invalid_proof"));
    Ok(())
}
