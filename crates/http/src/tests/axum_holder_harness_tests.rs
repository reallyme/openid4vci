// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tower::ServiceExt;

use crate::{
    holder_harness_max_body_bytes, holder_harness_router, HolderHarnessFlowDriver,
    HolderHarnessFlowError, HolderHarnessFlowErrorReason, HolderHarnessFlowOutcome,
    HolderHarnessFlowRequest, HolderHarnessProtocolRejectionReason, HolderHarnessState,
};

const IDEMPOTENCY_KEY: &str = "oidf-module-1";
const CONTROL_TOKEN: &str = "local-control-token-with-sufficient-entropy";

fn controlled_state() -> HolderHarnessState {
    HolderHarnessState::new()
        .with_control_token(SecretString::from(CONTROL_TOKEN.to_owned()))
        .expect("bounded control token is valid")
}

fn driven_state<D>(driver: D) -> HolderHarnessState
where
    D: HolderHarnessFlowDriver + 'static,
{
    HolderHarnessState::new()
        .with_flow_driver(driver, SecretString::from(CONTROL_TOKEN.to_owned()))
        .expect("bounded control token is valid")
}

#[test]
fn holder_harness_rejects_unbounded_body_configuration() {
    assert_eq!(holder_harness_max_body_bytes(), 64 * 1024);
    assert!(HolderHarnessState::with_max_body_bytes(0).is_err());
    assert!(HolderHarnessState::with_max_body_bytes(64 * 1024).is_ok());
    assert!(HolderHarnessState::with_max_body_bytes((64 * 1024) + 1).is_err());
}

#[test]
fn holder_flow_request_debug_redacts_offer_and_idempotency_values() {
    let request = HolderHarnessFlowRequest::new(
        "openid-credential-offer://?credential_offer=secret-offer".to_owned(),
        "secret-idempotency-key".to_owned(),
    )
    .expect("bounded request is valid");
    let debug = format!("{request:?}");

    assert!(!debug.contains("secret-offer"));
    assert!(!debug.contains("secret-idempotency-key"));
}

struct AcceptFlowDriver;

impl HolderHarnessFlowDriver for AcceptFlowDriver {
    fn drive_offer_launch(
        &self,
        request: &HolderHarnessFlowRequest,
    ) -> Result<HolderHarnessFlowOutcome, HolderHarnessFlowError> {
        if !request
            .credential_offer_launch_uri()
            .starts_with("openid-credential-offer://?")
            || request.idempotency_key() != IDEMPOTENCY_KEY
        {
            return Err(HolderHarnessFlowError::new(
                HolderHarnessFlowErrorReason::LaunchRejected,
            ));
        }
        Ok(HolderHarnessFlowOutcome::credential_stored())
    }
}

struct RejectFlowDriver;

struct ProtocolRejectFlowDriver;

impl HolderHarnessFlowDriver for ProtocolRejectFlowDriver {
    fn drive_offer_launch(
        &self,
        _request: &HolderHarnessFlowRequest,
    ) -> Result<HolderHarnessFlowOutcome, HolderHarnessFlowError> {
        Ok(HolderHarnessFlowOutcome::protocol_rejected(
            HolderHarnessProtocolRejectionReason::AuthorizationStateMismatch,
        ))
    }
}

impl HolderHarnessFlowDriver for RejectFlowDriver {
    fn drive_offer_launch(
        &self,
        _request: &HolderHarnessFlowRequest,
    ) -> Result<HolderHarnessFlowOutcome, HolderHarnessFlowError> {
        Err(HolderHarnessFlowError::new(
            HolderHarnessFlowErrorReason::CredentialRequestFailed,
        ))
    }
}

#[tokio::test]
async fn accepts_inline_credential_offer_launch() {
    let app = holder_harness_router(HolderHarnessState::new());
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/credential-offer")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::from(
            r#"{
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["pid"],
                    "grants": {
                        "authorization_code": {
                            "issuer_state": "state-1"
                        }
                    }
                }
            }"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn wallet_initiation_drives_authorization_code_offer() {
    let app = holder_harness_router(driven_state(AcceptFlowDriver));
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/initiate")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .header("Authorization", format!("Bearer {CONTROL_TOKEN}"))
        .body(Body::from(
            r#"{
                "credential_issuer": "https://issuer.example",
                "credential_configuration_id": "pid"
            }"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json parses");
    assert_eq!(json["offer"]["kind"], "inline");
    assert_eq!(json["offer"]["credential_configuration_count"], 1);
    assert_eq!(json["offer"]["authorization_code_grant_present"], true);
    assert_eq!(json["flow"]["status"], "credential_stored");
}

#[tokio::test]
async fn records_typed_protocol_rejection_as_a_terminal_flow() {
    let app = holder_harness_router(driven_state(ProtocolRejectFlowDriver));
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/initiate")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .header("Authorization", format!("Bearer {CONTROL_TOKEN}"))
        .body(Body::from(
            r#"{
                "credential_issuer": "https://issuer.example",
                "credential_configuration_id": "pid"
            }"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json parses");
    assert_eq!(json["flow"]["status"], "protocol_rejected");
    assert_eq!(json["flow"]["reason"], "authorization_state_mismatch");
}

#[tokio::test]
async fn wallet_initiation_rejects_invalid_or_extended_input() {
    for body in [
        r#"{
            "credential_issuer": "http://issuer.example",
            "credential_configuration_id": "pid"
        }"#,
        r#"{
            "credential_issuer": "https://issuer.example",
            "credential_configuration_id": "pid",
            "unexpected": true
        }"#,
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/oidf/wallet/initiate")
            .header(CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", IDEMPOTENCY_KEY)
            .body(Body::from(body))
            .expect("request builds");

        let response = holder_harness_router(HolderHarnessState::new())
            .oneshot(request)
            .await
            .expect("route responds");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn wallet_initiation_requires_json_content_type() {
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/initiate")
        .header(CONTENT_TYPE, "text/plain")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::from(
            r#"{
                "credential_issuer": "https://issuer.example",
                "credential_configuration_id": "pid"
            }"#,
        ))
        .expect("request builds");

    let response = holder_harness_router(HolderHarnessState::new())
        .oneshot(request)
        .await
        .expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn health_reports_recorder_only_harness_without_flow_driver() {
    let app = holder_harness_router(HolderHarnessState::new());
    let request = Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json parses");
    assert_eq!(json["composed_flow_driver_enabled"], false);
}

#[tokio::test]
async fn health_reports_composed_harness_with_flow_driver() {
    let app = holder_harness_router(driven_state(AcceptFlowDriver));
    let request = Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json parses");
    assert_eq!(json["composed_flow_driver_enabled"], true);
}

#[tokio::test]
async fn records_referenced_credential_offer_launch() {
    let app = holder_harness_router(HolderHarnessState::new());
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/credential-offer")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::from(
            r#"{"credential_offer_uri":"https://issuer.example/offers/123?module=oidf"}"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn exposes_latest_offer_session() {
    let app = holder_harness_router(controlled_state());
    let launch = Request::builder()
        .method("GET")
        .uri("/oidf/wallet/credential-offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::empty())
        .expect("request builds");
    app.clone()
        .oneshot(launch)
        .await
        .expect("launch route responds");
    let latest = Request::builder()
        .method("GET")
        .uri("/oidf/wallet/sessions/latest")
        .header("Authorization", format!("Bearer {CONTROL_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(latest).await.expect("latest route responds");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn records_composed_flow_outcome_when_driver_accepts() {
    let app = holder_harness_router(driven_state(AcceptFlowDriver));
    let request = Request::builder()
        .method("GET")
        .uri("/oidf/wallet/credential-offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .header("Authorization", format!("Bearer {CONTROL_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json parses");
    assert_eq!(json["flow"]["status"], "credential_stored");
}

#[tokio::test]
async fn composed_flow_driver_rejects_unauthenticated_launches() {
    let app = holder_harness_router(driven_state(AcceptFlowDriver));
    let request = Request::builder()
        .method("GET")
        .uri("/oidf/wallet/credential-offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn fails_closed_when_composed_flow_driver_rejects() {
    let app = holder_harness_router(driven_state(RejectFlowDriver));
    let request = Request::builder()
        .method("GET")
        .uri("/oidf/wallet/credential-offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .header("Authorization", format!("Bearer {CONTROL_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body reads");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json parses");
    assert_eq!(json["title"], "wallet_flow_failed");
    assert_eq!(json["error"], "credential_request_failed");
}

#[tokio::test]
async fn rejects_missing_offer_launch() {
    let app = holder_harness_router(HolderHarnessState::new());
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/credential-offer")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::from("{}"))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_duplicate_json_launch_members() {
    let app = holder_harness_router(HolderHarnessState::new());
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/credential-offer")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::from(
            r#"{
                "credential_offer_uri":"https://issuer.example/offers/one",
                "credential_offer_uri":"https://issuer.example/offers/two"
            }"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_conflicting_json_launch_sources() {
    let app = holder_harness_router(HolderHarnessState::new());
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/credential-offer")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::from(
            r#"{
                "credential_offer_launch_uri":"openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fone",
                "credential_offer_uri":"https://issuer.example/offers/two"
            }"#,
        ))
        .expect("request builds");

    let response = app.oneshot(request).await.expect("route responds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reset_clears_latest_offer_session() {
    let app = holder_harness_router(controlled_state());
    let launch = Request::builder()
        .method("GET")
        .uri("/oidf/wallet/credential-offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123")
        .header("Idempotency-Key", IDEMPOTENCY_KEY)
        .body(Body::empty())
        .expect("request builds");
    app.clone()
        .oneshot(launch)
        .await
        .expect("launch route responds");
    let reset = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/reset")
        .header("Authorization", format!("Bearer {CONTROL_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");
    app.clone()
        .oneshot(reset)
        .await
        .expect("reset route responds");
    let latest = Request::builder()
        .method("GET")
        .uri("/oidf/wallet/sessions/latest")
        .header("Authorization", format!("Bearer {CONTROL_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");

    let response = app.oneshot(latest).await.expect("latest route responds");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn control_routes_are_disabled_or_reject_invalid_bearer_tokens() {
    let disabled = holder_harness_router(HolderHarnessState::new());
    let request = Request::builder()
        .method("GET")
        .uri("/oidf/wallet/sessions/latest")
        .body(Body::empty())
        .expect("request builds");
    let response = disabled
        .oneshot(request)
        .await
        .expect("disabled control route responds");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let protected = holder_harness_router(controlled_state());
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/reset")
        .header("Authorization", "Bearer wrong-control-token")
        .body(Body::empty())
        .expect("request builds");
    let response = protected
        .oneshot(request)
        .await
        .expect("protected control route responds");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn launch_requires_one_bounded_opaque_idempotency_key() {
    for key in [None, Some("contains space"), Some(""), Some("é")] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/oidf/wallet/initiate")
            .header(CONTENT_TYPE, "application/json");
        if let Some(key) = key {
            builder = builder.header("Idempotency-Key", key);
        }
        let request = builder
            .body(Body::from(
                r#"{
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_id": "pid"
                }"#,
            ))
            .expect("request builds");
        let response = holder_harness_router(HolderHarnessState::new())
            .oneshot(request)
            .await
            .expect("route responds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let oversized = "a".repeat(129);
    let request = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/initiate")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", oversized)
        .body(Body::from(
            r#"{
                "credential_issuer": "https://issuer.example",
                "credential_configuration_id": "pid"
            }"#,
        ))
        .expect("request builds");
    let response = holder_harness_router(HolderHarnessState::new())
        .oneshot(request)
        .await
        .expect("route responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let duplicate = Request::builder()
        .method("POST")
        .uri("/oidf/wallet/initiate")
        .header(CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", "attempt-1")
        .header("Idempotency-Key", "attempt-2")
        .body(Body::from(
            r#"{
                "credential_issuer": "https://issuer.example",
                "credential_configuration_id": "pid"
            }"#,
        ))
        .expect("request builds");
    let response = holder_harness_router(HolderHarnessState::new())
        .oneshot(duplicate)
        .await
        .expect("route responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
