// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use axum::body::to_bytes;
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use openid4vci_types::ProblemDetails;
use serde_json::Value;

use super::{
    credential_error_response, deferred_credential_error_response, notification_error_response,
    oauth_headers,
};
use crate::serve_oauth::OAuthHttpErrorReason;

#[test]
fn oauth_headers_reject_duplicate_sensitive_values() {
    let mut headers = HeaderMap::new();
    headers.append("DPoP", HeaderValue::from_static("proof-one"));
    headers.append("DPoP", HeaderValue::from_static("proof-two"));

    assert_eq!(
        oauth_headers(&headers).err().map(|error| error.reason),
        Some(OAuthHttpErrorReason::InvalidRequest)
    );
}

#[test]
fn oauth_headers_reject_oversized_proofs() {
    let value = HeaderValue::from_str(&"a".repeat(16_385));
    assert!(value.is_ok());
    let Some(value) = value.ok() else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert("DPoP", value);

    assert_eq!(
        oauth_headers(&headers).err().map(|error| error.reason),
        Some(OAuthHttpErrorReason::InvalidRequest)
    );
}

#[test]
fn oauth_headers_reject_non_utf8_values() {
    let value = HeaderValue::from_bytes(&[0xff]);
    assert!(value.is_ok());
    let Some(value) = value.ok() else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert("OAuth-Client-Attestation", value);

    assert_eq!(
        oauth_headers(&headers).err().map(|error| error.reason),
        Some(OAuthHttpErrorReason::InvalidRequest)
    );
}

fn problem_with_code(code: &str) -> ProblemDetails {
    ProblemDetails {
        type_url: "about:blank".to_owned(),
        title: code.to_owned(),
        status: StatusCode::BAD_REQUEST.as_u16(),
        instance: None,
        error: Some(code.to_owned()),
    }
}

async fn assert_protocol_error_response(response: axum::response::Response, expected: &str) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let bytes = to_bytes(response.into_body(), 4_096).await;
    assert!(bytes.is_ok());
    if let Ok(bytes) = bytes {
        let parsed = serde_json::from_slice::<Value>(&bytes);
        assert!(parsed.is_ok());
        if let Ok(parsed) = parsed {
            assert_eq!(parsed.get("error").and_then(Value::as_str), Some(expected));
        }
    }
}

#[tokio::test]
async fn endpoint_error_responses_use_final_vocabularies_status_and_no_store() {
    for code in [
        "invalid_credential_request",
        "invalid_proof",
        "invalid_nonce",
        "unknown_credential_configuration",
        "unknown_credential_identifier",
        "invalid_encryption_parameters",
        "credential_request_denied",
    ] {
        assert_protocol_error_response(credential_error_response(problem_with_code(code)), code)
            .await;
    }
    for code in [
        "invalid_credential_request",
        "invalid_transaction_id",
        "invalid_encryption_parameters",
        "credential_request_denied",
    ] {
        assert_protocol_error_response(
            deferred_credential_error_response(problem_with_code(code)),
            code,
        )
        .await;
    }
    for code in ["invalid_notification_request", "invalid_notification_id"] {
        assert_protocol_error_response(notification_error_response(problem_with_code(code)), code)
            .await;
    }
}
