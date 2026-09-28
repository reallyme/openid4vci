// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded HTTP responses for the holder conformance harness.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::HolderHarnessFlowErrorReason;

const MAX_HARNESS_RESPONSE_BYTES: usize = 65_536;
const APPLICATION_JSON: &str = "application/json";
const CACHE_NO_STORE: &str = "no-store";
const PROBLEM_JSON: &str = "application/problem+json";
const INVALID_REQUEST_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"invalid_request\",\"status\":400,\"error\":\"invalid_request\"}";
const NOT_FOUND_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"not_found\",\"status\":404,\"error\":\"not_found\"}";
const PAYLOAD_TOO_LARGE_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"payload_too_large\",\"status\":413,\"error\":\"payload_too_large\"}";
const UNAUTHORIZED_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"unauthorized\",\"status\":401,\"error\":\"unauthorized\"}";
const SERVER_ERROR_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"server_error\",\"status\":500,\"error\":\"server_error\"}";
const WALLET_FLOW_LAUNCH_REJECTED_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"wallet_flow_failed\",\"status\":502,\"error\":\"launch_rejected\"}";
const WALLET_ATTESTATION_UNAVAILABLE_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"wallet_flow_failed\",\"status\":502,\"error\":\"wallet_attestation_unavailable\"}";
const TOKEN_EXCHANGE_FAILED_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"wallet_flow_failed\",\"status\":502,\"error\":\"token_exchange_failed\"}";
const CREDENTIAL_REQUEST_FAILED_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"wallet_flow_failed\",\"status\":502,\"error\":\"credential_request_failed\"}";
const CREDENTIAL_STORAGE_FAILED_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"wallet_flow_failed\",\"status\":502,\"error\":\"credential_storage_failed\"}";
const SERVICE_UNAVAILABLE_BODY: &str =
    "{\"type\":\"about:blank\",\"title\":\"service_unavailable\",\"status\":503}";

#[derive(Clone, Copy)]
pub(crate) enum Problem {
    InvalidRequest,
    NotFound,
    PayloadTooLarge,
    Unauthorized,
    ServiceUnavailable,
    ServerError,
    WalletFlowFailed(HolderHarnessFlowErrorReason),
}

pub(crate) fn problem_response(problem: Problem) -> Response {
    match problem {
        Problem::InvalidRequest => problem_body(
            StatusCode::BAD_REQUEST,
            INVALID_REQUEST_BODY.as_bytes().to_vec(),
        ),
        Problem::NotFound => {
            problem_body(StatusCode::NOT_FOUND, NOT_FOUND_BODY.as_bytes().to_vec())
        }
        Problem::PayloadTooLarge => problem_body(
            StatusCode::PAYLOAD_TOO_LARGE,
            PAYLOAD_TOO_LARGE_BODY.as_bytes().to_vec(),
        ),
        Problem::Unauthorized => problem_body(
            StatusCode::UNAUTHORIZED,
            UNAUTHORIZED_BODY.as_bytes().to_vec(),
        ),
        Problem::ServiceUnavailable => problem_body(
            StatusCode::SERVICE_UNAVAILABLE,
            SERVICE_UNAVAILABLE_BODY.as_bytes().to_vec(),
        ),
        Problem::ServerError => problem_body(
            StatusCode::INTERNAL_SERVER_ERROR,
            SERVER_ERROR_BODY.as_bytes().to_vec(),
        ),
        Problem::WalletFlowFailed(reason) => {
            let body = match reason {
                HolderHarnessFlowErrorReason::LaunchRejected => WALLET_FLOW_LAUNCH_REJECTED_BODY,
                HolderHarnessFlowErrorReason::WalletAttestationUnavailable => {
                    WALLET_ATTESTATION_UNAVAILABLE_BODY
                }
                HolderHarnessFlowErrorReason::TokenExchangeFailed => TOKEN_EXCHANGE_FAILED_BODY,
                HolderHarnessFlowErrorReason::CredentialRequestFailed => {
                    CREDENTIAL_REQUEST_FAILED_BODY
                }
                HolderHarnessFlowErrorReason::CredentialStorageFailed => {
                    CREDENTIAL_STORAGE_FAILED_BODY
                }
            };
            problem_body(StatusCode::BAD_GATEWAY, body.as_bytes().to_vec())
        }
    }
}

pub(crate) fn json_message_response<M>(message: &M) -> Response
where
    M: Serialize,
{
    let mut body = match serde_json::to_vec(message) {
        Ok(body) => Zeroizing::new(body),
        Err(_) => return problem_response(Problem::ServerError),
    };
    if body.len() > MAX_HARNESS_RESPONSE_BYTES {
        problem_response(Problem::ServerError)
    } else {
        json_response(StatusCode::OK, core::mem::take(&mut *body))
    }
}

fn problem_body(status: StatusCode, body: Vec<u8>) -> Response {
    response_with_content_type(status, PROBLEM_JSON, body)
}

pub(crate) fn json_response(status: StatusCode, body: Vec<u8>) -> Response {
    response_with_content_type(status, APPLICATION_JSON, body)
}

fn response_with_content_type(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response {
    let headers = [
        (CONTENT_TYPE, HeaderValue::from_static(content_type)),
        (CACHE_CONTROL, HeaderValue::from_static(CACHE_NO_STORE)),
    ];
    (status, headers, body).into_response()
}
