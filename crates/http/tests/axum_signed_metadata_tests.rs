// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed Credential Issuer Metadata HTTP negotiation tests.

#![cfg(feature = "axum")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use openid4vci_http::issuer_router;
use openid4vci_issuer::{IssuerMetadataSigner, IssuerResult, SignedIssuerMetadataJwt};
use openid4vci_types::IssuerMetadata;
use tower::ServiceExt;

#[path = "support/exercise_axum_issuer.rs"]
mod exercise_axum_issuer;

use exercise_axum_issuer::{response_body, state, RouteTestError};

struct FixedMetadataSigner;

impl IssuerMetadataSigner for FixedMetadataSigner {
    fn sign_metadata(
        &self,
        _metadata: &IssuerMetadata,
        _issued_at_unix: i64,
    ) -> IssuerResult<SignedIssuerMetadataJwt> {
        SignedIssuerMetadataJwt::new("e30.e30.AA".to_owned())
    }
}

#[tokio::test]
async fn metadata_endpoint_serves_signed_representation_when_requested(
) -> Result<(), RouteTestError> {
    let response = issuer_router(state()?.with_metadata_signer(Arc::new(FixedMetadataSigner)))
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .header(ACCEPT, "application/jwt")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/jwt")
    );
    assert_eq!(response_body(response).await?, "e30.e30.AA");
    Ok(())
}

#[tokio::test]
async fn zero_quality_signed_metadata_request_falls_back_to_json() -> Result<(), RouteTestError> {
    let response = issuer_router(state()?.with_metadata_signer(Arc::new(FixedMetadataSigner)))
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-credential-issuer")
                .header(ACCEPT, "application/jwt;q=0, application/json")
                .body(Body::empty())
                .map_err(|_| RouteTestError::Request)?,
        )
        .await
        .map_err(|_| RouteTestError::Response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body = response_body(response).await?;
    let _: IssuerMetadata = IssuerMetadata::parse_json(&body).map_err(|_| RouteTestError::Json)?;
    Ok(())
}
