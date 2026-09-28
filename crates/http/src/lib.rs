// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional HTTP adapter boundary.
//!
//! This crate intentionally contains no default HTTP runtime. Axum and reqwest
//! integrations are feature-gated so the core protocol crates remain transport
//! agnostic and suitable for FFI and WASM callers.

pub mod headers;

#[cfg(feature = "stack-errors")]
pub mod map_http_error_reason;

#[cfg(feature = "axum")]
pub mod axum_issuer;

#[cfg(feature = "axum-holder-harness")]
pub mod axum_holder_harness;

#[cfg(feature = "axum-holder-harness")]
mod holder_harness_flow_summary;
#[cfg(any(feature = "axum", feature = "axum-holder-harness"))]
mod media_type;
#[cfg(feature = "axum-holder-harness")]
mod parse_holder_offer;

#[cfg(feature = "axum-holder-harness")]
mod respond_holder_harness;

#[cfg(feature = "holder-harness")]
pub mod drive_holder_harness_flow;

#[cfg(feature = "axum")]
mod oauth_authorization_server_capabilities;
#[cfg(feature = "axum")]
pub mod serve_oauth;

#[cfg(feature = "axum")]
mod validate_access_token;
#[cfg(feature = "axum")]
pub mod validate_http_security;

pub use headers::{NoStoreJsonHeaders, NO_STORE_JSON_HEADERS};

#[cfg(feature = "axum")]
pub use axum_issuer::{
    default_max_body_bytes, issuer_router, issuer_router_at_path, AxumIssuerError, AxumIssuerParts,
    AxumIssuerSecurityPolicy, AxumIssuerState,
};

#[cfg(feature = "axum-holder-harness")]
pub use axum_holder_harness::{
    holder_harness_max_body_bytes, holder_harness_router, HolderHarnessControlError,
    HolderHarnessError, HolderHarnessState,
};

#[cfg(feature = "holder-harness")]
pub use drive_holder_harness_flow::{
    HolderHarnessFlowDriver, HolderHarnessFlowError, HolderHarnessFlowErrorReason,
    HolderHarnessFlowOutcome, HolderHarnessFlowRequest, HolderHarnessFlowStatus,
    HolderHarnessProtocolRejectionReason,
};

#[cfg(feature = "axum")]
pub use oauth_authorization_server_capabilities::OAuthAuthorizationServerCapabilities;
#[cfg(feature = "axum")]
pub use serve_oauth::{
    parse_oauth_form, AuthorizationResponse, OAuthAuthorizationServer, OAuthErrorBody,
    OAuthHttpError, OAuthHttpErrorReason, OAuthHttpResult, OAuthParameters, OAuthRequestHeaders,
    OAuthResponseEncodingError, OAuthResponseResult, PushedAuthorizationResponse, TokenResponse,
};
#[cfg(feature = "axum")]
pub use validate_access_token::{
    AccessTokenValidator, CredentialAuthorizationDecision, ValidatedAccessToken,
};

#[cfg(feature = "axum")]
pub use validate_http_security::{
    Clock, DpopHttpConfig, IssuerHttpSecurityConfig, SystemClock, WalletAttestationEvidenceError,
    WalletAttestationEvidenceRecorder, WalletAttestationHttpConfig,
};
