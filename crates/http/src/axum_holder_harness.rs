// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OIDF conformance holder harness HTTP adapter.
//!
//! The OpenID Foundation wallet-role plans need a reachable endpoint that can
//! receive Credential Offer launches. This module is a conformance control
//! plane only: it validates launch shape through the OpenID4VCI holder/type
//! parser and records opaque session state for a flow driver. Token exchange,
//! credential storage, user consent, and platform key handling stay above this
//! crate in wallet-core or identity.

use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use openid4vci_types::CredentialOffer;
use reallyme_codec::jcs::canonicalize_json_text;
use reallyme_crypto::operations::constant_time::equal as constant_time_equal;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::{
    holder_harness_flow_summary::HolderHarnessHealthSummary,
    media_type::{media_type_matches, single_content_type},
    parse_holder_offer::{parse_offer_launch, OfferLaunchBody, OfferRecord, ParsedHarnessOffer},
    respond_holder_harness::{json_message_response, json_response, problem_response, Problem},
    HolderHarnessFlowDriver, HolderHarnessFlowOutcome, HolderHarnessFlowRequest,
};

const DEFAULT_HARNESS_MAX_BODY_BYTES: usize = 64 * 1024;
// Keep custom deployments free to lower the body limit without permitting a
// configuration mistake to expand the public attack surface above the audited
// protocol-envelope ceiling.
const MAX_HARNESS_BODY_BYTES: usize = DEFAULT_HARNESS_MAX_BODY_BYTES;
const APPLICATION_JSON: &str = "application/json";
const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
const HEALTH_STATUS_OK: &str = "ok";
const HEALTH_SERVICE_NAME: &str = "oidf_openid4vci_wallet_harness";
const OFFER_URI_BASE: &str = "openid-credential-offer://";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_CONTROL_TOKEN_BYTES: usize = 256;
const BEARER_PREFIX: &str = "Bearer ";
const MAX_CONCURRENT_BLOCKING_FLOWS: usize = 8;

/// Construction errors for the OpenID4VCI holder harness.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum HolderHarnessError {
    /// Request body limit must be positive and within the audited ceiling.
    #[error("invalid_body_limit")]
    InvalidBodyLimit,
}

/// Construction errors for the holder-harness control plane.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum HolderHarnessControlError {
    /// Control-plane bearer token must be non-empty and bounded.
    #[error("invalid_control_token")]
    InvalidControlToken,
}

/// Return the audited upper bound for holder-harness request bodies.
///
/// Deployment adapters consume this value instead of duplicating it so a
/// protocol hardening change cannot leave a composed host advertising a wider
/// boundary that the protocol adapter will reject at startup.
#[must_use]
pub const fn holder_harness_max_body_bytes() -> usize {
    MAX_HARNESS_BODY_BYTES
}

/// Shared Axum state for the OIDF holder harness.
#[derive(Clone)]
pub struct HolderHarnessState {
    inner: Arc<Mutex<HolderHarnessMemory>>,
    flow_driver: Option<Arc<dyn HolderHarnessFlowDriver>>,
    control_token: Option<Arc<SecretString>>,
    max_body_bytes: usize,
    flow_permits: Arc<Semaphore>,
}

impl HolderHarnessState {
    /// Create holder-harness state using the default request body limit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HolderHarnessMemory::default())),
            flow_driver: None,
            control_token: None,
            max_body_bytes: DEFAULT_HARNESS_MAX_BODY_BYTES,
            flow_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_BLOCKING_FLOWS)),
        }
    }

    /// Create holder-harness state using an explicit request body limit.
    pub fn with_max_body_bytes(max_body_bytes: usize) -> Result<Self, HolderHarnessError> {
        if max_body_bytes == 0 || max_body_bytes > MAX_HARNESS_BODY_BYTES {
            return Err(HolderHarnessError::InvalidBodyLimit);
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(HolderHarnessMemory::default())),
            flow_driver: None,
            control_token: None,
            max_body_bytes,
            flow_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_BLOCKING_FLOWS)),
        })
    }

    /// Attach a composed wallet flow driver behind a required control token.
    ///
    /// A driver can cause network requests and credential operations. Requiring
    /// its authorization secret in the same construction step prevents a host
    /// from accidentally exposing that capability through public launch routes.
    pub fn with_flow_driver<D>(
        mut self,
        flow_driver: D,
        control_token: SecretString,
    ) -> Result<Self, HolderHarnessControlError>
    where
        D: HolderHarnessFlowDriver + 'static,
    {
        validate_control_token(&control_token)?;
        self.flow_driver = Some(Arc::new(flow_driver));
        self.control_token = Some(Arc::new(control_token));
        Ok(self)
    }

    /// Enables the session-inspection and reset control endpoints.
    ///
    /// Without this explicit secret, those endpoints remain unavailable. The
    /// Credential Offer launch endpoints stay public because they are protocol
    /// callbacks exercised by the OIDF wallet-role conformance suite.
    pub fn with_control_token(
        mut self,
        token: SecretString,
    ) -> Result<Self, HolderHarnessControlError> {
        validate_control_token(&token)?;
        self.control_token = Some(Arc::new(token));
        Ok(self)
    }

    fn authorize_control(&self, headers: &HeaderMap) -> Result<(), Problem> {
        let expected = self.control_token.as_ref().ok_or(Problem::NotFound)?;
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let supplied = values
            .next()
            .ok_or(Problem::Unauthorized)?
            .to_str()
            .map_err(|_| Problem::Unauthorized)?;
        if values.next().is_some() {
            return Err(Problem::Unauthorized);
        }
        let supplied = supplied
            .strip_prefix(BEARER_PREFIX)
            .ok_or(Problem::Unauthorized)?;
        if !constant_time_equal(supplied.as_bytes(), expected.expose_secret().as_bytes()) {
            return Err(Problem::Unauthorized);
        }
        Ok(())
    }

    fn authorize_flow_launch(&self, headers: &HeaderMap) -> Result<(), Problem> {
        if self.flow_driver.is_some() {
            self.authorize_control(headers)
        } else {
            Ok(())
        }
    }

    fn record(
        &self,
        offer: ParsedHarnessOffer,
        flow: Option<HolderHarnessFlowOutcome>,
    ) -> Result<OfferRecord, Problem> {
        let mut inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        inner.record(offer, flow)
    }

    async fn drive_flow(
        &self,
        launch_uri: &str,
        idempotency_key: &str,
    ) -> Result<Option<HolderHarnessFlowOutcome>, Problem> {
        let Some(flow_driver) = self.flow_driver.as_ref() else {
            return Ok(None);
        };
        let flow_driver = Arc::clone(flow_driver);
        let request = HolderHarnessFlowRequest::from_validated_launch(
            launch_uri.to_owned(),
            idempotency_key.to_owned(),
        );
        // Do not create an attacker-controlled, unbounded waiter queue behind
        // the bounded blocking pool. Excess public launches fail closed and
        // can be retried by the conformance driver.
        let permit = Arc::clone(&self.flow_permits)
            .try_acquire_owned()
            .map_err(|_| Problem::ServiceUnavailable)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            flow_driver.drive_offer_launch(&request)
        })
        .await
        .map_err(|_| Problem::ServerError)?
        .map(Some)
        .map_err(|error| Problem::WalletFlowFailed(error.reason()))
    }

    fn has_flow_driver(&self) -> bool {
        self.flow_driver.is_some()
    }

    fn latest(&self) -> Result<Option<OfferRecord>, Problem> {
        let inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        Ok(inner.latest.clone())
    }

    fn reset(&self) -> Result<(), Problem> {
        let mut inner = self.inner.lock().map_err(|_| Problem::ServerError)?;
        inner.reset();
        Ok(())
    }
}

impl Default for HolderHarnessState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct HolderHarnessMemory {
    next_session_id: u64,
    latest: Option<OfferRecord>,
}

impl HolderHarnessMemory {
    fn record(
        &mut self,
        offer: ParsedHarnessOffer,
        flow: Option<HolderHarnessFlowOutcome>,
    ) -> Result<OfferRecord, Problem> {
        let session_id = self.next_session_id;
        self.next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or(Problem::ServerError)?;
        let record = OfferRecord::from_offer(session_id, offer, flow);
        self.latest = Some(record.clone());
        Ok(record)
    }

    fn reset(&mut self) {
        self.latest = None;
    }
}

/// Create an Axum router exposing the OpenID4VCI OIDF holder harness.
pub fn holder_harness_router(state: HolderHarnessState) -> Router {
    Router::new()
        .route("/healthz", get(handle_health))
        .route(
            "/oidf/wallet/credential-offer",
            get(handle_offer_get).post(handle_offer_post),
        )
        .route("/oidf/wallet/initiate", post(handle_wallet_initiation))
        .route("/oidf/wallet/sessions/latest", get(handle_latest))
        .route("/oidf/wallet/reset", post(handle_reset))
        .with_state(state)
}

async fn handle_health(State(state): State<HolderHarnessState>) -> Response {
    json_message_response(&HolderHarnessHealthSummary {
        status: HEALTH_STATUS_OK,
        service: HEALTH_SERVICE_NAME,
        composed_flow_driver_enabled: state.has_flow_driver(),
    })
}

async fn handle_offer_get(
    State(state): State<HolderHarnessState>,
    request: Request<Body>,
) -> Response {
    if let Err(problem) = state.authorize_flow_launch(request.headers()) {
        return problem_response(problem);
    }
    let idempotency_key = match parse_idempotency_key(request.headers()) {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    let launch_uri = match request.uri().query() {
        Some(query) => [OFFER_URI_BASE, "?", query].concat(),
        None => return problem_response(Problem::InvalidRequest),
    };
    handle_offer_launch(state, launch_uri, idempotency_key).await
}

async fn handle_offer_post(
    State(state): State<HolderHarnessState>,
    request: Request<Body>,
) -> Response {
    if let Err(problem) = state.authorize_flow_launch(request.headers()) {
        return problem_response(problem);
    }
    let idempotency_key = match parse_idempotency_key(request.headers()) {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    let content_type = single_content_type(request.headers()).map(ToOwned::to_owned);
    let body = match read_body_bytes(request, state.max_body_bytes).await {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    let launch_uri = match decode_offer_body(content_type.as_deref(), &body) {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    handle_offer_launch(state, launch_uri, idempotency_key).await
}

async fn handle_wallet_initiation(
    State(state): State<HolderHarnessState>,
    request: Request<Body>,
) -> Response {
    if let Err(problem) = state.authorize_flow_launch(request.headers()) {
        return problem_response(problem);
    }
    let idempotency_key = match parse_idempotency_key(request.headers()) {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    if !single_content_type(request.headers())
        .is_some_and(|value| media_type_matches(value, APPLICATION_JSON))
    {
        return problem_response(Problem::InvalidRequest);
    }
    let body = match read_body_bytes(request, state.max_body_bytes).await {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    let launch_uri = match decode_wallet_initiation_body(&body) {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    handle_offer_launch(state, launch_uri, idempotency_key).await
}

fn validate_control_token(token: &SecretString) -> Result<(), HolderHarnessControlError> {
    let token_len = token.expose_secret().len();
    if token_len == 0 || token_len > MAX_CONTROL_TOKEN_BYTES {
        return Err(HolderHarnessControlError::InvalidControlToken);
    }
    Ok(())
}

async fn handle_latest(State(state): State<HolderHarnessState>, headers: HeaderMap) -> Response {
    if let Err(problem) = state.authorize_control(&headers) {
        return problem_response(problem);
    }
    match state.latest() {
        Ok(Some(record)) => json_message_response(&record),
        Ok(None) => problem_response(Problem::NotFound),
        Err(problem) => problem_response(problem),
    }
}

async fn handle_reset(State(state): State<HolderHarnessState>, headers: HeaderMap) -> Response {
    if let Err(problem) = state.authorize_control(&headers) {
        return problem_response(problem);
    }
    match state.reset() {
        Ok(()) => json_response(StatusCode::NO_CONTENT, Vec::new()),
        Err(problem) => problem_response(problem),
    }
}

async fn handle_offer_launch(
    state: HolderHarnessState,
    launch_uri: String,
    idempotency_key: String,
) -> Response {
    // Credential Offer URIs can embed pre-authorized codes. Keep both raw
    // control-plane values in zeroizing owners across every early return.
    let launch_uri = Zeroizing::new(launch_uri);
    let idempotency_key = Zeroizing::new(idempotency_key);
    let parsed = match parse_offer_launch(&launch_uri) {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    let flow = match state.drive_flow(&launch_uri, &idempotency_key).await {
        Ok(value) => value,
        Err(problem) => return problem_response(problem),
    };
    match state.record(parsed, flow) {
        Ok(record) => json_message_response(&record),
        Err(problem) => problem_response(problem),
    }
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<String, Problem> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let value = values.next().ok_or(Problem::InvalidRequest)?;
    if values.next().is_some() {
        return Err(Problem::InvalidRequest);
    }
    let text = value.to_str().map_err(|_| Problem::InvalidRequest)?;
    if text.is_empty()
        || text.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Problem::InvalidRequest);
    }
    Ok(text.to_owned())
}

async fn read_body_bytes(
    request: Request<Body>,
    limit: usize,
) -> Result<axum::body::Bytes, Problem> {
    to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| Problem::PayloadTooLarge)
}

fn decode_offer_body(content_type: Option<&str>, body: &[u8]) -> Result<String, Problem> {
    if content_type.is_some_and(|value| media_type_matches(value, FORM_URLENCODED)) {
        return std::str::from_utf8(body)
            .map(|value| [OFFER_URI_BASE, "?", value].concat())
            .map_err(|_| Problem::InvalidRequest);
    }

    if content_type.is_some_and(|value| media_type_matches(value, APPLICATION_JSON)) {
        let text = core::str::from_utf8(body).map_err(|_| Problem::InvalidRequest)?;
        let canonical =
            Zeroizing::new(canonicalize_json_text(text).map_err(|_| Problem::InvalidRequest)?);
        let launch: OfferLaunchBody =
            serde_json::from_str(canonical.as_str()).map_err(|_| Problem::InvalidRequest)?;
        return launch.into_offer_uri();
    }

    Err(Problem::InvalidRequest)
}

fn decode_wallet_initiation_body(body: &[u8]) -> Result<String, Problem> {
    let text = core::str::from_utf8(body).map_err(|_| Problem::InvalidRequest)?;
    let canonical =
        Zeroizing::new(canonicalize_json_text(text).map_err(|_| Problem::InvalidRequest)?);
    let initiation: WalletInitiationBody =
        serde_json::from_str(canonical.as_str()).map_err(|_| Problem::InvalidRequest)?;
    let offer = CredentialOffer::authorization_code(
        initiation.credential_issuer,
        vec![initiation.credential_configuration_id],
        None,
    )
    .map_err(|_| Problem::InvalidRequest)?;
    offer.to_uri().map_err(|_| Problem::InvalidRequest)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletInitiationBody {
    credential_issuer: String,
    credential_configuration_id: String,
}

#[path = "tests/axum_holder_harness_tests.rs"]
#[cfg(test)]
mod axum_holder_harness_tests;
