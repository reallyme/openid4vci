// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serve the OIDF OpenID4VCI holder harness over HTTP.
//!
//! This executable exposes the conformance control-plane endpoint that OIDF
//! wallet-role plans can call with Credential Offer launches. Public HTTPS is
//! provided outside this process by CI ingress or a tunnel when the suite is
//! remote.

use std::env;
use std::net::SocketAddr;

use openid4vci_http::{holder_harness_router, HolderHarnessState};
use secrecy::SecretString;
use thiserror::Error;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:8788";
const CONTROL_TOKEN_ENV: &str = "OIDF_HARNESS_CONTROL_TOKEN";

#[derive(Debug, Error)]
enum HolderHarnessServeError {
    #[error("invalid_bind_address")]
    InvalidBindAddress,
    #[error("unexpected_argument")]
    UnexpectedArgument,
    #[error("bind_failed")]
    BindFailed,
    #[error("serve_failed")]
    ServeFailed,
    #[error("public_bind_forbidden")]
    PublicBindForbidden,
    #[error("invalid_control_token")]
    InvalidControlToken,
}

#[tokio::main]
async fn main() -> Result<(), HolderHarnessServeError> {
    let bind = bind_address()?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| HolderHarnessServeError::BindFailed)?;
    let mut state = HolderHarnessState::new();
    if let Ok(token) = env::var(CONTROL_TOKEN_ENV) {
        state = state
            .with_control_token(SecretString::from(token))
            .map_err(|_| HolderHarnessServeError::InvalidControlToken)?;
    }
    let app = holder_harness_router(state);

    axum::serve(listener, app)
        .await
        .map_err(|_| HolderHarnessServeError::ServeFailed)
}

fn bind_address() -> Result<SocketAddr, HolderHarnessServeError> {
    let mut args = env::args();
    let _binary = args.next();
    let raw = match args.next() {
        Some(value) => value,
        None => DEFAULT_BIND_ADDRESS.to_owned(),
    };
    if args.next().is_some() {
        return Err(HolderHarnessServeError::UnexpectedArgument);
    }

    let address: SocketAddr = raw
        .parse()
        .map_err(|_| HolderHarnessServeError::InvalidBindAddress)?;
    if !address.ip().is_loopback() {
        return Err(HolderHarnessServeError::PublicBindForbidden);
    }
    Ok(address)
}
