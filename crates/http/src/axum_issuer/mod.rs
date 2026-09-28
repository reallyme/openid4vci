// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Axum adapter for issuer and authorization-server routes.

mod authorize_credential_access;
mod configure;
mod handle;
mod respond;

pub use configure::{
    default_max_body_bytes, issuer_router, issuer_router_at_path, AxumIssuerError, AxumIssuerParts,
    AxumIssuerSecurityPolicy, AxumIssuerState,
};
