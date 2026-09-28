// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Composed synthetic conformance issuer. Do not deploy this example.

mod authorize;
#[cfg(test)]
mod authorize_tests;
mod build_authorization_redirect;
mod configure;
#[cfg(test)]
mod configure_tests;
mod credential_authorization;
#[cfg(test)]
mod credential_authorization_tests;
mod exchange_token;
#[cfg(test)]
mod exchange_token_tests;
mod issue;
#[cfg(test)]
mod issue_tests;
mod mdoc;
#[cfg(test)]
mod mdoc_tests;
mod run;
#[cfg(test)]
mod run_tests;
mod sign;
mod sign_metadata;
#[cfg(test)]
mod sign_metadata_tests;
mod store_authorization_state;
mod verify;
#[cfg(test)]
mod verify_tests;

pub(crate) use run::{run, ExampleIssuerError};
