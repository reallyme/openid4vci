// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Synthetic issuer entrypoint used only by the conformance CI harness.
//!
//! **Do not deploy this example.** It deliberately uses fixed test keys and
//! identifiers and does not implement production authentication, durable
//! storage, consent, HSM custody, or multi-tenant operational controls.

#[path = "issuer/mod.rs"]
mod example;

#[tokio::main]
async fn main() -> Result<(), example::ExampleIssuerError> {
    example::run().await
}
