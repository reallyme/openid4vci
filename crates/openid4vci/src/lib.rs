// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public facade for ReallyMe OpenID4VCI crates.

#[path = "configure_policy.rs"]
pub mod policy;

#[cfg(feature = "codec")]
pub mod sdk;

pub use openid4vci_attestation as attestation;
#[cfg(feature = "http")]
pub use openid4vci_http as http;
pub use openid4vci_issuer as issuer;
#[cfg(feature = "profiles")]
pub use openid4vci_profiles as profiles;
pub use openid4vci_types as types;
pub use reallyme_openid4vci_wallet as wallet;
