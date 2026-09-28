// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common HTTP headers for OpenID4VCI adapters.

/// Common OpenID4VCI response headers used by HTTP adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoStoreJsonHeaders {
    /// Content-Type header value.
    pub content_type: &'static str,
    /// Cache-Control header value.
    pub cache_control: &'static str,
}

/// Headers for unencrypted JSON responses that must not be cached.
pub const NO_STORE_JSON_HEADERS: NoStoreJsonHeaders = NoStoreJsonHeaders {
    content_type: "application/json",
    cache_control: "no-store",
};
