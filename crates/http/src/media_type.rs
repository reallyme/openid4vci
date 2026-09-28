// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict HTTP media-type recognition shared by Axum adapters.

use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderMap;

/// Returns the single UTF-8 Content-Type value, rejecting duplicates.
pub(crate) fn single_content_type(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

/// Matches a Content-Type value by media type, excluding parameters.
pub(crate) fn media_type_matches(value: &str, expected: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
}

/// Returns true only for one exact Content-Type media type.
#[cfg(feature = "axum")]
pub(crate) fn has_content_type(headers: &HeaderMap, expected: &str) -> bool {
    single_content_type(headers).is_some_and(|value| media_type_matches(value, expected))
}

#[path = "tests/media_type_tests.rs"]
#[cfg(test)]
mod media_type_tests;
