// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "axum")]

use axum::http::{HeaderMap, HeaderValue};

use super::has_content_type;

#[test]
fn content_type_match_is_exact_case_insensitive_and_parameter_aware() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("Application/JWT; charset=utf-8"),
    );
    assert!(has_content_type(&headers, "application/jwt"));

    for malformed in ["text/application/jwt", "application/jwt-evil"] {
        headers.insert("content-type", HeaderValue::from_static(malformed));
        assert!(!has_content_type(&headers, "application/jwt"));
    }
}

#[test]
fn duplicate_content_types_fail_closed() {
    let mut headers = HeaderMap::new();
    headers.append("content-type", HeaderValue::from_static("application/jwt"));
    headers.append("content-type", HeaderValue::from_static("application/json"));

    assert!(!has_content_type(&headers, "application/jwt"));
    assert!(!has_content_type(&headers, "application/json"));
}
