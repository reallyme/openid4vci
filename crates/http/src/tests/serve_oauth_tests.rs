// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{parse_oauth_form, OAuthHttpErrorReason, OAuthResponseEncodingError, TokenResponse};

#[test]
fn oauth_form_rejects_duplicate_parameters() {
    let result = parse_oauth_form(b"client_id=one&client_id=two");
    assert_eq!(
        result.err().map(|error| error.reason),
        Some(OAuthHttpErrorReason::InvalidRequest)
    );
}

#[test]
fn oauth_form_rejects_invalid_percent_encoded_utf8() {
    let result = parse_oauth_form(b"client_id=%FF");
    assert_eq!(
        result.err().map(|error| error.reason),
        Some(OAuthHttpErrorReason::InvalidRequest)
    );
}

#[test]
fn oauth_form_decodes_valid_components() {
    let result =
        parse_oauth_form(b"scope=openid+credential&redirect_uri=https%3A%2F%2Fwallet.example");
    assert_eq!(
        result
            .as_ref()
            .ok()
            .and_then(|parameters| parameters.get("scope"))
            .map(String::as_str),
        Some("openid credential")
    );
    assert_eq!(
        result
            .as_ref()
            .ok()
            .and_then(|parameters| parameters.get("redirect_uri"))
            .map(String::as_str),
        Some("https://wallet.example")
    );
}

#[test]
fn token_response_serialization_is_bounded() {
    let response = TokenResponse::new("a".repeat(65_536), "DPoP".to_owned(), 300, Vec::new());

    assert_eq!(
        response.to_json().err(),
        Some(OAuthResponseEncodingError::OutputTooLarge)
    );
}

#[test]
fn token_response_serializes_valid_shape() {
    let response = TokenResponse::new("token-1".to_owned(), "DPoP".to_owned(), 300, Vec::new());

    let encoded = response.to_json();
    assert!(encoded.is_ok());
}

#[test]
fn token_response_serializes_optional_refresh_token() {
    let response = TokenResponse::new(
        "access-token-1".to_owned(),
        "DPoP".to_owned(),
        300,
        Vec::new(),
    )
    .with_refresh_token("refresh-token-1".to_owned());

    let encoded = response.to_json();
    assert!(encoded
        .as_ref()
        .is_ok_and(|body| body.contains(r#""refresh_token":"refresh-token-1""#)));
}
