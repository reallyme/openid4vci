// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential authorization parsing and response tests.

use openid4vci_http::parse_oauth_form;
use serde_json::json;

use super::credential_authorization::CredentialAuthorization;

#[test]
fn mdoc_scope_produces_matching_token_authorization_details() {
    let parameters = parse_oauth_form(b"scope=openid%20pid-mdoc");
    let authorizations = parameters
        .as_ref()
        .ok()
        .and_then(|parameters| CredentialAuthorization::from_parameters(parameters).ok());
    let details = authorizations.as_ref().map(|values| {
        values
            .iter()
            .map(|value| value.response_detail("https://issuer.example/"))
            .collect::<Vec<_>>()
    });

    assert_eq!(
        details
            .as_ref()
            .and_then(|values| values.first())
            .and_then(|value| value.get("credential_configuration_id"))
            .and_then(serde_json::Value::as_str),
        Some("pid-mdoc")
    );
}

#[test]
fn authorization_details_select_the_requested_configuration() {
    let parameters = parse_oauth_form(
        b"authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22credential_configuration_id%22%3A%22pid%22%7D%5D",
    );
    let result = parameters
        .as_ref()
        .ok()
        .and_then(|parameters| CredentialAuthorization::from_parameters(parameters).ok());

    assert_eq!(result, Some(vec![CredentialAuthorization::SdJwtPid]));
}

#[test]
fn unknown_and_duplicate_credential_authorizations_fail_closed() {
    for body in [
        b"scope=unknown".as_slice(),
        b"scope=pid%20pid".as_slice(),
        b"authorization_details=%5B%5D".as_slice(),
        b"authorization_details=%7B%7D".as_slice(),
        b"authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22credential_configuration_id%22%3A%22unknown%22%7D%5D".as_slice(),
    ] {
        let rejected = parse_oauth_form(body).is_ok_and(|parameters| {
            CredentialAuthorization::from_parameters(&parameters).is_err()
        });
        assert!(rejected);
    }
}

#[test]
fn excessive_authorization_details_fail_closed() {
    let detail = json!({
        "type": "openid_credential",
        "credential_configuration_id": "pid"
    });
    let details = serde_json::to_string(&vec![detail; 9]);
    let body = details.ok().map(|details| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("authorization_details", &details)
            .finish()
    });
    let rejected = body.as_deref().is_some_and(|body| {
        parse_oauth_form(body.as_bytes())
            .is_ok_and(|parameters| CredentialAuthorization::from_parameters(&parameters).is_err())
    });

    assert!(rejected);
}

#[test]
fn oversized_authorization_parameter_fails_before_parsing() {
    const OVERSIZED_VALUE_BYTES: usize = 16_385;
    let mut body = b"scope=".to_vec();
    body.extend(core::iter::repeat_n(b'a', OVERSIZED_VALUE_BYTES));

    assert!(parse_oauth_form(&body).is_err());
}
