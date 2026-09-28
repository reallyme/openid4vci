// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::{Arc, Barrier};

use openid4vci_http::{parse_oauth_form, OAuthAuthorizationServer, OAuthHttpErrorReason};

use super::store_authorization_state::{ExampleOAuthAuthorizationServer, ParRecord};

const CLIENT_ID: &str = "openid4vci-conformance-wallet";
const SECONDARY_CLIENT_ID: &str = "openid4vci-conformance-wallet-2";
const REDIRECT_URI: &str = "https://suite.example/test/a/release/callback";
const SECONDARY_REDIRECT_URI: &str = "https://suite.example/test/a/release/callback2";

fn authorization_server() -> ExampleOAuthAuthorizationServer {
    ExampleOAuthAuthorizationServer::new(
        "https://issuer.example/openid4vci/example-issuer/".to_owned(),
        "https://issuer.example/".to_owned(),
    )
}

fn insert_par(server: &ExampleOAuthAuthorizationServer, redirect_uri: &str, used: bool) {
    let record = ParRecord {
        client_id: CLIENT_ID.to_owned(),
        client_subject: CLIENT_ID.to_owned(),
        client_instance_key_thumbprint: "test-thumbprint".to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        state: Some("state-one".to_owned()),
        code_challenge: "test-challenge".to_owned(),
        dpop_jkt: None,
        credential_authorizations: Vec::new(),
        expires_at: u64::MAX,
        used,
    };
    match server.par_records.lock() {
        Ok(mut records) => {
            records.insert("urn:openid4vci:used-request".to_owned(), record);
        }
        Err(_) => panic!("test PAR store lock was poisoned"),
    }
}

fn complete_authorization(
    server: &ExampleOAuthAuthorizationServer,
    parameters: &openid4vci_http::OAuthParameters,
) -> openid4vci_http::AuthorizationResponse {
    let pending = match server.authorize(parameters) {
        Ok(value) => value,
        Err(error) => panic!("authorization visit failed: {:?}", error.reason),
    };
    let completion_url = match url::Url::parse(pending.location()) {
        Ok(value) => value,
        Err(_) => panic!("authorization completion URL was invalid"),
    };
    let completion = match completion_url
        .query()
        .ok_or(())
        .and_then(|query| parse_oauth_form(query.as_bytes()).map_err(|_| ()))
    {
        Ok(value) => value,
        Err(()) => panic!("authorization completion parameters were invalid"),
    };
    match server.authorize(&completion) {
        Ok(value) => value,
        Err(error) => panic!("authorization completion failed: {:?}", error.reason),
    }
}

#[test]
fn direct_authorization_error_redirects_only_to_exact_registration() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    let parameters = parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet&redirect_uri=https%3A%2F%2Fsuite.example%2Ftest%2Fa%2Frelease%2Fcallback&state=state-one",
    );
    let response = match parameters.and_then(|value| server.authorize(&value)) {
        Ok(value) => value,
        Err(error) => panic!("registered callback was rejected: {:?}", error.reason),
    };

    assert_eq!(
        response.location(),
        "https://suite.example/test/a/release/callback?error=invalid_request&state=state-one"
    );
}

#[test]
fn direct_authorization_error_rejects_unregistered_callback() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    let parameters = match parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet&redirect_uri=https%3A%2F%2Fattacker.example%2Fcallback",
    ) {
        Ok(value) => value,
        Err(error) => panic!("test parameters were rejected: {:?}", error.reason),
    };

    let error = match server.authorize(&parameters) {
        Ok(_) => panic!("unregistered callback was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.reason, OAuthHttpErrorReason::InvalidRequest);
}

#[test]
fn par_registration_requires_an_exact_redirect_uri() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    let alternate = "https://suite.example/test/a/release/callback?mode=alternate";
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), alternate.to_owned())
        .is_ok());

    assert!(server
        .validate_registered_client(CLIENT_ID, REDIRECT_URI)
        .is_ok());
    assert!(server
        .validate_registered_client(CLIENT_ID, alternate)
        .is_ok());
    let error =
        match server.validate_registered_client(CLIENT_ID, "https://attacker.example/callback") {
            Ok(()) => panic!("unregistered PAR callback was accepted"),
            Err(error) => error,
        };
    assert_eq!(
        error.reason,
        OAuthHttpErrorReason::InvalidPushedAuthorizationRequest
    );
}

#[test]
fn used_par_redirects_error_only_to_its_registered_callback() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    insert_par(&server, REDIRECT_URI, true);
    let parameters = parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet&request_uri=urn%3Aopenid4vci%3Aused-request",
    );
    let response = match parameters.and_then(|value| server.authorize(&value)) {
        Ok(value) => value,
        Err(error) => panic!("used PAR callback was rejected: {:?}", error.reason),
    };

    assert_eq!(
        response.location(),
        "https://suite.example/test/a/release/callback?error=invalid_request_uri&state=state-one"
    );
}

#[test]
fn used_par_does_not_redirect_when_registration_is_absent() {
    let server = authorization_server();
    insert_par(&server, "https://attacker.example/callback", true);
    let parameters = match parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet&request_uri=urn%3Aopenid4vci%3Aused-request",
    ) {
        Ok(value) => value,
        Err(error) => panic!("test parameters were rejected: {:?}", error.reason),
    };

    let error = match server.authorize(&parameters) {
        Ok(_) => panic!("unregistered retained PAR callback was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.reason, OAuthHttpErrorReason::InvalidRequestUri);
}

#[test]
fn mismatched_par_redirects_only_to_the_original_par_registration() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    assert!(server
        .register_redirect_uri(
            SECONDARY_CLIENT_ID.to_owned(),
            SECONDARY_REDIRECT_URI.to_owned()
        )
        .is_ok());
    insert_par(&server, REDIRECT_URI, true);
    let parameters = parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet-2&redirect_uri=https%3A%2F%2Fattacker.example%2Fcallback&request_uri=urn%3Aopenid4vci%3Aused-request&state=secondary-state",
    );
    let response = match parameters.and_then(|value| server.authorize(&value)) {
        Ok(value) => value,
        Err(error) => panic!(
            "registered secondary client was rejected: {:?}",
            error.reason
        ),
    };

    assert_eq!(
        response.location(),
        "https://suite.example/test/a/release/callback?error=invalid_request_uri&state=state-one"
    );
}

#[test]
fn mismatched_par_does_not_redirect_for_an_unknown_client() {
    let server = authorization_server();
    insert_par(&server, REDIRECT_URI, true);
    let parameters = match parse_oauth_form(
        b"client_id=unknown-client&redirect_uri=https%3A%2F%2Fattacker.example%2Fcallback&request_uri=urn%3Aopenid4vci%3Aused-request",
    ) {
        Ok(value) => value,
        Err(error) => panic!("test parameters were rejected: {:?}", error.reason),
    };

    let error = match server.authorize(&parameters) {
        Ok(_) => panic!("unknown client received an authorization redirect"),
        Err(error) => error,
    };
    assert_eq!(error.reason, OAuthHttpErrorReason::InvalidRequestUri);
}

#[test]
fn authorization_visit_remains_reusable_until_completion() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    insert_par(&server, REDIRECT_URI, false);
    let parameters = match parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet&request_uri=urn%3Aopenid4vci%3Aused-request",
    ) {
        Ok(value) => value,
        Err(error) => panic!("test parameters were rejected: {:?}", error.reason),
    };

    let first_visit = match server.authorize(&parameters) {
        Ok(value) => value,
        Err(error) => panic!("first authorization visit failed: {:?}", error.reason),
    };
    let second_visit = match server.authorize(&parameters) {
        Ok(value) => value,
        Err(error) => panic!("second authorization visit failed: {:?}", error.reason),
    };

    assert_eq!(first_visit.location(), second_visit.location());
    let used = match server.par_records.lock() {
        Ok(records) => records
            .get("urn:openid4vci:used-request")
            .is_some_and(|record| record.used),
        Err(_) => panic!("test PAR store lock was poisoned"),
    };
    assert!(!used);
}

#[test]
fn authorization_consumes_par_before_a_replay_can_mint_another_code() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    insert_par(&server, REDIRECT_URI, false);
    let parameters = match parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet&request_uri=urn%3Aopenid4vci%3Aused-request",
    ) {
        Ok(value) => value,
        Err(error) => panic!("test parameters were rejected: {:?}", error.reason),
    };

    let first = complete_authorization(&server, &parameters);
    assert!(first.location().contains("code="));
    let replay = match server.authorize(&parameters) {
        Ok(value) => value,
        Err(error) => panic!("replay error callback failed: {:?}", error.reason),
    };
    assert!(replay.location().contains("error=invalid_request_uri"));
    assert!(!replay.location().contains("code="));
}

#[test]
fn concurrent_authorization_replay_mints_exactly_one_code() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    insert_par(&server, REDIRECT_URI, false);
    let server = Arc::new(server);
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();

    for _ in 0..2 {
        let server = Arc::clone(&server);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let parameters = match parse_oauth_form(
                b"client_id=openid4vci-conformance-wallet&request_uri=urn%3Aopenid4vci%3Aused-request",
            ) {
                Ok(value) => value,
                Err(error) => panic!("test parameters were rejected: {:?}", error.reason),
            };
            barrier.wait();
            let pending = match server.authorize(&parameters) {
                Ok(value) => value,
                Err(error) => panic!("authorization visit failed: {:?}", error.reason),
            };
            let completion_url = match url::Url::parse(pending.location()) {
                Ok(value) => value,
                Err(_) => panic!("authorization completion URL was invalid"),
            };
            let completion = match completion_url.query() {
                Some(query) => match parse_oauth_form(query.as_bytes()) {
                    Ok(value) => value,
                    Err(error) => panic!("completion parameters failed: {:?}", error.reason),
                },
                None => panic!("authorization completion query was missing"),
            };
            barrier.wait();
            match server.authorize(&completion) {
                Ok(response) => response.location().to_owned(),
                Err(error) => panic!("authorization failed: {:?}", error.reason),
            }
        }));
    }

    let mut locations = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(location) => locations.push(location),
            Err(_) => panic!("authorization worker panicked"),
        }
    }
    assert_eq!(
        locations
            .iter()
            .filter(|location| location.contains("code="))
            .count(),
        1
    );
    assert_eq!(
        locations
            .iter()
            .filter(|location| location.contains("error=invalid_request_uri"))
            .count(),
        1
    );
}

#[test]
fn user_rejection_also_consumes_par() {
    let mut server = authorization_server();
    assert!(server
        .register_redirect_uri(CLIENT_ID.to_owned(), REDIRECT_URI.to_owned())
        .is_ok());
    insert_par(&server, REDIRECT_URI, false);
    let rejected = match parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet&request_uri=urn%3Aopenid4vci%3Aused-request&reallyme_oidf_user_reject=1",
    ) {
        Ok(value) => value,
        Err(error) => panic!("test parameters were rejected: {:?}", error.reason),
    };
    let rejected_response = complete_authorization(&server, &rejected);
    assert!(rejected_response.location().contains("error=access_denied"));

    let replay = match parse_oauth_form(
        b"client_id=openid4vci-conformance-wallet&request_uri=urn%3Aopenid4vci%3Aused-request",
    ) {
        Ok(value) => value,
        Err(error) => panic!("test parameters were rejected: {:?}", error.reason),
    };
    let response = match server.authorize(&replay) {
        Ok(value) => value,
        Err(error) => panic!("replay error callback failed: {:?}", error.reason),
    };
    assert!(response.location().contains("error=invalid_request_uri"));
    assert!(!response.location().contains("code="));
}
