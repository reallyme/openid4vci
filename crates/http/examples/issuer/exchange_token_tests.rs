// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client and client-instance binding tests for token exchanges.

use openid4vci_http::{parse_oauth_form, CredentialAuthorizationDecision, OAuthHttpErrorReason};
use openid4vci_types::CredentialSelector;

use super::credential_authorization::CredentialAuthorization;
use super::exchange_token::{validate_client_binding, validate_refresh_client_binding};
use super::store_authorization_state::{
    opaque_token_digest, AccessTokenRecord, AuthenticatedClient, CodeRecord,
    ExampleOAuthAuthorizationServer, RefreshTokenRecord,
};

#[test]
fn authorization_code_binding_accepts_the_original_client_instance() {
    let parameters = parse_oauth_form(b"client_id=wallet-1");
    assert!(parameters.as_ref().is_ok_and(|parameters| {
        validate_client_binding(parameters, &client(), &code_record()).is_ok()
    }));
}

#[test]
fn authorization_code_binding_rejects_a_different_client_instance() {
    let parameters = parse_oauth_form(b"client_id=wallet-1");
    let different = AuthenticatedClient {
        subject: "wallet-subject".to_owned(),
        instance_key_thumbprint: "different-instance-key".to_owned(),
    };
    assert_eq!(
        parameters.as_ref().ok().and_then(|parameters| {
            validate_client_binding(parameters, &different, &code_record())
                .err()
                .map(|error| error.reason)
        }),
        Some(OAuthHttpErrorReason::InvalidGrant)
    );
}

#[test]
fn refresh_binding_rejects_a_different_client_identifier() {
    let parameters = parse_oauth_form(b"client_id=wallet-2");
    assert_eq!(
        parameters.as_ref().ok().and_then(|parameters| {
            validate_refresh_client_binding(parameters, &client(), &refresh_record())
                .err()
                .map(|error| error.reason)
        }),
        Some(OAuthHttpErrorReason::InvalidGrant)
    );
}

#[test]
fn access_token_authorizes_its_configuration_and_credential_identifier() {
    let server = authorization_server();
    let token = server.issue_access_token(
        "dpop-key".to_owned(),
        "wallet-subject".to_owned(),
        vec![CredentialAuthorization::SdJwtPid],
    );

    assert!(token.as_ref().is_ok_and(|token| {
        matches!(
            server.authorize_access_token_credential(
                token,
                &CredentialSelector::ConfigurationId("pid".to_owned()),
            ),
            Ok(CredentialAuthorizationDecision::Authorized(_))
        ) && matches!(
            server.authorize_access_token_credential(
                token,
                &CredentialSelector::CredentialIdentifier("pid-credential-1".to_owned()),
            ),
            Ok(CredentialAuthorizationDecision::Authorized(_))
        )
    }));
}

#[test]
fn access_token_rejects_cross_configuration_substitution() {
    let server = authorization_server();
    let token = server.issue_access_token(
        "dpop-key".to_owned(),
        "wallet-subject".to_owned(),
        vec![CredentialAuthorization::SdJwtPid],
    );
    let decision = token.as_ref().ok().and_then(|token| {
        server
            .authorize_access_token_credential(
                token,
                &CredentialSelector::ConfigurationId("pid-mdoc".to_owned()),
            )
            .ok()
    });

    assert!(matches!(
        decision,
        Some(CredentialAuthorizationDecision::InsufficientAuthorization)
    ));
}

#[test]
fn access_token_without_credential_authorization_fails_closed() {
    let server = authorization_server();
    let token = "access-token-without-authorization".to_owned();
    let record = AccessTokenRecord {
        dpop_jkt: "dpop-key".to_owned(),
        client_subject: "wallet-subject".to_owned(),
        credential_authorizations: Vec::new(),
        expires_at: u64::MAX,
    };
    let inserted = server
        .access_tokens
        .lock()
        .map(|mut records| records.insert(opaque_token_digest(&token), record));
    assert!(inserted.is_ok());
    assert!(matches!(
        server
            .authorize_access_token_credential(
                &token,
                &CredentialSelector::ConfigurationId("pid".to_owned()),
            )
            .ok(),
        Some(CredentialAuthorizationDecision::InsufficientAuthorization)
    ));
}

#[test]
fn access_token_distinguishes_unknown_selector_kinds() {
    let server = authorization_server();
    let token = server.issue_access_token(
        "dpop-key".to_owned(),
        "wallet-subject".to_owned(),
        vec![CredentialAuthorization::SdJwtPid],
    );

    assert!(token.as_ref().is_ok_and(|token| {
        matches!(
            server.authorize_access_token_credential(
                token,
                &CredentialSelector::ConfigurationId("unknown".to_owned()),
            ),
            Ok(CredentialAuthorizationDecision::UnknownCredentialConfiguration)
        ) && matches!(
            server.authorize_access_token_credential(
                token,
                &CredentialSelector::CredentialIdentifier("unknown".to_owned()),
            ),
            Ok(CredentialAuthorizationDecision::UnknownCredentialIdentifier)
        )
    }));
}

#[test]
fn refreshed_access_token_preserves_original_credential_authorization() {
    let server = authorization_server();
    let refresh = refresh_record();
    let token = server.issue_access_token(
        "refreshed-dpop-key".to_owned(),
        refresh.client_subject.clone(),
        refresh.credential_authorizations.clone(),
    );

    assert!(token.as_ref().is_ok_and(|token| {
        matches!(
            server.authorize_access_token_credential(
                token,
                &CredentialSelector::ConfigurationId("pid".to_owned()),
            ),
            Ok(CredentialAuthorizationDecision::Authorized(_))
        )
    }));
}

fn client() -> AuthenticatedClient {
    AuthenticatedClient {
        subject: "wallet-subject".to_owned(),
        instance_key_thumbprint: "instance-key-1".to_owned(),
    }
}

fn code_record() -> CodeRecord {
    CodeRecord {
        client_id: "wallet-1".to_owned(),
        client_subject: "wallet-subject".to_owned(),
        client_instance_key_thumbprint: "instance-key-1".to_owned(),
        code_challenge: "challenge".to_owned(),
        dpop_jkt: Some("dpop-key".to_owned()),
        credential_authorizations: vec![CredentialAuthorization::SdJwtPid],
        expires_at: u64::MAX,
    }
}

fn refresh_record() -> RefreshTokenRecord {
    RefreshTokenRecord {
        client_id: "wallet-1".to_owned(),
        client_subject: "wallet-subject".to_owned(),
        client_instance_key_thumbprint: "instance-key-1".to_owned(),
        credential_authorizations: vec![CredentialAuthorization::SdJwtPid],
        expires_at: u64::MAX,
    }
}

fn authorization_server() -> ExampleOAuthAuthorizationServer {
    ExampleOAuthAuthorizationServer::new(
        "https://issuer.example/".to_owned(),
        "https://issuer.example/".to_owned(),
    )
}
