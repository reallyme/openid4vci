// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP security policy regression tests.

use std::sync::Arc;

use axum::http::{header::AUTHORIZATION, HeaderMap, Uri};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_openid_oauth::{
    jwk_thumbprint, jwt::sign_compact_jwt, DpopProof, DpopValidationContext, DpopVerifier,
    JwtSigner, OauthError,
};
use serde_json::{json, Value};

use super::{
    absolute_target_uri, is_token68, validate_http_security, HttpSecurityError,
    HttpSecurityValidation, IssuerHttpSecurityConfig,
};
use crate::serve_oauth::OAuthHttpErrorReason;
use crate::serve_oauth::OAuthHttpResult;
use crate::validate_access_token::{
    AccessTokenValidator, CredentialAuthorizationDecision, ValidatedAccessToken,
};

struct DpopBoundTokenValidator;

struct AcceptingDpopVerifier;

impl JwtSigner for AcceptingDpopVerifier {
    fn algorithm(&self) -> &str {
        "ES256"
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, OauthError> {
        Ok(signing_input.to_vec())
    }
}

impl DpopVerifier for AcceptingDpopVerifier {
    fn verify_signature(
        &self,
        _protected_header: &Value,
        _signing_input: &[u8],
        _signature: &[u8],
    ) -> Result<(), OauthError> {
        Ok(())
    }

    fn check_replay(&self, _jti: &str, _iat: i64) -> Result<(), OauthError> {
        Ok(())
    }
}

#[test]
fn validated_access_token_retains_client_and_confirmation_binding() {
    let validated = ValidatedAccessToken::new(
        "wallet-client".to_owned(),
        Some("bound-key-thumbprint".to_owned()),
    );

    assert!(validated.as_ref().is_ok_and(|context| {
        context.client_id() == "wallet-client"
            && context.confirmed_jkt() == Some("bound-key-thumbprint")
    }));
}

#[test]
fn validated_access_token_rejects_invalid_client_identifier() {
    let result = ValidatedAccessToken::new("\n".to_owned(), None);

    assert_eq!(
        result.err().map(|error| error.reason),
        Some(OAuthHttpErrorReason::InvalidClient)
    );
}

#[test]
fn validated_access_token_rejects_invalid_confirmation_binding() {
    let result = ValidatedAccessToken::new("wallet-client".to_owned(), Some("\0".to_owned()));

    assert_eq!(
        result.err().map(|error| error.reason),
        Some(OAuthHttpErrorReason::InvalidDpopProof)
    );
}

impl AccessTokenValidator for DpopBoundTokenValidator {
    fn validate_access_token(&self, _access_token: &str) -> OAuthHttpResult<ValidatedAccessToken> {
        ValidatedAccessToken::new(
            "wallet-client".to_owned(),
            Some("bound-key-thumbprint".to_owned()),
        )
    }

    fn authorize_credential_request(
        &self,
        _access_token: &str,
        _selector: &openid4vci_types::CredentialSelector,
    ) -> OAuthHttpResult<CredentialAuthorizationDecision> {
        let context = openid4vci_issuer::IssuanceAuthorization::new(
            "pid".to_owned(),
            "subject-1".to_owned(),
            [7_u8; 32],
        )
        .map_err(|_| {
            crate::serve_oauth::OAuthHttpError::new(
                crate::serve_oauth::OAuthHttpErrorReason::InvalidRequest,
            )
        })?;
        Ok(CredentialAuthorizationDecision::Authorized(context))
    }
}

#[test]
fn dpop_bound_token_is_not_accepted_as_bearer() {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer access-token"),
    );
    let validator: Arc<dyn AccessTokenValidator> = Arc::new(DpopBoundTokenValidator);
    let uri = Uri::from_static("/credential");
    let result = validate_http_security(
        &IssuerHttpSecurityConfig {
            dpop: None,
            wallet_attestation: None,
        },
        HttpSecurityValidation {
            dpop_verifier: None,
            attestation_verifier: None,
            attestation_evidence_recorder: None,
            access_token_validator: &validator,
            issuer: "https://issuer.example",
            headers: &headers,
            uri: &uri,
        },
        1_700_000_000,
    );
    assert!(matches!(result, Err(HttpSecurityError::InvalidAccessToken)));
}

#[test]
fn token68_rejects_embedded_padding_and_whitespace() {
    assert!(!is_token68("abc=def"));
    assert!(!is_token68("abc def"));
    assert!(is_token68("abc_DEF-123=="));
}

#[test]
fn dpop_target_preserves_encoded_path_octets_and_excludes_query() {
    let uri = Uri::try_from("/tenant/%63redential?transport_hint=ignored");
    assert!(uri.is_ok());
    if let Ok(uri) = uri {
        assert!(matches!(
            absolute_target_uri("https://issuer.example/openid4vci/issuer", &uri).as_deref(),
            Ok("https://issuer.example/tenant/%63redential")
        ));
    }
}

#[test]
fn dpop_validation_ignores_query_and_fragment_in_htu() -> Result<(), OauthError> {
    let verifier = AcceptingDpopVerifier;
    let access_token = "access-token";
    let public_jwk = json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
    let ath = bytes_to_base64url(reallyme_crypto::sha2::digest(access_token.as_bytes()).as_bytes());
    let jwt = sign_compact_jwt(
        &json!({"typ":"dpop+jwt","alg":"ES256","jwk":public_jwk}),
        &json!({
            "jti":"proof-with-components",
            "htm":"POST",
            "htu":"https://issuer.example/credential?ignored=true#ignored",
            "iat":1_700_000_000_i64,
            "ath":ath
        }),
        &verifier,
    )?;
    let proof = DpopProof::new(jwt.as_str().to_owned())?;
    let confirmed_jkt = jwk_thumbprint(&public_jwk)?;

    proof.validate(
        &DpopValidationContext {
            method: "POST".to_owned(),
            target_uri: "https://issuer.example/credential".to_owned(),
            access_token: Some(access_token.to_owned()),
            nonce: None,
            earliest_iat: 1_699_999_990,
            latest_iat: 1_700_000_010,
            confirmed_jkt: Some(confirmed_jkt),
        },
        &verifier,
    )
}
