// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared fixtures for Axum issuer integration tests.

// Each integration-test binary includes this fixture module independently, so
// helpers used by the sibling binary are intentionally dormant in either one.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::to_bytes;
use openid4vci_http::{
    default_max_body_bytes, AccessTokenValidator, AuthorizationResponse, AxumIssuerParts,
    AxumIssuerSecurityPolicy, AxumIssuerState, Clock, CredentialAuthorizationDecision,
    DpopHttpConfig, IssuerHttpSecurityConfig, OAuthAuthorizationServer, OAuthHttpError,
    OAuthHttpErrorReason, OAuthHttpResult, OAuthParameters, OAuthRequestHeaders,
    PushedAuthorizationResponse, TokenResponse, ValidatedAccessToken, WalletAttestationHttpConfig,
};
use openid4vci_issuer::{
    ConfirmationJwk, CredentialEndpointConfig, IssuerError, IssuerResult, IssuerStatus,
    NonceManager, ProofAlgorithm, ProofKind, ProofVerificationContext, ProofVerifier,
    VerifiedProof, VerifiedProofSet,
};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::{encode_proto, OpenId4VciProtoJson};
use openid4vci_types::{
    CredentialConfiguration, CredentialFormat, CredentialResponseEncryptionMetadata,
    CredentialSelector, IssuerMetadata, Proofs,
};
use reallyme_openid_oauth::jwt::sign_compact_jwt;
use reallyme_openid_oauth::{
    jwk_thumbprint, AttestationPopRequest, AuthorizationServerMetadata, DpopProofRequest,
};
use serde_json::json;
use thiserror::Error;

mod test_oauth_verifier;
pub(super) use test_oauth_verifier::TestOauthVerifier;
mod test_notification_handler;
pub(super) use test_notification_handler::TestNotificationHandler;
mod test_issuer_services;
pub(super) use test_issuer_services::{
    TestCredentialIssuer, TestDeferredIssuer, TestEvidenceRecorder, TestRequestDecryptor,
    TestResponseEncryptor,
};

pub(super) const ISSUER: &str = "https://issuer.example";
const WALLET_CLIENT_ID: &str = "wallet-client";

fn test_issuance_authorization(
    configuration_id: &str,
) -> OAuthHttpResult<openid4vci_issuer::IssuanceAuthorization> {
    openid4vci_issuer::IssuanceAuthorization::new(
        configuration_id.to_owned(),
        "subject-1".to_owned(),
        [7_u8; 32],
    )
    .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(super) enum RouteTestError {
    #[error("state")]
    State,
    #[error("request")]
    Request,
    #[error("response")]
    Response,
    #[error("json")]
    Json,
    #[error("proto")]
    Proto,
    #[error("oauth")]
    Oauth,
}

pub(super) fn encode_proto_body<M: OpenId4VciProtoJson>(
    message: &M,
) -> Result<Vec<u8>, RouteTestError> {
    let mut encoded = encode_proto(message).map_err(|_| RouteTestError::Proto)?;
    // The HTTP body deliberately assumes ownership here, matching the runtime
    // adapter's explicit transfer out of the codec's zeroizing staging owner.
    Ok(core::mem::take(&mut *encoded))
}

pub(super) async fn response_body(
    response: axum::response::Response,
) -> Result<String, RouteTestError> {
    let bytes = response_bytes(response).await?;
    String::from_utf8(bytes.to_vec()).map_err(|_| RouteTestError::Response)
}

pub(super) async fn response_bytes(
    response: axum::response::Response,
) -> Result<axum::body::Bytes, RouteTestError> {
    to_bytes(response.into_body(), default_max_body_bytes())
        .await
        .map_err(|_| RouteTestError::Response)
}

pub(super) fn state() -> Result<AxumIssuerState, RouteTestError> {
    AxumIssuerState::new(parts()?).map_err(|_| RouteTestError::State)
}

pub(super) fn parts() -> Result<AxumIssuerParts, RouteTestError> {
    Ok(AxumIssuerParts {
        security_policy: AxumIssuerSecurityPolicy::interoperability(),
        metadata: metadata()?,
        authorization_server_metadata: None,
        oauth_authorization_server: None,
        access_token_validator: Arc::new(TestBearerAccessTokenValidator),
        metadata_signer: None,
        credential_configs: test_credential_configs()?,
        nonce_manager: seeded_nonce_manager(),
        nonce_ttl_seconds: 60,
        proof_verifier: Arc::new(TestProofVerifier),
        credential_issuer: Arc::new(TestCredentialIssuer),
        response_encryptor: Arc::new(TestResponseEncryptor),
        request_decryptor: Some(Arc::new(TestRequestDecryptor)),
        http_security: IssuerHttpSecurityConfig {
            dpop: None,
            wallet_attestation: None,
        },
        dpop_verifier: None,
        attestation_client_authentication_verifier: None,
        wallet_attestation_evidence_recorder: None,
        deferred_issuer: Arc::new(TestDeferredIssuer),
        notification_handler: Arc::new(TestNotificationHandler),
        max_body_bytes: default_max_body_bytes(),
        clock: Arc::new(TestClock),
    })
}

pub(super) fn state_with_authorization_server_metadata() -> Result<AxumIssuerState, RouteTestError>
{
    AxumIssuerState::new(AxumIssuerParts {
        security_policy: AxumIssuerSecurityPolicy::interoperability(),
        metadata: metadata()?,
        authorization_server_metadata: Some(test_authorization_server_metadata()?),
        oauth_authorization_server: None,
        access_token_validator: Arc::new(TestBearerAccessTokenValidator),
        metadata_signer: None,
        credential_configs: test_credential_configs()?,
        nonce_manager: seeded_nonce_manager(),
        nonce_ttl_seconds: 60,
        proof_verifier: Arc::new(TestProofVerifier),
        credential_issuer: Arc::new(TestCredentialIssuer),
        response_encryptor: Arc::new(TestResponseEncryptor),
        request_decryptor: Some(Arc::new(TestRequestDecryptor)),
        http_security: IssuerHttpSecurityConfig {
            dpop: None,
            wallet_attestation: None,
        },
        dpop_verifier: None,
        attestation_client_authentication_verifier: None,
        wallet_attestation_evidence_recorder: None,
        deferred_issuer: Arc::new(TestDeferredIssuer),
        notification_handler: Arc::new(TestNotificationHandler),
        max_body_bytes: default_max_body_bytes(),
        clock: Arc::new(TestClock),
    })
    .map_err(|_| RouteTestError::State)
}

fn test_authorization_server_metadata() -> Result<AuthorizationServerMetadata, RouteTestError> {
    let body = json!({
        "issuer": ISSUER,
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "pushed_authorization_request_endpoint": "https://issuer.example/par",
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "require_pushed_authorization_requests": true,
        "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth"],
        "authorization_response_iss_parameter_supported": true
    });
    AuthorizationServerMetadata::parse_json(&body.to_string()).map_err(|_| RouteTestError::State)
}

pub(super) fn haip_baseline_parts() -> Result<AxumIssuerParts, RouteTestError> {
    let mut value = parts()?;
    value.security_policy = AxumIssuerSecurityPolicy::new(true, false, false, true)
        .with_haip_authorization_server_controls();
    value.authorization_server_metadata = Some(test_authorization_server_metadata()?);
    value.oauth_authorization_server = Some(Arc::new(TestAuthorizationServer));
    value.http_security.dpop = Some(DpopHttpConfig {
        nonce: None,
        max_age_seconds: 10,
        max_future_skew_seconds: 10,
    });
    value.dpop_verifier = Some(Arc::new(TestOauthVerifier));
    Ok(value)
}

pub(super) fn state_with_authorization_server_routes() -> Result<AxumIssuerState, RouteTestError> {
    AxumIssuerState::new(AxumIssuerParts {
        security_policy: AxumIssuerSecurityPolicy::interoperability(),
        metadata: metadata()?,
        authorization_server_metadata: None,
        oauth_authorization_server: Some(Arc::new(TestAuthorizationServer)),
        access_token_validator: Arc::new(TestBearerAccessTokenValidator),
        metadata_signer: None,
        credential_configs: test_credential_configs()?,
        nonce_manager: seeded_nonce_manager(),
        nonce_ttl_seconds: 60,
        proof_verifier: Arc::new(TestProofVerifier),
        credential_issuer: Arc::new(TestCredentialIssuer),
        response_encryptor: Arc::new(TestResponseEncryptor),
        request_decryptor: Some(Arc::new(TestRequestDecryptor)),
        http_security: IssuerHttpSecurityConfig {
            dpop: None,
            wallet_attestation: None,
        },
        dpop_verifier: None,
        attestation_client_authentication_verifier: None,
        wallet_attestation_evidence_recorder: None,
        deferred_issuer: Arc::new(TestDeferredIssuer),
        notification_handler: Arc::new(TestNotificationHandler),
        max_body_bytes: default_max_body_bytes(),
        clock: Arc::new(TestClock),
    })
    .map_err(|_| RouteTestError::State)
}

pub(super) const TEST_NOW_UNIX: i64 = 1_700_000_000;
pub(super) const TEST_NONCE: &str = "nonce-1";

fn test_response_encryption_metadata() -> CredentialResponseEncryptionMetadata {
    CredentialResponseEncryptionMetadata {
        alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
        enc_values_supported: Some(vec!["A256GCM".to_owned()]),
        zip_values_supported: None,
        encryption_required: false,
    }
}

/// Fixed clock so DPoP/attestation `iat` windows are deterministic in tests.
pub(super) struct TestClock;

impl Clock for TestClock {
    fn now_unix(&self) -> i64 {
        TEST_NOW_UNIX
    }
}

/// A nonce manager pre-seeded with the nonce returned by `TestProofVerifier`.
pub(super) fn seeded_nonce_manager() -> Arc<dyn NonceManager> {
    Arc::new(TestNonceManager {
        expires_at_unix: Mutex::new(Some(1_700_000_060)),
    })
}

pub(super) fn secured_state() -> Result<AxumIssuerState, RouteTestError> {
    secured_state_with_authorization(None)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TestResourceAuthorization {
    SdJwtPid,
    MdocPid,
    None,
}

impl TestResourceAuthorization {
    const fn configuration_id(self) -> &'static str {
        match self {
            Self::SdJwtPid => "pid",
            Self::MdocPid => "pid-mdoc",
            Self::None => "unsupported",
        }
    }
}

pub(super) fn secured_state_with_resource_authorization(
    authorization: TestResourceAuthorization,
) -> Result<AxumIssuerState, RouteTestError> {
    secured_state_with_authorization(Some(authorization))
}

fn secured_state_with_authorization(
    authorization: Option<TestResourceAuthorization>,
) -> Result<AxumIssuerState, RouteTestError> {
    let resource_validator = authorization
        .map(|authorization| Arc::new(TestResourceAuthorizationServer { authorization }));
    AxumIssuerState::new(AxumIssuerParts {
        security_policy: AxumIssuerSecurityPolicy::interoperability(),
        metadata: metadata()?,
        authorization_server_metadata: None,
        oauth_authorization_server: resource_validator
            .clone()
            .map(|service| service as Arc<dyn OAuthAuthorizationServer>),
        access_token_validator: resource_validator
            .map(|service| service as Arc<dyn AccessTokenValidator>)
            .unwrap_or_else(|| Arc::new(TestAccessTokenValidator)),
        metadata_signer: None,
        credential_configs: test_credential_configs()?,
        nonce_manager: seeded_nonce_manager(),
        nonce_ttl_seconds: 60,
        proof_verifier: Arc::new(TestProofVerifier),
        credential_issuer: Arc::new(TestCredentialIssuer),
        response_encryptor: Arc::new(TestResponseEncryptor),
        request_decryptor: Some(Arc::new(TestRequestDecryptor)),
        http_security: IssuerHttpSecurityConfig {
            dpop: Some(DpopHttpConfig {
                nonce: None,
                max_age_seconds: 10,
                max_future_skew_seconds: 10,
            }),
            wallet_attestation: Some(WalletAttestationHttpConfig {
                expected_audience: ISSUER.to_owned(),
                expected_challenge: None,
                max_age_seconds: 10,
                max_future_skew_seconds: 10,
                max_trust_evidence_age_seconds: 30,
            }),
        },
        dpop_verifier: Some(Arc::new(TestOauthVerifier)),
        attestation_client_authentication_verifier: Some(Arc::new(TestOauthVerifier)),
        wallet_attestation_evidence_recorder: Some(Arc::new(TestEvidenceRecorder)),
        deferred_issuer: Arc::new(TestDeferredIssuer),
        notification_handler: Arc::new(TestNotificationHandler),
        max_body_bytes: default_max_body_bytes(),
        clock: Arc::new(TestClock),
    })
    .map_err(|_| RouteTestError::State)
}

pub(super) struct SecurityHeaders {
    pub(super) dpop: String,
    pub(super) authorization: String,
    pub(super) client_attestation: String,
    pub(super) client_attestation_pop: String,
}

pub(super) fn security_headers(target_uri: &str) -> Result<SecurityHeaders, RouteTestError> {
    let signer = TestOauthVerifier;
    let dpop = DpopProofRequest {
        method: "POST".to_owned(),
        target_uri: target_uri.to_owned(),
        jti: "dpop-jti-1".to_owned(),
        iat: 1_700_000_000,
        public_jwk: json!({"kty":"EC","crv":"P-256","x":"x","y":"y"}),
        access_token: Some("access-token".to_owned()),
        nonce: None,
    }
    .sign(&signer)
    .map_err(|_| RouteTestError::Oauth)?;
    let pop = AttestationPopRequest {
        audience: ISSUER.to_owned(),
        jti: "attestation-pop-jti-1".to_owned(),
        iat: 1_700_000_000,
        challenge: None,
    }
    .sign(&signer)
    .map_err(|_| RouteTestError::Oauth)?;
    let client_attestation = sign_compact_jwt(
        &json!({"typ": "oauth-client-attestation+jwt", "alg": "ES256"}),
        &json!({
            "sub": WALLET_CLIENT_ID,
            "iat": 1_700_000_000_i64,
            "exp": 1_700_000_300_i64,
            "cnf": {
                "jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "B_zLQ0UJb5Yhcm_E5De-DPgcQxCB8yjlVJZyOaxVIu4",
                    "y": "DZcUdT7G939Veqc3FCadWs_rcpS-vc_8Z8FaZREVX4A"
                }
            }
        }),
        &signer,
    )
    .map_err(|_| RouteTestError::Oauth)?;
    Ok(SecurityHeaders {
        dpop: dpop.as_str().to_owned(),
        authorization: "DPoP access-token".to_owned(),
        client_attestation: client_attestation.as_str().to_owned(),
        client_attestation_pop: pop.as_str().to_owned(),
    })
}

pub(super) fn metadata() -> Result<IssuerMetadata, RouteTestError> {
    IssuerMetadata::builder(
        ISSUER.to_owned(),
        "https://issuer.example/credential".to_owned(),
    )
    .nonce_endpoint("https://issuer.example/nonce".to_owned())
    .deferred_credential_endpoint("https://issuer.example/deferred_credential".to_owned())
    .notification_endpoint("https://issuer.example/notification".to_owned())
    .credential_response_encryption(test_response_encryption_metadata())
    .proof_required(true)
    .jwt_proof_signing_alg_values_supported(vec!["ES256".to_owned()])
    .credential_configuration(
        "pid".to_owned(),
        CredentialConfiguration::new(CredentialFormat::SdJwtVc),
    )
    .credential_configuration("pid-mdoc".to_owned(), {
        let mut configuration = CredentialConfiguration::new(CredentialFormat::MsoMdoc);
        configuration.doctype = Some("eu.europa.ec.eudi.pid.1".to_owned());
        configuration
    })
    .build()
    .map_err(|_| RouteTestError::State)
}

fn test_credential_configs() -> Result<BTreeMap<String, CredentialEndpointConfig>, RouteTestError> {
    let metadata = metadata()?;
    let mut configs = BTreeMap::new();
    for configuration_id in metadata.credential_configurations_supported.keys() {
        let config = CredentialEndpointConfig::from_metadata(&metadata, configuration_id, None)
            .map_err(|_| RouteTestError::State)?;
        configs.insert(configuration_id.clone(), config);
    }
    Ok(configs)
}

pub(super) fn proof_request() -> pb::CredentialRequest {
    let mut proofs = pb::Proofs::default();
    proofs.jwt = vec!["a.b.c".to_owned()];
    pb::CredentialRequest {
        selector: Some(pb::CredentialSelector {
            selector: Some(
                pb::credential_selector::Selector::CredentialConfigurationId("pid".to_owned()),
            ),
            __buffa_unknown_fields: Default::default(),
        })
        .into(),
        proofs: Some(proofs).into(),
        ..Default::default()
    }
}

pub(super) struct TestNonceManager {
    expires_at_unix: Mutex<Option<u64>>,
}

impl NonceManager for TestNonceManager {
    fn issue(&self, now_unix: u64, ttl_seconds: u64) -> IssuerResult<String> {
        let expires_at_unix = now_unix
            .checked_add(ttl_seconds)
            .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidRequest))?;
        let mut stored = self
            .expires_at_unix
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        *stored = Some(expires_at_unix);
        Ok(TEST_NONCE.to_owned())
    }

    fn consume(
        &self,
        nonce: &str,
        _replay_partition: &[u8; 32],
        now_unix: u64,
    ) -> IssuerResult<()> {
        let mut stored = self
            .expires_at_unix
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        match *stored {
            Some(expires_at_unix) if nonce == TEST_NONCE && expires_at_unix > now_unix => {
                *stored = None;
                Ok(())
            }
            _ => Err(IssuerError::new(IssuerStatus::InvalidNonce)),
        }
    }
}

pub(super) struct TestAuthorizationServer;

struct TestAccessTokenValidator;

struct TestBearerAccessTokenValidator;

impl AccessTokenValidator for TestBearerAccessTokenValidator {
    fn validate_access_token(&self, access_token: &str) -> OAuthHttpResult<ValidatedAccessToken> {
        if access_token == "access-token" {
            ValidatedAccessToken::new(WALLET_CLIENT_ID.to_owned(), None)
        } else {
            Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))
        }
    }

    fn authorize_credential_request(
        &self,
        access_token: &str,
        selector: &CredentialSelector,
    ) -> OAuthHttpResult<CredentialAuthorizationDecision> {
        self.validate_access_token(access_token)?;
        let configuration_id = match selector {
            CredentialSelector::ConfigurationId(value) => value.as_str(),
            CredentialSelector::CredentialIdentifier(_) => "pid",
        };
        test_issuance_authorization(configuration_id)
            .map(CredentialAuthorizationDecision::Authorized)
    }

    fn authorize_deferred_credential_request(
        &self,
        access_token: &str,
        transaction_id: &str,
    ) -> OAuthHttpResult<openid4vci_issuer::IssuanceAuthorization> {
        self.validate_access_token(access_token)?;
        if matches!(transaction_id, "transaction-1" | "encrypted-transaction-1") {
            test_issuance_authorization("pid")
        } else {
            Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InsufficientAuthorization,
            ))
        }
    }

    fn authorize_notification_request(
        &self,
        access_token: &str,
        notification_id: &str,
    ) -> OAuthHttpResult<()> {
        self.validate_access_token(access_token)?;
        if notification_id == "notification-1" {
            Ok(())
        } else {
            Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InsufficientAuthorization,
            ))
        }
    }
}

impl AccessTokenValidator for TestAccessTokenValidator {
    fn validate_access_token(&self, access_token: &str) -> OAuthHttpResult<ValidatedAccessToken> {
        if access_token != "access-token" {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof));
        }
        let thumbprint = jwk_thumbprint(&json!({"kty":"EC","crv":"P-256","x":"x","y":"y"}))
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
        ValidatedAccessToken::new(WALLET_CLIENT_ID.to_owned(), Some(thumbprint))
    }

    fn authorize_credential_request(
        &self,
        access_token: &str,
        selector: &CredentialSelector,
    ) -> OAuthHttpResult<CredentialAuthorizationDecision> {
        self.validate_access_token(access_token)?;
        let configuration_id = match selector {
            CredentialSelector::ConfigurationId(value) => value.as_str(),
            CredentialSelector::CredentialIdentifier(_) => "pid",
        };
        test_issuance_authorization(configuration_id)
            .map(CredentialAuthorizationDecision::Authorized)
    }

    fn authorize_deferred_credential_request(
        &self,
        access_token: &str,
        transaction_id: &str,
    ) -> OAuthHttpResult<openid4vci_issuer::IssuanceAuthorization> {
        self.validate_access_token(access_token)?;
        if matches!(transaction_id, "transaction-1" | "encrypted-transaction-1") {
            test_issuance_authorization("pid")
        } else {
            Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InsufficientAuthorization,
            ))
        }
    }

    fn authorize_notification_request(
        &self,
        access_token: &str,
        notification_id: &str,
    ) -> OAuthHttpResult<()> {
        self.validate_access_token(access_token)?;
        if notification_id == "notification-1" {
            Ok(())
        } else {
            Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InsufficientAuthorization,
            ))
        }
    }
}

impl OAuthAuthorizationServer for TestAuthorizationServer {
    fn security_capabilities(&self) -> openid4vci_http::OAuthAuthorizationServerCapabilities {
        openid4vci_http::OAuthAuthorizationServerCapabilities::high_assurance()
    }

    fn pushed_authorization_request(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
    ) -> OAuthHttpResult<PushedAuthorizationResponse> {
        if headers.dpop() != Some("dpop-proof") {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest));
        }
        if headers.client_attestation() != Some("attestation") {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        if parameters.get("client_id").map(String::as_str) != Some("client-1") {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest));
        }
        if parameters.get("response_type").map(String::as_str) != Some("code")
            || parameters.get("code_challenge_method").map(String::as_str) != Some("S256")
            || parameters
                .get("code_challenge")
                .is_none_or(String::is_empty)
        {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest));
        }
        Ok(PushedAuthorizationResponse::new(
            "urn:openid4vci:test-request".to_owned(),
            90,
        ))
    }

    fn authorize(&self, parameters: &OAuthParameters) -> OAuthHttpResult<AuthorizationResponse> {
        if parameters.get("request_uri").map(String::as_str) != Some("urn:openid4vci:test-request")
        {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest));
        }
        Ok(AuthorizationResponse::redirect(
            "https://wallet.example/cb?code=test-code&iss=https%3A%2F%2Fissuer.example".to_owned(),
        ))
    }

    fn token(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
    ) -> OAuthHttpResult<TokenResponse> {
        if headers.dpop() != Some("dpop-proof") {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        if headers.client_attestation() != Some("attestation") {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        if parameters.get("grant_type").map(String::as_str) != Some("authorization_code") {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest));
        }
        Ok(TokenResponse::new(
            "access-token".to_owned(),
            "DPoP".to_owned(),
            300,
            vec![json!({
                "type": "openid_credential",
                "credential_configuration_id": "pid"
            })],
        ))
    }
}

struct TestResourceAuthorizationServer {
    authorization: TestResourceAuthorization,
}

impl OAuthAuthorizationServer for TestResourceAuthorizationServer {
    fn security_capabilities(&self) -> openid4vci_http::OAuthAuthorizationServerCapabilities {
        openid4vci_http::OAuthAuthorizationServerCapabilities::interoperability()
    }

    fn pushed_authorization_request(
        &self,
        _headers: &OAuthRequestHeaders,
        _parameters: &OAuthParameters,
    ) -> OAuthHttpResult<PushedAuthorizationResponse> {
        Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
    }

    fn authorize(&self, _parameters: &OAuthParameters) -> OAuthHttpResult<AuthorizationResponse> {
        Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
    }

    fn token(
        &self,
        _headers: &OAuthRequestHeaders,
        _parameters: &OAuthParameters,
    ) -> OAuthHttpResult<TokenResponse> {
        Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
    }
}

impl AccessTokenValidator for TestResourceAuthorizationServer {
    fn validate_access_token(&self, access_token: &str) -> OAuthHttpResult<ValidatedAccessToken> {
        TestAccessTokenValidator.validate_access_token(access_token)
    }

    fn authorize_credential_request(
        &self,
        access_token: &str,
        selector: &CredentialSelector,
    ) -> OAuthHttpResult<CredentialAuthorizationDecision> {
        if access_token != "access-token" {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof));
        }
        let requested_authorization = match selector {
            CredentialSelector::ConfigurationId(value) if value == "pid" => {
                TestResourceAuthorization::SdJwtPid
            }
            CredentialSelector::ConfigurationId(value) if value == "pid-mdoc" => {
                TestResourceAuthorization::MdocPid
            }
            CredentialSelector::CredentialIdentifier(value) if value == "pid-credential-1" => {
                TestResourceAuthorization::SdJwtPid
            }
            CredentialSelector::CredentialIdentifier(value) if value == "pid-mdoc-credential-1" => {
                TestResourceAuthorization::MdocPid
            }
            CredentialSelector::ConfigurationId(_) => {
                return Ok(CredentialAuthorizationDecision::UnknownCredentialConfiguration);
            }
            CredentialSelector::CredentialIdentifier(_) => {
                return Ok(CredentialAuthorizationDecision::UnknownCredentialIdentifier);
            }
        };
        if matches!(self.authorization, TestResourceAuthorization::SdJwtPid)
            && requested_authorization == TestResourceAuthorization::SdJwtPid
        {
            test_issuance_authorization(requested_authorization.configuration_id())
                .map(CredentialAuthorizationDecision::Authorized)
        } else {
            Ok(CredentialAuthorizationDecision::InsufficientAuthorization)
        }
    }

    fn authorize_deferred_credential_request(
        &self,
        access_token: &str,
        transaction_id: &str,
    ) -> OAuthHttpResult<openid4vci_issuer::IssuanceAuthorization> {
        TestAccessTokenValidator.authorize_deferred_credential_request(access_token, transaction_id)
    }

    fn authorize_notification_request(
        &self,
        access_token: &str,
        notification_id: &str,
    ) -> OAuthHttpResult<()> {
        TestAccessTokenValidator.authorize_notification_request(access_token, notification_id)
    }
}

pub(super) struct TestProofVerifier;

impl ProofVerifier for TestProofVerifier {
    fn verify(
        &self,
        proofs: &Proofs,
        _context: &ProofVerificationContext,
    ) -> IssuerResult<VerifiedProofSet> {
        let mut verified = Vec::with_capacity(proofs.jwt.len());
        for index in 0..proofs.jwt.len() {
            let key_byte =
                u8::try_from(index).map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
            verified.push(VerifiedProof::new(
                ProofKind::Jwt,
                Some("nonce-1".to_owned()),
                Some(ISSUER.to_owned()),
                None,
                None,
                Some(json!({"kty": "EC", "x": key_byte})),
                Some(ConfirmationJwk {
                    algorithm: ProofAlgorithm::Es256,
                    public_key: vec![key_byte; 65],
                    key_id: None,
                }),
            )?);
        }
        VerifiedProofSet::new(verified, Vec::new())
    }
}
