// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example issuer entrypoint used by the conformance CI harness.

use std::collections::BTreeMap;
use std::env;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openid4vci_http::{
    default_max_body_bytes, issuer_router_at_path, AxumIssuerParts, AxumIssuerSecurityPolicy,
    AxumIssuerState, DpopHttpConfig, IssuerHttpSecurityConfig, SystemClock,
};
use openid4vci_issuer::{
    AuthenticatedNonceManager, CredentialEndpointConfig, IssuerError, IssuerResult, IssuerStatus,
    JoseJweCredentialRequestDecryptor, JoseJweCredentialResponseEncryptor, JoseJwePrivateKey,
    JoseJwtProofVerifier,
};
use thiserror::Error;

use super::configure::{
    authorization_server_metadata, example_request_encryption_keypair, key_attestation_policy,
    metadata, scoped_issuer_url, ExampleDeferredIssuer, ExampleNotificationHandler,
    EXAMPLE_ISSUER_PATH,
};
use super::issue::ExampleCredentialIssuer;
use super::store_authorization_state::ExampleOAuthAuthorizationServer;
use super::verify::ExampleKeyAttestationTrustVerifier;

const EXAMPLE_NONCE_TTL_SECONDS: u64 = 300;
pub(super) const PAR_EXPIRES_IN_SECONDS: u64 = 90;
pub(super) const AUTHORIZATION_CODE_EXPIRES_IN_SECONDS: u64 = 60;
pub(super) const ACCESS_TOKEN_EXPIRES_IN_SECONDS: u64 = 300;
pub(super) const REFRESH_TOKEN_EXPIRES_IN_SECONDS: u64 = 3_600;
pub(super) const KEY_ATTESTATION_MAX_AGE_SECONDS: u64 = 300;
pub(super) const KEY_ATTESTATION_ALLOWED_CLOCK_SKEW_SECONDS: u64 = 60;
pub(super) const KEY_ATTESTATION_TRUST_VALIDITY_SECONDS: i64 = 300;
pub(super) const CREDENTIAL_TIME_ROUNDING_SECONDS: u64 = 3_600;
pub(super) const EXAMPLE_MAX_BATCH_SIZE: u64 = 2;
pub(super) const OPAQUE_TOKEN_BYTES: usize = 32;
pub(super) const P256_PRIVATE_SCALAR_BYTES: usize = 32;
pub(super) const P256_UNCOMPRESSED_PUBLIC_KEY_BYTES: usize = 65;
pub(super) const P256_X_COORDINATE_RANGE: std::ops::Range<usize> = 1..33;
pub(super) const P256_Y_COORDINATE_RANGE: std::ops::Range<usize> = 33..65;
const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:9443";
const DEFAULT_ISSUER_BASE_URL: &str = "https://localhost.emobix.co.uk:9443";
pub(super) const PID_VCT: &str = "urn:reallyme:openid4vci:pid";
pub(super) const REQUEST_ENCRYPTION_KEY_KID: &str = "openid4vci-example-request-enc-1";
pub(super) const REQUEST_ENCRYPTION_PRIVATE_SCALAR_LAST_BYTE: u8 = 7;
pub(super) const CONFORMANCE_ISSUER_PRIVATE_KEY_D: &str =
    "Gkmh-vjcuC8QStQqLqM_PhJQUp8KepSGGL2-stl79Bs";
pub(super) const CONFORMANCE_ISSUER_X5C_LEAF: &str = "MIICTDCCAdKgAwIBAgIUPlAaWKujE4TvY8sCwXmyDMGgOIwwCgYIKoZIzj0EAwIwLDEqMCgGA1UEAwwhT3BlbklENFZDSSBDb25mb3JtYW5jZSBUZXN0cyBSb290MB4XDTI2MDExNTE2NTQyNFoXDTI4MDQxOTE2NTQyNFowUTELMAkGA1UEBhMCREUxFzAVBgNVBAoMDkV4YW1wbGUgSXNzdWVyMRAwDgYDVQQLDAdPSUQ0VkNJMRcwFQYDVQQDDA5pc3N1ZXIuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKfvyBxDvW/12SMltkh8mK0cjJ3cHFoxoZ4Uvsheh0Ym/6IzIjawRYvQLdrypBlCqeBh27jR2tLNUq8h86deoe+jgawwgakwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBSNQHXEutjrfQDfbTgLG0mHepGesjAfBgNVHSMEGDAWgBTgt/z+s54ZDXsVA/YQLaW4RI7WajAqBgNVHREEIzAhgg5pc3N1ZXIuZXhhbXBsZYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA2gAMGUCMQC24WF0JjXEH0MuirdaXckJuxQUR2N7m3CO2WnUvnmnvEVUfgrUB0G78SFL0LDbuHECMByQ90GH0dB94Z2/4D6f4uDm0j9m6LHTEM0XrW9JcGT2fDMfVEMgUYrMod6yHWbgSw==";
pub(super) const CONFORMANCE_ATTESTER_PUBLIC_X: &str =
    "p-_IHEO9b_XZIyW2SHyYrRyMndwcWjGhnhS-yF6HRiY";
pub(super) const CONFORMANCE_ATTESTER_PUBLIC_Y: &str =
    "_6IzIjawRYvQLdrypBlCqeBh27jR2tLNUq8h86deoe8";
pub(super) const CLIENT_ATTESTATION_TYP: &str = "oauth-client-attestation+jwt";
pub(super) const CLIENT_ATTESTATION_POP_TYP: &str = "oauth-client-attestation-pop+jwt";
pub(super) const AUTHORIZATION_COMPLETE_QUERY: &str = "reallyme_authorization_complete";
pub(super) const OIDF_USER_REJECT_QUERY: &str = "reallyme_oidf_user_reject";
const OIDF_PRIMARY_CLIENT_ID: &str = "openid4vci-conformance-wallet";
const OIDF_SECONDARY_CLIENT_ID: &str = "openid4vci-conformance-wallet-2";
const PRIMARY_REDIRECT_URI_ENV: &str = "OPENID4VCI_OAUTH_PRIMARY_REDIRECT_URI";
const SECONDARY_REDIRECT_URI_ENV: &str = "OPENID4VCI_OAUTH_SECONDARY_REDIRECT_URI";
const SECONDARY_ALTERNATE_REDIRECT_URI_ENV: &str =
    "OPENID4VCI_OAUTH_SECONDARY_ALTERNATE_REDIRECT_URI";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExampleIssuerError {
    #[error("invalid_bind_address")]
    InvalidBindAddress,
    #[error("invalid_metadata")]
    InvalidMetadata,
    #[error("invalid_router_state")]
    InvalidRouterState,
    #[error("invalid_tls_config")]
    InvalidTlsConfig,
    #[error("bind_failed")]
    BindFailed,
    #[error("bind_address_in_use")]
    BindAddressInUse,
    #[error("bind_address_unavailable")]
    BindAddressUnavailable,
    #[error("bind_permission_denied")]
    BindPermissionDenied,
    #[error("invalid_tls_listener")]
    InvalidTlsListener,
    #[error("serve_failed")]
    ServeFailed,
}

pub(crate) async fn run() -> Result<(), ExampleIssuerError> {
    let bind_address = env::var("OPENID4VCI_ISSUER_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDRESS.to_owned())
        .parse::<SocketAddr>()
        .map_err(|_| ExampleIssuerError::InvalidBindAddress)?;
    let issuer_base_url = env::var("OPENID4VCI_ISSUER_BASE_URL")
        .unwrap_or_else(|_| DEFAULT_ISSUER_BASE_URL.to_owned());
    let scoped_issuer_url = scoped_issuer_url(&issuer_base_url);
    let (request_encryption_public, request_encryption_private) =
        example_request_encryption_keypair()?;
    let metadata = metadata(
        &scoped_issuer_url,
        &issuer_base_url,
        &request_encryption_public,
    )?;
    let authorization_server_metadata = authorization_server_metadata(&issuer_base_url)?;
    let request_decryptor = JoseJweCredentialRequestDecryptor::new(
        JoseJwePrivateKey::p256(
            request_encryption_private,
            Some(REQUEST_ENCRYPTION_KEY_KID.to_owned()),
        )
        .map_err(|_| ExampleIssuerError::InvalidMetadata)?,
    );
    let mut oauth_authorization_server = ExampleOAuthAuthorizationServer::new(
        scoped_issuer_url.clone(),
        issuer_base_url.trim_end_matches('/').to_owned(),
    );
    register_redirect_from_env(
        &mut oauth_authorization_server,
        OIDF_PRIMARY_CLIENT_ID,
        PRIMARY_REDIRECT_URI_ENV,
    )?;
    register_redirect_from_env(
        &mut oauth_authorization_server,
        OIDF_SECONDARY_CLIENT_ID,
        SECONDARY_REDIRECT_URI_ENV,
    )?;
    register_redirect_from_env(
        &mut oauth_authorization_server,
        OIDF_SECONDARY_CLIENT_ID,
        SECONDARY_ALTERNATE_REDIRECT_URI_ENV,
    )?;
    let shared_dpop_verifier = oauth_authorization_server.shared_dpop_verifier();
    let oauth_authorization_server = Arc::new(oauth_authorization_server);
    let attestation_policy = key_attestation_policy()?;
    let credential_configs = BTreeMap::from([
        (
            "pid".to_owned(),
            CredentialEndpointConfig::from_metadata(&metadata, "pid", Some(attestation_policy))
                .map_err(|_| ExampleIssuerError::InvalidRouterState)?,
        ),
        (
            super::mdoc::PID_MDOC_CONFIGURATION_ID.to_owned(),
            CredentialEndpointConfig::from_metadata(
                &metadata,
                super::mdoc::PID_MDOC_CONFIGURATION_ID,
                Some(attestation_policy),
            )
            .map_err(|_| ExampleIssuerError::InvalidRouterState)?,
        ),
    ]);
    let state = AxumIssuerState::new(AxumIssuerParts {
        // The example advertises the HAIP authorization-server controls and
        // therefore makes construction fail unless metadata and the provider
        // both declare every mandatory OAuth behavior. Wallet/key attestation
        // use remains an ecosystem overlay rather than a universal HAIP rule.
        security_policy: AxumIssuerSecurityPolicy::new(true, false, false, true)
            .with_haip_authorization_server_controls(),
        metadata,
        authorization_server_metadata: Some(authorization_server_metadata),
        oauth_authorization_server: Some(oauth_authorization_server.clone()),
        access_token_validator: oauth_authorization_server,
        metadata_signer: Some(Arc::new(super::sign_metadata::ExampleIssuerMetadataSigner)),
        credential_configs,
        nonce_manager: Arc::new(
            AuthenticatedNonceManager::with_generated_key()
                .map_err(|_| ExampleIssuerError::InvalidRouterState)?,
        ),
        nonce_ttl_seconds: EXAMPLE_NONCE_TTL_SECONDS,
        proof_verifier: Arc::new(
            JoseJwtProofVerifier::new()
                .with_key_attestation_verifier(Arc::new(ExampleKeyAttestationTrustVerifier)),
        ),
        credential_issuer: Arc::new(ExampleCredentialIssuer::new(scoped_issuer_url.clone())),
        response_encryptor: Arc::new(JoseJweCredentialResponseEncryptor::new()),
        request_decryptor: Some(Arc::new(request_decryptor)),
        http_security: IssuerHttpSecurityConfig {
            dpop: Some(DpopHttpConfig {
                nonce: None,
                max_age_seconds: 300,
                max_future_skew_seconds: 60,
            }),
            wallet_attestation: None,
        },
        dpop_verifier: Some(shared_dpop_verifier),
        attestation_client_authentication_verifier: None,
        wallet_attestation_evidence_recorder: None,
        deferred_issuer: Arc::new(ExampleDeferredIssuer),
        notification_handler: Arc::new(ExampleNotificationHandler),
        max_body_bytes: default_max_body_bytes(),
        clock: Arc::new(SystemClock),
    })
    .map_err(|_| ExampleIssuerError::InvalidRouterState)?;
    let router = issuer_router_at_path(state, EXAMPLE_ISSUER_PATH)
        .map_err(|_| ExampleIssuerError::InvalidRouterState)?;
    let tls_required = url::Url::parse(&issuer_base_url)
        .map(|url| url.scheme() == "https")
        .map_err(|_| ExampleIssuerError::InvalidMetadata)?;
    match tls_config_from_env(tls_required).await? {
        Some(tls_config) => {
            let listener = tls_listener(bind_address)?;
            axum_server::from_tcp_rustls(listener, tls_config)
                .map_err(bind_error)?
                .serve(router.into_make_service())
                .await
                .map_err(serve_error)
        }
        None => {
            let listener = tokio::net::TcpListener::bind(bind_address)
                .await
                .map_err(bind_error)?;
            axum::serve(listener, router).await.map_err(serve_error)
        }
    }
}

fn register_redirect_from_env(
    server: &mut ExampleOAuthAuthorizationServer,
    client_id: &'static str,
    variable: &'static str,
) -> Result<(), ExampleIssuerError> {
    let redirect_uri = match env::var(variable) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(env::VarError::NotUnicode(_)) => return Err(ExampleIssuerError::InvalidRouterState),
    };
    server
        .register_redirect_uri(client_id.to_owned(), redirect_uri)
        .map_err(|_| ExampleIssuerError::InvalidRouterState)
}

fn tls_listener(bind_address: SocketAddr) -> Result<TcpListener, ExampleIssuerError> {
    let listener = TcpListener::bind(bind_address).map_err(bind_error)?;
    listener.set_nonblocking(true).map_err(bind_error)?;
    Ok(listener)
}

fn bind_error(error: std::io::Error) -> ExampleIssuerError {
    match error.kind() {
        ErrorKind::AddrInUse => ExampleIssuerError::BindAddressInUse,
        ErrorKind::AddrNotAvailable => ExampleIssuerError::BindAddressUnavailable,
        ErrorKind::InvalidInput => ExampleIssuerError::InvalidTlsListener,
        ErrorKind::PermissionDenied => ExampleIssuerError::BindPermissionDenied,
        _ => ExampleIssuerError::BindFailed,
    }
}

fn serve_error(error: std::io::Error) -> ExampleIssuerError {
    match error.kind() {
        ErrorKind::AddrInUse => ExampleIssuerError::BindAddressInUse,
        ErrorKind::AddrNotAvailable => ExampleIssuerError::BindAddressUnavailable,
        ErrorKind::PermissionDenied => ExampleIssuerError::BindPermissionDenied,
        _ => ExampleIssuerError::ServeFailed,
    }
}

pub(super) fn current_unix_seconds_issuer() -> IssuerResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

async fn tls_config_from_env(
    tls_required: bool,
) -> Result<Option<axum_server::tls_rustls::RustlsConfig>, ExampleIssuerError> {
    let Some((cert_path, key_path)) = resolve_tls_paths(
        env::var("OPENID4VCI_ISSUER_TLS_CERT"),
        env::var("OPENID4VCI_ISSUER_TLS_KEY"),
        tls_required,
    )?
    else {
        return Ok(None);
    };
    axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map(Some)
        .map_err(|_| ExampleIssuerError::InvalidTlsConfig)
}

pub(super) fn resolve_tls_paths(
    cert_path: Result<String, env::VarError>,
    key_path: Result<String, env::VarError>,
    tls_required: bool,
) -> Result<Option<(String, String)>, ExampleIssuerError> {
    match (cert_path, key_path) {
        (Ok(cert), Ok(key)) if tls_required && !cert.is_empty() && !key.is_empty() => {
            Ok(Some((cert, key)))
        }
        (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent)) if !tls_required => {
            Ok(None)
        }
        _ => Err(ExampleIssuerError::InvalidTlsConfig),
    }
}
