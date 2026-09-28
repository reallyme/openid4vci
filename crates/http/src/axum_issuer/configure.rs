// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Axum issuer routes for OpenID4VCI.
//!
//! The router is intentionally a thin adapter. It owns HTTP status codes,
//! content types, body limits, and problem-details serialization while all
//! protocol decisions stay in `openid4vci-types`, `openid4vci-issuer`, and the
//! generated protobuf service boundary.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use openid4vci_issuer::{
    CredentialEndpointConfig, CredentialIssuer, CredentialRequestDecryptor,
    CredentialResponseEncryptor, DeferredIssuer, IssuerMetadataSigner, NonceManager,
    NotificationHandler, ProofVerifier,
};
use openid4vci_types::IssuerMetadata;
use reallyme_openid_oauth::{
    AttestationClientAuthenticationVerifier, AuthorizationServerMetadata, DpopVerifier, GrantType,
};

use crate::serve_oauth::OAuthAuthorizationServer;
use crate::validate_access_token::AccessTokenValidator;
use crate::validate_http_security::{
    Clock, IssuerHttpSecurityConfig, WalletAttestationEvidenceRecorder,
};

use super::handle::{
    get_authorize, get_issuer_metadata, get_oauth_authorization_server_metadata,
    get_openid_metadata, post_credential, post_deferred_credential, post_nonce, post_notification,
    post_pushed_authorization_request, post_token,
};

const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;

/// Explicit security profile enforced while constructing issuer router state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxumIssuerSecurityPolicy {
    require_dpop: bool,
    require_wallet_attestation: bool,
    require_key_attestation: bool,
    require_par: bool,
    require_authorization_code_grant: bool,
    require_pkce_s256: bool,
    require_authorization_response_issuer: bool,
    require_oauth_client_authentication: bool,
}

impl AxumIssuerSecurityPolicy {
    /// Explicit baseline for deployments that do not claim HAIP controls.
    #[must_use]
    pub const fn interoperability() -> Self {
        Self {
            require_dpop: false,
            require_wallet_attestation: false,
            require_key_attestation: false,
            require_par: false,
            require_authorization_code_grant: false,
            require_pkce_s256: false,
            require_authorization_response_issuer: false,
            require_oauth_client_authentication: false,
        }
    }

    /// Builds a policy from the composing profile's concrete requirements.
    #[must_use]
    pub const fn new(
        require_dpop: bool,
        require_wallet_attestation: bool,
        require_key_attestation: bool,
        require_par: bool,
    ) -> Self {
        Self {
            require_dpop,
            require_wallet_attestation,
            require_key_attestation,
            require_par,
            require_authorization_code_grant: false,
            require_pkce_s256: false,
            require_authorization_response_issuer: false,
            require_oauth_client_authentication: false,
        }
    }

    /// Requires the concrete authorization-server controls mandated by HAIP.
    ///
    /// Wallet and key attestation use are intentionally configured separately
    /// because HAIP leaves their concrete formats and use to ecosystem policy.
    #[must_use]
    pub const fn with_haip_authorization_server_controls(mut self) -> Self {
        self.require_authorization_code_grant = true;
        self.require_pkce_s256 = true;
        self.require_authorization_response_issuer = true;
        self.require_oauth_client_authentication = true;
        self
    }

    fn is_satisfied_by(&self, parts: &AxumIssuerParts) -> bool {
        let dpop = !self.require_dpop || parts.http_security.dpop.is_some();
        let wallet_attestation =
            !self.require_wallet_attestation || parts.http_security.wallet_attestation.is_some();
        let key_attestation = !self.require_key_attestation
            || parts
                .credential_configs
                .values()
                .all(|config| config.key_attestation_required);
        let par = !self.require_par
            || parts
                .authorization_server_metadata
                .as_ref()
                .is_some_and(|metadata| {
                    metadata.require_pushed_authorization_requests == Some(true)
                        && metadata.pushed_authorization_request_endpoint.is_some()
                });
        let authorization_code_grant = !self.require_authorization_code_grant
            || parts
                .authorization_server_metadata
                .as_ref()
                .and_then(|metadata| metadata.grant_types_supported.as_ref())
                .is_some_and(|grants| grants.contains(&GrantType::AuthorizationCode));
        let pkce_s256 = !self.require_pkce_s256
            || parts
                .authorization_server_metadata
                .as_ref()
                .and_then(|metadata| metadata.code_challenge_methods_supported.as_ref())
                .is_some_and(|methods| methods.iter().any(|method| method == "S256"));
        let authorization_response_issuer = !self.require_authorization_response_issuer
            || parts
                .authorization_server_metadata
                .as_ref()
                .is_some_and(|metadata| {
                    metadata.authorization_response_iss_parameter_supported == Some(true)
                });
        let oauth_client_authentication = !self.require_oauth_client_authentication
            || parts
                .authorization_server_metadata
                .as_ref()
                .and_then(|metadata| metadata.token_endpoint_auth_methods_supported.as_ref())
                .is_some_and(|methods| methods.iter().any(|method| method != "none"));
        let oauth_provider = (!self.require_dpop
            && !self.require_wallet_attestation
            && !self.require_par
            && !self.require_authorization_code_grant
            && !self.require_pkce_s256
            && !self.require_authorization_response_issuer
            && !self.require_oauth_client_authentication)
            || parts
                .oauth_authorization_server
                .as_ref()
                .is_some_and(|provider| {
                    provider.security_capabilities().satisfies(
                        self.require_dpop,
                        self.require_wallet_attestation || self.require_oauth_client_authentication,
                        self.require_par,
                        self.require_authorization_code_grant,
                        self.require_pkce_s256,
                        self.require_authorization_response_issuer,
                    )
                });
        dpop && wallet_attestation
            && key_attestation
            && par
            && authorization_code_grant
            && pkce_s256
            && authorization_response_issuer
            && oauth_client_authentication
            && oauth_provider
    }
}

/// Dependencies required by the axum issuer router.
pub struct AxumIssuerParts {
    /// Security profile that this concrete router must enforce.
    pub security_policy: AxumIssuerSecurityPolicy,
    /// Credential Issuer Metadata served at the well-known endpoint.
    pub metadata: IssuerMetadata,
    /// Optional OAuth Authorization Server Metadata served by example or
    /// composed deployments where the issuer and AS share one HTTP adapter.
    pub authorization_server_metadata: Option<AuthorizationServerMetadata>,
    /// Optional OAuth Authorization Server route implementation.
    pub oauth_authorization_server: Option<Arc<dyn OAuthAuthorizationServer>>,
    /// Required validator for every protected issuer resource.
    pub access_token_validator: Arc<dyn AccessTokenValidator>,
    /// Optional provider for the `application/jwt` metadata representation.
    pub metadata_signer: Option<Arc<dyn IssuerMetadataSigner>>,
    /// Credential Endpoint policy for this issuer deployment.
    pub credential_configs: BTreeMap<String, CredentialEndpointConfig>,
    /// Authenticated nonce issuer and atomic replay guard.
    pub nonce_manager: Arc<dyn NonceManager>,
    /// Lifetime in seconds applied to a freshly issued `c_nonce`.
    pub nonce_ttl_seconds: u64,
    /// Proof verifier used by preflight and issuance.
    pub proof_verifier: Arc<dyn ProofVerifier + Send + Sync>,
    /// Credential issuer implementation.
    pub credential_issuer: Arc<dyn CredentialIssuer + Send + Sync>,
    /// Credential response encryption backend.
    pub response_encryptor: Arc<dyn CredentialResponseEncryptor + Send + Sync>,
    /// Optional decryptor for encrypted (`application/jwt`) Credential Request bodies.
    pub request_decryptor: Option<Arc<dyn CredentialRequestDecryptor>>,
    /// HTTP-level OAuth sender-constraining and client-auth policy.
    pub http_security: IssuerHttpSecurityConfig,
    /// DPoP verifier used when `http_security.dpop` is configured.
    pub dpop_verifier: Option<Arc<dyn DpopVerifier + Send + Sync>>,
    /// Wallet attestation verifier used when `http_security.wallet_attestation` is configured.
    pub attestation_client_authentication_verifier:
        Option<Arc<dyn AttestationClientAuthenticationVerifier + Send + Sync>>,
    /// Recorder that retains the exact accepted wallet-attestation receipt.
    pub wallet_attestation_evidence_recorder: Option<Arc<dyn WalletAttestationEvidenceRecorder>>,
    /// Deferred credential resolver.
    pub deferred_issuer: Arc<dyn DeferredIssuer + Send + Sync>,
    /// Notification handler.
    pub notification_handler: Arc<dyn NotificationHandler + Send + Sync>,
    /// Maximum accepted request body size in bytes.
    pub max_body_bytes: usize,
    /// Clock used to anchor DPoP / attestation `iat` acceptance windows.
    pub clock: Arc<dyn Clock>,
}

/// Shared state for the axum issuer router.
#[derive(Clone)]
pub struct AxumIssuerState {
    pub(crate) metadata: IssuerMetadata,
    // Router state is cloned by Axum. Share the hardened generated message
    // instead of requiring its value type to implement `Clone`.
    pub(crate) authorization_server_metadata: Option<Arc<AuthorizationServerMetadata>>,
    pub(crate) oauth_authorization_server: Option<Arc<dyn OAuthAuthorizationServer>>,
    pub(crate) access_token_validator: Arc<dyn AccessTokenValidator>,
    pub(crate) metadata_signer: Option<Arc<dyn IssuerMetadataSigner>>,
    pub(crate) credential_configs: BTreeMap<String, CredentialEndpointConfig>,
    pub(crate) nonce_manager: Arc<dyn NonceManager>,
    pub(crate) nonce_ttl_seconds: u64,
    pub(crate) proof_verifier: Arc<dyn ProofVerifier + Send + Sync>,
    pub(crate) credential_issuer: Arc<dyn CredentialIssuer + Send + Sync>,
    pub(crate) response_encryptor: Arc<dyn CredentialResponseEncryptor + Send + Sync>,
    pub(crate) request_decryptor: Option<Arc<dyn CredentialRequestDecryptor>>,
    pub(crate) http_security: IssuerHttpSecurityConfig,
    pub(crate) dpop_verifier: Option<Arc<dyn DpopVerifier + Send + Sync>>,
    pub(crate) attestation_client_authentication_verifier:
        Option<Arc<dyn AttestationClientAuthenticationVerifier + Send + Sync>>,
    pub(crate) wallet_attestation_evidence_recorder:
        Option<Arc<dyn WalletAttestationEvidenceRecorder>>,
    pub(crate) deferred_issuer: Arc<dyn DeferredIssuer + Send + Sync>,
    pub(crate) notification_handler: Arc<dyn NotificationHandler + Send + Sync>,
    pub(crate) max_body_bytes: usize,
    pub(crate) clock: Arc<dyn Clock>,
}

impl AxumIssuerState {
    /// Creates validated router state.
    pub fn new(parts: AxumIssuerParts) -> Result<Self, AxumIssuerError> {
        parts
            .metadata
            .validate()
            .map_err(|_| AxumIssuerError::InvalidMetadata)?;
        if parts.max_body_bytes == 0 {
            return Err(AxumIssuerError::InvalidBodyLimit);
        }
        if !parts.security_policy.is_satisfied_by(&parts) {
            return Err(AxumIssuerError::UnsatisfiedSecurityPolicy);
        }
        if parts.credential_configs.len()
            != parts.metadata.credential_configurations_supported.len()
        {
            return Err(AxumIssuerError::InvalidCredentialPolicy);
        }
        for (configuration_id, config) in &parts.credential_configs {
            let expected = CredentialEndpointConfig::from_metadata(
                &parts.metadata,
                configuration_id,
                config.key_attestation_local_policy,
            )
            .map_err(|_| AxumIssuerError::InvalidCredentialPolicy)?;
            if &expected != config {
                return Err(AxumIssuerError::InvalidCredentialPolicy);
            }
        }
        if !parts.http_security.is_satisfied_by(
            parts.dpop_verifier.as_ref(),
            parts.attestation_client_authentication_verifier.as_ref(),
            parts.wallet_attestation_evidence_recorder.as_ref(),
        ) {
            return Err(AxumIssuerError::MissingSecurityVerifier);
        }
        Ok(Self {
            metadata: parts.metadata,
            authorization_server_metadata: parts.authorization_server_metadata.map(Arc::new),
            oauth_authorization_server: parts.oauth_authorization_server,
            access_token_validator: parts.access_token_validator,
            metadata_signer: parts.metadata_signer,
            credential_configs: parts.credential_configs,
            nonce_manager: parts.nonce_manager,
            nonce_ttl_seconds: parts.nonce_ttl_seconds,
            proof_verifier: parts.proof_verifier,
            credential_issuer: parts.credential_issuer,
            response_encryptor: parts.response_encryptor,
            request_decryptor: parts.request_decryptor,
            http_security: parts.http_security,
            dpop_verifier: parts.dpop_verifier,
            attestation_client_authentication_verifier: parts
                .attestation_client_authentication_verifier,
            wallet_attestation_evidence_recorder: parts.wallet_attestation_evidence_recorder,
            deferred_issuer: parts.deferred_issuer,
            notification_handler: parts.notification_handler,
            max_body_bytes: parts.max_body_bytes,
            clock: parts.clock,
        })
    }

    /// Installs a signed-metadata provider on an already validated state.
    ///
    /// This is primarily useful for composition and focused adapter tests; the
    /// provider still signs the same canonical metadata stored in this state.
    #[must_use]
    pub fn with_metadata_signer(mut self, signer: Arc<dyn IssuerMetadataSigner>) -> Self {
        self.metadata_signer = Some(signer);
        self
    }
}

/// Stable construction errors for the axum issuer adapter.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum AxumIssuerError {
    /// Issuer metadata failed validation.
    #[error("invalid_metadata")]
    InvalidMetadata,
    /// Runtime credential policy does not exactly match published metadata.
    #[error("invalid_credential_policy")]
    InvalidCredentialPolicy,
    /// Request body limit must be positive.
    #[error("invalid_body_limit")]
    InvalidBodyLimit,
    /// A configured HTTP security policy is missing its verifier.
    #[error("missing_security_verifier")]
    MissingSecurityVerifier,
    /// The configured runtime does not satisfy its declared security profile.
    #[error("unsatisfied_security_policy")]
    UnsatisfiedSecurityPolicy,
    /// The requested issuer route prefix is not an absolute canonical path.
    #[error("invalid_mount_path")]
    InvalidMountPath,
}

/// Creates an axum router for OpenID4VCI issuer endpoints.
pub fn issuer_router(state: AxumIssuerState) -> Router {
    issuer_router_with_paths(state, "", "/.well-known/openid-credential-issuer")
}

/// Creates a router for a path-scoped Credential Issuer Identifier.
///
/// OAuth Authorization Server routes remain at the origin root. The issuer
/// well-known route follows RFC 8615 suffix insertion, so issuer path
/// `/tenant/a/` maps to `/.well-known/openid-credential-issuer/tenant/a/`.
pub fn issuer_router_at_path(
    state: AxumIssuerState,
    issuer_path: &str,
) -> Result<Router, AxumIssuerError> {
    if !issuer_path.starts_with('/')
        || issuer_path.contains('?')
        || issuer_path.contains('#')
        || issuer_path.split('/').any(|segment| segment == "..")
    {
        return Err(AxumIssuerError::InvalidMountPath);
    }
    let prefix = issuer_path.trim_end_matches('/');
    if prefix.is_empty() {
        return Ok(issuer_router(state));
    }
    let well_known = ["/.well-known/openid-credential-issuer", issuer_path].concat();
    Ok(issuer_router_with_paths(state, prefix, &well_known))
}

fn issuer_router_with_paths(
    state: AxumIssuerState,
    issuer_prefix: &str,
    issuer_metadata_path: &str,
) -> Router {
    let nonce = [issuer_prefix, "/nonce"].concat();
    let credential = [issuer_prefix, "/credential"].concat();
    let deferred = [issuer_prefix, "/deferred_credential"].concat();
    let notification = [issuer_prefix, "/notification"].concat();
    Router::new()
        .route(issuer_metadata_path, get(get_issuer_metadata))
        .route(
            "/.well-known/oauth-authorization-server",
            get(get_oauth_authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(get_openid_metadata),
        )
        .route("/par", post(post_pushed_authorization_request))
        .route("/authorize", get(get_authorize))
        .route("/token", post(post_token))
        .route(&nonce, post(post_nonce))
        .route(&credential, post(post_credential))
        .route(&deferred, post(post_deferred_credential))
        .route(&notification, post(post_notification))
        .with_state(state)
}

/// Returns the default request body limit used by the example issuer.
#[must_use]
pub const fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}
